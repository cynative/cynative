package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/cynative/cynative/internal/auth/cloudauth"
	"github.com/cynative/cynative/internal/cache"
)

// metadataAPIVersion is the pinned api-version for /metadata/endpoints (the 2022
// object shape; 2019 returns an array, rejected by parseCloudEndpoints).
const metadataAPIVersion = "2022-09-01"

// providerOpsAPIVersion is the pinned api-version for providerOperations.
const providerOpsAPIVersion = "2022-04-01"

// defaultHTTPTimeout is the per-request timeout for Azure metadata HTTPS fetches.
const defaultHTTPTimeout = 30 * time.Second

// defaultMetadataURLs are the per-cloud /metadata/endpoints endpoints (public,
// US-Gov, China; Azure Germany is closed and not enumerated).
var defaultMetadataURLs = map[string]string{ //nolint:gochecknoglobals // immutable lookup table
	"AzureCloud":        "https://management.azure.com/metadata/endpoints",
	"AzureUSGovernment": "https://management.usgovcloudapi.net/metadata/endpoints",
	"AzureChinaCloud":   "https://management.chinacloudapi.cn/metadata/endpoints",
}

// CatalogConfig configures the real metadata-backed catalog.
type CatalogConfig struct {
	cache.Config

	HTTPClient   *http.Client
	MetadataURLs map[string]string // per-cloud /metadata/endpoints; defaults to defaultMetadataURLs.
	// Cloud is the resolved canonical cloud name (AzureCloud/AzureUSGovernment/
	// AzureChinaCloud). When set it narrows MetadataURLs to that one cloud, scopes
	// the on-disk cache path by it, and makes Parse reject a cache not scoped to it.
	// "" (tests) leaves the catalog multi-cloud and unscoped.
	Cloud   string
	BaseURL string // base for providerOperations GETs (tests); "" → per-cloud resourceManager.
	// BearerFunc mints a home-tenant ARM bearer for the providerOperations GET,
	// which requires Microsoft.Authorization/providerOperations/read. Mirrors
	// arm_shell's BearerFunc. The /metadata/endpoints fetch stays anonymous. nil
	// in tests → providerOperations is fetched without an Authorization header.
	BearerFunc func(ctx context.Context) (string, error)
}

// NewCatalog builds a Catalog whose fetcher performs real HTTPS GETs of
// /metadata/endpoints (per cloud) + providerOperations (per namespace), runs the
// startup shape-validation probe (rejecting the 2019 array shape), and caches the
// parsed CatalogData under Dir/catalog/ with a .meta TTL sidecar. Excluded from
// the coverage gate.
func NewCatalog(cfg CatalogConfig) Catalog {
	cfg, cacheName := applyCloudScope(cfg) // narrow MetadataURLs + cloud-scoped cache name.
	cfg = applyDefaults(cfg)
	tc := &cache.TTLCache[CatalogData]{
		DataPath: filepath.Join(cfg.Dir, "catalog", cacheName),
		MetaPath: filepath.Join(cfg.Dir, "catalog", cacheName+".meta"),
		TTL:      cfg.TTL,
		Clock:    cfg.Clock,
		Fetch: func(ctx context.Context) ([]byte, error) {
			data, err := fetchCatalog(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return json.Marshal(data)
		},
		Parse: scopedParse(cfg.Cloud),
	}
	return newCatalog(func(ctx context.Context) (CatalogData, error) {
		if d := tc.Get(ctx); d != nil {
			return *d, nil
		}
		return CatalogData{}, ErrCatalogUnavailable
	})
}

func fetchCatalog(ctx context.Context, cfg CatalogConfig) (CatalogData, error) {
	getEndpoints := func(ctx context.Context, mURL string) ([]byte, error) {
		body, err := cloudauth.GetBytes(ctx, cfg.HTTPClient, withAPIVersion(mURL, metadataAPIVersion), "")
		return body, err
	}
	getProviderOps := func(ctx context.Context, armBase string) (map[string]ProviderOps, error) {
		return fetchAllProviderOps(ctx, cfg, armBase)
	}
	return buildCatalog(ctx, cfg.MetadataURLs, getEndpoints, getProviderOps, cfg.BaseURL)
}

// fetchAllProviderOps fetches the FULL providerOperations catalog in one
// authenticated, $expand=resourceTypes call and flattens every element into a
// namespace-keyed map. Data-driven: no hardcoded namespace list — every RP the
// directory exposes is modeled. The GET requires
// Microsoft.Authorization/providerOperations/read, so it carries the home-tenant
// ARM bearer (cfg.BearerFunc); /metadata/endpoints stays anonymous.
func fetchAllProviderOps(ctx context.Context, cfg CatalogConfig, armBase string) (map[string]ProviderOps, error) {
	resp, err := getAuthedJSON(ctx, cfg, providerOpsURL(armBase))
	if err != nil {
		return nil, err
	}
	return collectProviderOps(resp), nil
}

// getAuthedBytes GETs rawURL with an optional ARM bearer (when cfg.BearerFunc
// is set). Used for the providerOperations GET, which requires
// Microsoft.Authorization/providerOperations/read; without the header ARM
// returns 401 and the catalog comes back empty.
func getAuthedBytes(ctx context.Context, cfg CatalogConfig, rawURL string) ([]byte, error) {
	tok := ""
	if cfg.BearerFunc != nil {
		var terr error
		tok, terr = cfg.BearerFunc(ctx)
		if terr != nil {
			return nil, fmt.Errorf("acquire ARM token: %w", terr)
		}
	}
	body, err := cloudauth.GetBytes(ctx, cfg.HTTPClient, rawURL, tok)
	return body, err
}

func getAuthedJSON(ctx context.Context, cfg CatalogConfig, rawURL string) (allProviderOpsResponse, error) {
	var zero allProviderOpsResponse
	body, err := getAuthedBytes(ctx, cfg, rawURL)
	if err != nil {
		return zero, err
	}
	return decodeJSON(body)
}
