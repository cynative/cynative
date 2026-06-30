package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/cynative/cynative/internal/auth/cloudauth"
	"github.com/cynative/cynative/internal/cache"
)

// DefaultDiscoveryDirectoryURL is the canonical Discovery directory endpoint.
const DefaultDiscoveryDirectoryURL = "https://discovery.googleapis.com/discovery/v1/apis"

// defaultHTTPTimeout is the per-request timeout for Discovery HTTPS fetches.
const defaultHTTPTimeout = 30 * time.Second

// discoveryCacheFile is the on-disk catalog cache basename. The trailing format
// version is bumped whenever the serialized DiscoveryData representation changes,
// so a cache written by an older binary is ignored (cache miss → refetch) rather
// than served stale. v2: the multi-version merge now stores same-id sibling
// methods under disambiguated keys (see mergeServiceDocs); a v1 cache holds only
// the last-version-wins index, which would keep e.g. GET /v1/projects failing
// closed after an upgrade until the 24h TTL expired.
const discoveryCacheFile = "discovery.v2.json"

// CatalogConfig configures the real Discovery-backed catalog.
type CatalogConfig struct {
	cache.Config

	DirectoryURL string // defaults to DefaultDiscoveryDirectoryURL.
	BaseURL      string // base for resolving relative discoveryRestUrl (tests); "" in prod.
	HTTPClient   *http.Client
}

// NewCatalog builds a Catalog whose fetcher performs real HTTPS GETs and caches
// the parsed DiscoveryData under Dir/catalog/ with a .meta TTL sidecar. A
// partial fetch (some Discovery docs transiently unreachable) is cached as-is —
// the dropped services are denied until the TTL expires. Excluded from the
// coverage gate.
func NewCatalog(cfg CatalogConfig) Catalog {
	cfg = applyDefaults(cfg)
	tc := &cache.TTLCache[DiscoveryData]{
		DataPath: filepath.Join(cfg.Dir, "catalog", discoveryCacheFile),
		MetaPath: filepath.Join(cfg.Dir, "catalog", discoveryCacheFile+".meta"),
		TTL:      cfg.TTL,
		Clock:    cfg.Clock,
		Fetch: func(ctx context.Context) ([]byte, error) {
			data, err := fetchCatalog(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return json.Marshal(data)
		},
		Parse: parseDiscoveryData,
	}
	return newCatalog(func(ctx context.Context) (DiscoveryData, error) {
		if d := tc.Get(ctx); d != nil {
			return *d, nil
		}
		return DiscoveryData{}, ErrCatalogUnavailable
	})
}

type directoryItem struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	DiscoveryRestURL string `json:"discoveryRestUrl"`
}

type directoryResponse struct {
	Items []directoryItem `json:"items"`
}

// maxConcurrentDocFetches bounds the parallel Discovery REST-doc GETs. The
// directory lists ~500 docs at hundreds of ms each, so a serial fetch takes
// minutes — far longer than any single tool-call timeout, which would leave the
// catalog chronically partial — and a partial fetch is now cached as-is for the
// whole TTL, denying the omitted services until refresh. They are fetched
// concurrently and assembled in directory order.
const maxConcurrentDocFetches = 64

// fetchCatalog fetches the Discovery directory then each per-service REST doc.
// Failed individual docs are skipped (best-effort assembly): the resulting
// catalog may be partial, but is returned as success so the plain cache persists
// it — dropped services are denied for the TTL (fail-closed, never over-
// permitted). Failed docs (transient errors or permanent 404/410s) are skipped
// silently. Only a directory fetch failure or a zero-service result returns an error.
func fetchCatalog(ctx context.Context, cfg CatalogConfig) (DiscoveryData, error) {
	dir, _, err := cloudauth.GetJSON[directoryResponse](ctx, cfg.HTTPClient, cfg.DirectoryURL)
	if err != nil {
		return DiscoveryData{}, fmt.Errorf("%w: directory: %w", ErrCatalogUnavailable, err)
	}
	out, err := assembleCatalog(fetchAllDocs(ctx, cfg, dir.Items))
	if err != nil {
		return DiscoveryData{}, err
	}
	return out, nil
}

// fetchAllDocs fetches every directory item's REST doc concurrently (bounded by
// maxConcurrentDocFetches) and returns the results in the input order. Each
// goroutine writes its own slot, so the shared slice needs no lock; the caller
// assembles sequentially. A per-doc failure is recorded as ok=false rather than
// failing the whole fetch.
func fetchAllDocs(ctx context.Context, cfg CatalogConfig, items []directoryItem) []fetchedDoc {
	results := make([]fetchedDoc, len(items))
	sem := make(chan struct{}, maxConcurrentDocFetches)
	var wg sync.WaitGroup
	for i, item := range items {
		wg.Add(1)
		go func(i int, item directoryItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			docURL := resolveDocURL(cfg.BaseURL, item.DiscoveryRestURL)
			doc, _, derr := cloudauth.GetJSON[restDoc](ctx, cfg.HTTPClient, docURL)
			results[i] = fetchedDoc{name: item.Name, doc: doc, ok: derr == nil}
		}(i, item)
	}
	wg.Wait()
	return results
}
