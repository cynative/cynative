package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// ProviderOperation is one entry of a providerOperations response, trimmed to
// what hardening needs. isDataAction keys the data-plane gate; the structural
// /action verb (not this flag) keys the read-vs-mutate safety check.
type ProviderOperation struct {
	Name         string `json:"name"`         // e.g. "Microsoft.Compute/virtualMachines/read".
	IsDataAction bool   `json:"isDataAction"` //nolint:tagliatelle // Azure API uses camelCase.
}

// ProviderOps is one resource-provider's catalog: its registered resource-type
// paths (name-vs-type structure) and its operation list.
type ProviderOps struct {
	ResourceTypes []string            `json:"resourceTypes"`
	Operations    []ProviderOperation `json:"operations"`
}

// CloudEndpoints is the trimmed /metadata/endpoints document for one cloud.
type CloudEndpoints struct {
	ResourceManager string            `json:"resourceManager"` // control-plane host (no scheme/path after parse).
	Suffixes        map[string]string `json:"suffixes"`
}

// CatalogData is the parsed per-cloud endpoint catalog + per-namespace
// providerOperations snapshot. Produced by catalogFetcher (real impl in shell).
type CatalogData struct {
	Clouds    map[string]CloudEndpoints `json:"clouds"`    // keyed by cloud name (AzureCloud, …).
	Providers map[string]ProviderOps    `json:"providers"` // keyed by RP namespace.
}

// Catalog is the Layer-3 (host pin) + Layer-2 (action validation) catalog port.
type Catalog interface {
	// ResolveCloud confirms the parsed host equals a cloud's resourceManager,
	// fills Cloud, else ErrHostPattern.
	ResolveCloud(ctx context.Context, p ParsedHost) (ParsedHost, error)
	// ResourceTypes returns a provider's registered resource-type paths.
	ResourceTypes(ctx context.Context, namespace string) ([]string, error)
	// LookupOperation returns the distinct registered verbs for one
	// (namespace, resourceTypePath, verbToken) plus an isDataAction-by-verb map.
	LookupOperation(
		ctx context.Context, namespace, resourceTypePath, verbToken string,
	) (verbs []string, isDataActionByVerb map[string]bool, err error)
}

// catalogFetcher fetches + parses the endpoint catalog and providerOperations.
// One-call seam; real impl in catalog_shell.go.
type catalogFetcher func(ctx context.Context) (CatalogData, error)

type catalog struct {
	fetch catalogFetcher
}

func newCatalog(fetch catalogFetcher) *catalog { return &catalog{fetch: fetch} }

// applyDefaults fills the zero-valued CatalogConfig fields with their production
// defaults. Pure; the gated counterpart of NewCatalog's inline defaulting so the
// shell constructor stays under the thin-shell complexity budget.
func applyDefaults(cfg CatalogConfig) CatalogConfig {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout} //nolint:exhaustruct // defaults fine
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.MetadataURLs == nil {
		cfg.MetadataURLs = defaultMetadataURLs
	}
	return cfg
}

// parseCatalogData unmarshals the cached catalog blob. Pure. Mirrors gcp's
// parseDiscoveryData so the azure cache Parse hook is a named func, not an inline
// closure (which inflated NewCatalog's cognitive complexity).
func parseCatalogData(raw []byte) (*CatalogData, error) {
	var d CatalogData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// applyCloudScope narrows the catalog to a single resolved cloud (so host pinning
// structurally pins to it) and returns the cloud-scoped cache file name. A run
// under a different cloud reads a different file, so caches never cross-contaminate.
// "" leaves the catalog multi-cloud (tests). Pure; the gated counterpart of
// NewCatalog's cloud handling so the shell stays under the thin-shell budget.
func applyCloudScope(cfg CatalogConfig) (CatalogConfig, string) {
	if cfg.Cloud == "" {
		return cfg, "azure.json"
	}
	if u, ok := defaultMetadataURLs[cfg.Cloud]; ok && cfg.MetadataURLs == nil {
		cfg.MetadataURLs = map[string]string{cfg.Cloud: u}
	}
	return cfg, "azure-" + cfg.Cloud + ".json"
}

// scopedParse returns the cache Parse hook. With a resolved cloud it rejects a
// payload whose Clouds set is not exactly that cloud — a Parse error the TTL cache
// treats as a miss, so a wrong-cloud or format-drifted cache forces a fresh fetch
// (fail-closed) instead of leaving the connector denied until the TTL expires.
// Without a cloud (tests) it is the plain parser. Pure; keeps NewCatalog thin.
func scopedParse(cloud string) func([]byte) (*CatalogData, error) {
	if cloud == "" {
		return parseCatalogData
	}
	return func(raw []byte) (*CatalogData, error) {
		d, err := parseCatalogData(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := d.Clouds[cloud]; !ok || len(d.Clouds) != 1 {
			return nil, fmt.Errorf("%w: cached catalog not scoped to %q", ErrCatalogUnavailable, cloud)
		}
		return d, nil
	}
}

// parseCloudEndpoints parses a single cloud's /metadata/endpoints body, rejecting
// the 2019 array shape and any object missing resourceManager (the drift guard).
// The shell's startup probe calls this; it is exported within the package for the
// drift-rejection test.
func parseCloudEndpoints(
	body []byte,
) (CloudEndpoints, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		return CloudEndpoints{}, fmt.Errorf(
			"%w: /metadata/endpoints returned the 2019 array shape",
			ErrCatalogUnavailable,
		)
	}
	var raw struct {
		ResourceManager string            `json:"resourceManager"`
		Suffixes        map[string]string `json:"suffixes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return CloudEndpoints{}, fmt.Errorf("%w: parse /metadata/endpoints: %w", ErrCatalogUnavailable, err)
	}
	if raw.ResourceManager == "" || raw.Suffixes == nil {
		return CloudEndpoints{}, fmt.Errorf(
			"%w: /metadata/endpoints missing resourceManager/suffixes",
			ErrCatalogUnavailable,
		)
	}
	return CloudEndpoints{ResourceManager: cloudauth.HostOf(raw.ResourceManager), Suffixes: raw.Suffixes}, nil
}

// ResolveCloud confirms p.Host equals some cloud's resourceManager and fills
// Cloud. Else ErrHostPattern.
func (c *catalog) ResolveCloud(ctx context.Context, p ParsedHost) (ParsedHost, error) {
	data, err := c.fetch(ctx)
	if err != nil {
		return ParsedHost{}, fmt.Errorf("%w: %w", ErrCatalogUnavailable, err)
	}
	for cloud, ep := range data.Clouds {
		if strings.EqualFold(ep.ResourceManager, p.Host) {
			return p.WithCloud(cloud), nil
		}
	}
	return ParsedHost{}, fmt.Errorf("%w: %q is not a known cloud resourceManager host", ErrHostPattern, p.Host)
}

// providerOps looks up an RP namespace case-insensitively.
func (c *catalog) providerOps(ctx context.Context, namespace string) (ProviderOps, error) {
	data, err := c.fetch(ctx)
	if err != nil {
		return ProviderOps{}, fmt.Errorf("%w: %w", ErrCatalogUnavailable, err)
	}
	for ns, ops := range data.Providers {
		if strings.EqualFold(ns, namespace) {
			return ops, nil
		}
	}
	return ProviderOps{}, fmt.Errorf(
		"%w: namespace %q not in providerOperations catalog",
		ErrCatalogUnavailable,
		namespace,
	)
}

// ResourceTypes returns the provider's registered resource-type paths.
func (c *catalog) ResourceTypes(ctx context.Context, namespace string) ([]string, error) {
	ops, err := c.providerOps(ctx, namespace)
	if err != nil {
		return nil, err
	}
	return ops.ResourceTypes, nil
}

// LookupOperation returns the distinct registered verbs for one
// (namespace, resourceTypePath, verbToken) and their isDataAction flags. An
// operation Name has the form {namespace}/{resourceTypePath}/{verb}; for a POST
// the verbToken is the trailing path segment, which may register as both /read
// and /action (the ambiguity case) — both distinct verbs are returned.
func (c *catalog) LookupOperation(
	ctx context.Context, namespace, resourceTypePath, verbToken string,
) ([]string, map[string]bool, error) {
	ops, err := c.providerOps(ctx, namespace)
	if err != nil {
		return nil, nil, err
	}
	prefix := strings.ToLower(namespace + "/" + resourceTypePath + "/" + verbToken)
	seen := map[string]bool{}
	isData := map[string]bool{}
	var verbs []string
	for _, op := range ops.Operations {
		name := strings.ToLower(op.Name)
		rest, ok := strings.CutPrefix(name, prefix)
		// Anchor on a segment boundary: rest is "" (the token IS the verb, e.g.
		// ".../read") or "/action". A non-empty rest not starting with "/" means the
		// token is only a string-prefix of a longer verb segment — not a match.
		if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
			continue
		}
		verb := strings.TrimPrefix(rest, "/")
		if verb == "" {
			verb = verbToken // the token itself is the registered verb.
		}
		if !seen[verb] {
			seen[verb] = true
			verbs = append(verbs, verb)
		}
		// Last-write-wins per verb; OR so a data-plane op is never masked by a later
		// control-plane op sharing the token (fail-closed: true dominates).
		isData[verb] = isData[verb] || op.IsDataAction
	}
	return verbs, isData, nil
}

// providerOpsMetadata is one element of the full providerOperations catalog
// (one resource provider): its RP namespace (name), nested resourceTypes each
// carrying operations, and top-level operations. Flattened into ProviderOps.
type providerOpsMetadata struct {
	Name          string `json:"name"`
	ResourceTypes []struct {
		Name       string              `json:"name"`
		Operations []ProviderOperation `json:"operations"`
	} `json:"resourceTypes"`
	Operations []ProviderOperation `json:"operations"`
}

// allProviderOpsResponse is the full providerOperations catalog wire shape:
// {"value":[ <providerOpsMetadata>, ... ]}, one element per resource provider.
type allProviderOpsResponse struct {
	Value []providerOpsMetadata `json:"value"`
}

// flattenProviderOps flattens one providerOpsMetadata element (nested
// resourceTypes each carrying operations + top-level operations) into ProviderOps,
// then prunes the action-verb landmine resourceTypes (see pruneActionVerbTypes).
//
// All operations are preserved verbatim; only the ResourceTypes list is pruned,
// so the classifier's verb/ambiguity lookup (which scans Operations by name
// prefix) is untouched — only resolveResourceType's longest-match is corrected.
func flattenProviderOps(md providerOpsMetadata) ProviderOps {
	out := ProviderOps{} //nolint:exhaustruct // assembled below
	var rawTypes []string
	for _, rt := range md.ResourceTypes {
		rawTypes = append(rawTypes, rt.Name)
		for _, op := range rt.Operations {
			out.Operations = append(out.Operations, ProviderOperation{Name: op.Name, IsDataAction: op.IsDataAction})
		}
	}
	for _, op := range md.Operations {
		out.Operations = append(out.Operations, ProviderOperation{Name: op.Name, IsDataAction: op.IsDataAction})
	}
	out.ResourceTypes = pruneActionVerbTypes(md.Name, rawTypes, out.Operations)
	return out
}

// pruneActionVerbTypes drops the "action-verb landmine" resourceTypes that the
// full ($expand=resourceTypes) catalog over-lists. With $expand, an instance
// action like Microsoft.DocumentDB/databaseAccounts/readonlykeys/action causes
// "databaseAccounts/readonlykeys" to ALSO be reported as a (nested) resourceType.
// If kept, resolveResourceType's longest-match would absorb the verb token into
// the type path, so a POST .../databaseAccounts/a/readonlykeys would no longer be
// recognized as the {readonlykeys} verb — defeating the listKeys/readonlykeys
// ambiguity-deny. A type "parent/seg" is such a landmine iff parent is itself a
// registered resourceType AND "{ns}/parent/seg/action" is a registered operation
// (seg is an action verb of the parent). Genuine nested types (e.g.
// virtualMachines/extensions, storageAccounts/blobServices/containers) have no
// such "/action" op and survive; top-level types (e.g. querypacks) are never
// dropped (no "/" → not nested).
func pruneActionVerbTypes(namespace string, types []string, ops []ProviderOperation) []string {
	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[strings.ToLower(t)] = true
	}
	opSet := make(map[string]bool, len(ops))
	for _, op := range ops {
		opSet[strings.ToLower(op.Name)] = true
	}
	out := types[:0:0] // fresh backing array; preserve input order.
	for _, t := range types {
		slash := strings.LastIndex(t, "/")
		parent := t[:max(slash, 0)] // t with the last "/seg" stripped ("" when not nested).
		actionOp := strings.ToLower(namespace + "/" + t + "/action")
		if slash > 0 && typeSet[strings.ToLower(parent)] && opSet[actionOp] {
			continue // nested action-verb landmine.
		}
		out = append(out, t)
	}
	return out
}

// providerOpsBase picks the ARM resource-manager base for the providerOperations
// GET. With single-cloud narrowing (NewCatalog scopes MetadataURLs to the resolved
// cloud) the map holds exactly the resolved cloud, so any entry is correct and its
// bearer audience matches the request host.
func providerOpsBase(clouds map[string]CloudEndpoints) string {
	for _, ep := range clouds {
		return "https://" + ep.ResourceManager
	}
	return ""
}

func withAPIVersion(rawURL, version string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("api-version", version)
	u.RawQuery = q.Encode()
	return u.String()
}

// providerOpsURL builds the $expand=resourceTypes providerOperations GET URL for
// an ARM resource-manager base (tolerating a trailing slash).
func providerOpsURL(armBase string) string {
	u := strings.TrimSuffix(armBase, "/") + "/providers/Microsoft.Authorization/providerOperations"
	return withAPIVersion(u, providerOpsAPIVersion) + "&%24expand=resourceTypes"
}

// collectProviderOps flattens every element of a providerOperations response into
// a namespace-keyed map.
func collectProviderOps(resp allProviderOpsResponse) map[string]ProviderOps {
	out := make(map[string]ProviderOps, len(resp.Value))
	for _, md := range resp.Value {
		out[md.Name] = flattenProviderOps(md)
	}
	return out
}

// decodeJSON unmarshals body into an allProviderOpsResponse, returning the zero
// value on error.
func decodeJSON(body []byte) (allProviderOpsResponse, error) {
	var out allProviderOpsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		var zero allProviderOpsResponse
		return zero, err
	}
	return out, nil
}

// buildCatalog assembles the per-cloud endpoint catalog + providerOperations
// snapshot from injected fetchers — the pure spine of fetchCatalog. It carries
// the per-cloud continue-on-error loop, the parseCloudEndpoints hard-fail
// propagation, the fail-closed guard when no cloud is reachable, the
// armBase/providerOpsBase fallback, and the soft providerOps failure that leaves
// an empty (but cached) Providers map — Layer-2 action checks stay denied until
// the TTL refresh recovers providers.
func buildCatalog(
	ctx context.Context,
	clouds map[string]string,
	getEndpoints func(ctx context.Context, mURL string) ([]byte, error),
	getProviderOps func(ctx context.Context, armBase string) (map[string]ProviderOps, error),
	baseURL string,
) (CatalogData, error) {
	out := CatalogData{Clouds: map[string]CloudEndpoints{}, Providers: map[string]ProviderOps{}}
	for cloud, mURL := range clouds {
		body, err := getEndpoints(ctx, mURL)
		if err != nil {
			continue // an unreachable sovereign cloud must not sink the reachable ones.
		}
		ep, perr := parseCloudEndpoints(body) // startup shape-validation probe (2019 array → reject).
		if perr != nil {
			return CatalogData{}, perr
		}
		out.Clouds[cloud] = ep
	}
	if len(out.Clouds) == 0 {
		return CatalogData{}, fmt.Errorf("%w: no reachable /metadata/endpoints", ErrCatalogUnavailable)
	}
	armBase := baseURL
	if armBase == "" {
		armBase = providerOpsBase(out.Clouds)
	}
	// A providerOps fetch failure must not sink the catalog: Layer-3 host pinning
	// (Clouds) still works and the empty Providers map fails Layer-2 closed. The
	// incomplete catalog (empty Providers) is cached normally for the TTL — Layer-2
	// stays denied until the TTL expires and a fresh fetch recovers providers.
	if providers, err := getProviderOps(ctx, armBase); err == nil {
		out.Providers = providers
	}
	return out, nil
}
