package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// MethodDescriptor is the per-method Discovery info the classifier matches on.
type MethodDescriptor struct {
	ID          string `json:"id"` // Discovery method id, e.g. "compute.instances.list".
	HTTPMethod  string `json:"httpMethod"`
	FlatPath    string `json:"flatPath"` // falls back to ServicePath+Path for storage v1 (no flatPath).
	ServicePath string `json:"servicePath"`
	Path        string `json:"path"`
}

// MethodIndex maps a Discovery method id to its descriptor.
type MethodIndex map[string]MethodDescriptor

// ServiceDoc is one parsed Discovery REST document, trimmed to what hardening needs.
type ServiceDoc struct {
	RootURL     string      `json:"rootUrl"`
	MTLSRootURL string      `json:"mtlsRootUrl"`
	ServicePath string      `json:"servicePath"`
	Endpoints   []string    `json:"endpoints"` // regional host list (in-doc endpoints[]).
	Methods     MethodIndex `json:"methods"`
}

// DiscoveryData is the parsed Discovery directory + per-service docs, keyed by
// canonical service short name. Produced by catalogFetcher (real impl in shell).
type DiscoveryData struct {
	Services map[string]ServiceDoc `json:"services"`
}

// Catalog is the Layer-3/Layer-2 catalog port.
type Catalog interface {
	ResolveService(ctx context.Context, parsed ParsedHost, host string) (string, error)
	MethodIndex(ctx context.Context, service string) (MethodIndex, error)
	ResolveWWWService(ctx context.Context, reqPath string) (string, bool)
}

// catalogFetcher fetches the Discovery directory + per-API docs. One-call seam;
// real impl in catalog_shell.go.
type catalogFetcher func(ctx context.Context) (DiscoveryData, error)

type catalog struct {
	fetch catalogFetcher
}

func newCatalog(fetch catalogFetcher) *catalog { return &catalog{fetch: fetch} }

// applyDefaults fills the zero-valued CatalogConfig fields with their production
// defaults. Pure; the gated counterpart of NewCatalog's inline defaulting so the
// shell constructor stays under the thin-shell complexity budget.
func applyDefaults(cfg CatalogConfig) CatalogConfig {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = DefaultDiscoveryDirectoryURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout} //nolint:exhaustruct // defaults fine
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return cfg
}

// hostToService builds the resolved-host → service index (rootUrl + mtlsRootUrl
// hosts), never the directory name. Pure.
func hostToService(d DiscoveryData) map[string]string {
	idx := make(map[string]string)
	for svc, doc := range d.Services {
		for _, raw := range []string{doc.RootURL, doc.MTLSRootURL} {
			if h := cloudauth.HostOf(raw); h != "" && h != wwwGoogleapisHost {
				idx[h] = svc // www.googleapis.com is path-resolved, never host-resolved.
			}
		}
		for _, ep := range doc.Endpoints {
			idx[strings.ToLower(ep)] = svc
		}
	}
	return idx
}

// mergeServiceDocs unions the methods and endpoints of two Discovery docs that
// resolved to the same service short name (e.g. iam v1 + v2 both on
// iam.googleapis.com, or cloudresourcemanager v1 + v3). Without this the
// directory's later version silently OVERWRITES the earlier one and drops its
// methods — iam v2 carries only 6 policy methods and would erase v1's roles/
// serviceAccounts surface, leaving those operations unclassifiable. Where ids
// are DISJOINT across versions (iam v1 roles/serviceAccounts vs v2 policies),
// the union recovers both.
//
// Where ids are SHARED across versions but route to DIFFERENT request signatures
// (cloudresourcemanager v1+v3 both define cloudresourcemanager.projects.list, at
// GET v1/projects vs GET v3/projects; organizations.search is POST v1/... vs GET
// v3/...), both are distinct routable operations and BOTH must survive — keying
// the index by id alone would drop whichever version is fetched first, making its
// real paths unclassifiable and fail-closed (the v1 enumeration calls a read-only
// audit naturally reaches for). The first occurrence keeps the canonical id key;
// each later different-signature sibling is stored under a disambiguated internal
// key. The key is never surfaced — Classify returns md.ID — so the permission
// resolver and caller still see the Discovery id. A genuine same-signature
// re-fetch (identical method+template) still overwrites, so a re-modeled GA
// version does not accumulate duplicates. Endpoints are concatenated (the
// consumer, hostToService, is idempotent). Allocates fresh containers; does not
// mutate either input.
func mergeServiceDocs(a, b ServiceDoc) ServiceDoc {
	merged := make(MethodIndex, len(a.Methods)+len(b.Methods))
	maps.Copy(merged, a.Methods)
	for id, md := range b.Methods {
		if existing, clash := merged[id]; clash && methodSignature(existing) != methodSignature(md) {
			merged[disambiguatedKey(md)] = md
			continue
		}
		merged[id] = md
	}
	a.Methods = merged
	a.Endpoints = slices.Concat(a.Endpoints, b.Endpoints)
	return a
}

// methodSignature is the (HTTP method, request-path template) tuple Classify
// matches a request against. Two methods sharing a Discovery id but differing in
// signature are distinct routable operations across API versions.
func methodSignature(md MethodDescriptor) string {
	return strings.ToUpper(md.HTTPMethod) + " " + effectiveTemplate(md)
}

// disambiguatedKey derives a collision-free MethodIndex key for a method whose
// Discovery id is already held by a different-signature sibling version. Internal
// only: Classify returns md.ID, so this key never reaches the resolver or caller.
func disambiguatedKey(md MethodDescriptor) string {
	return md.ID + "\x00" + methodSignature(md)
}

// ResolveService verifies the parsed candidate against the live catalog. For
// concrete services it confirms the short name (or resolved host) is modeled;
// the www-compound sentinel is rejected here — the provider must call
// ResolveWWWService(path) instead.
func (c *catalog) ResolveService(ctx context.Context, parsed ParsedHost, host string) (string, error) {
	data, err := c.fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCatalogUnavailable, err)
	}
	if parsed.Service == wwwCompoundSentinel {
		// The provider must call ResolveWWWService(path); a bare host has no path.
		return "", fmt.Errorf("%w: www.googleapis.com service must be resolved from path", ErrHostPattern)
	}
	if _, ok := data.Services[parsed.Service]; ok {
		return parsed.Service, nil
	}
	// Fall back to the resolved-host index (covers host≠name APIs, mtls hosts,
	// regional endpoints[] entries).
	if svc, ok := hostToService(data)[cloudauth.HostOf(host)]; ok {
		return svc, nil
	}
	return "", fmt.Errorf("%w: %q (service not in discovery catalog)", ErrHostPattern, parsed.Service)
}

// ResolveWWWService maps a www.googleapis.com request path to a service via the
// servicePath table (longest, anchored, full-segment match). Pure.
func (c *catalog) ResolveWWWService(ctx context.Context, reqPath string) (string, bool) {
	data, err := c.fetch(ctx)
	if err != nil {
		return "", false
	}
	clean := strings.TrimPrefix(reqPath, "/")
	type entry struct {
		svc  string
		path string
	}
	var entries []entry
	for svc, doc := range data.Services {
		if doc.ServicePath != "" {
			entries = append(entries, entry{svc: svc, path: strings.TrimPrefix(doc.ServicePath, "/")})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].path) > len(entries[j].path) })
	// Anchor on segment boundaries: append a "/" to both so a servicePath of "ab"
	// never matches request path "abcdef/foo" across a segment boundary. Real
	// Discovery servicePaths always end in "/" but this guards against any that do
	// not. We compare clean+"/" against segPath (already /-terminated) so an exact
	// match (clean == stripped servicePath) is also accepted.
	for _, e := range entries {
		segPath := e.path
		if !strings.HasSuffix(segPath, "/") {
			segPath += "/"
		}
		if strings.HasPrefix(clean+"/", segPath) {
			return e.svc, true
		}
	}
	return "", false
}

// MethodIndex returns the per-service method index for the classifier.
func (c *catalog) MethodIndex(ctx context.Context, service string) (MethodIndex, error) {
	data, err := c.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCatalogUnavailable, err)
	}
	doc, ok := data.Services[service]
	if !ok {
		return nil, fmt.Errorf("%w: service %q has no discovery doc", ErrClassifierUnknownOp, service)
	}
	return doc.Methods, nil
}

func serviceShortName(rootURL, dirName string) string {
	if h := cloudauth.HostOf(rootURL); strings.HasSuffix(h, googleapisSuffix) {
		short := strings.TrimSuffix(h, googleapisSuffix)
		if !strings.Contains(short, ".") && short != "www" && short != "" {
			return short
		}
	}
	return dirName
}

func resolveDocURL(base, ref string) string {
	if base == "" || strings.HasPrefix(ref, "http") {
		return ref
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(ref, "/")
}

type restDoc struct {
	RootURL     string `json:"rootUrl"`
	MTLSRootURL string `json:"mtlsRootUrl"`
	ServicePath string `json:"servicePath"`
	Endpoints   []struct {
		Location string `json:"location"`
		Endpoint string `json:"endpointUrl"`
	} `json:"endpoints"`
	Methods   map[string]methodDoc       `json:"methods"`
	Resources map[string]json.RawMessage `json:"resources"`
}

type methodDoc struct {
	ID         string `json:"id"`
	HTTPMethod string `json:"httpMethod"`
	FlatPath   string `json:"flatPath"`
	Path       string `json:"path"`
}

func serviceDocFrom(doc restDoc) ServiceDoc {
	methods := MethodIndex{}
	collectMethods(doc.Methods, doc.ServicePath, methods)
	collectResourceMethods(doc.Resources, doc.ServicePath, methods)
	eps := make([]string, 0, len(doc.Endpoints))
	for _, e := range doc.Endpoints {
		eps = append(eps, cloudauth.HostOf(e.Endpoint))
	}
	return ServiceDoc{
		RootURL: doc.RootURL, MTLSRootURL: doc.MTLSRootURL,
		ServicePath: doc.ServicePath, Endpoints: eps, Methods: methods,
	}
}

func collectMethods(in map[string]methodDoc, servicePath string, out MethodIndex) {
	for _, m := range in {
		out[m.ID] = MethodDescriptor{
			ID: m.ID, HTTPMethod: m.HTTPMethod, FlatPath: m.FlatPath,
			ServicePath: servicePath, Path: m.Path,
		}
	}
}

func collectResourceMethods(resources map[string]json.RawMessage, servicePath string, out MethodIndex) {
	for _, raw := range resources {
		var r restDoc
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		collectMethods(r.Methods, servicePath, out)
		collectResourceMethods(r.Resources, servicePath, out)
	}
}

// fetchedDoc is one directory item's REST-doc result, retained in directory order
// so the multi-version service merge stays deterministic regardless of the order
// the concurrent fetches complete in. A failed fetch (ok=false) — whether a
// transient error or a permanent 404/410 — is skipped.
type fetchedDoc struct {
	name string
	doc  restDoc
	ok   bool
}

// assembleCatalog merges fetched Discovery docs into DiscoveryData in input
// (directory) order: skips !ok docs, applies serviceShortName + serviceDocFrom,
// and merges multi-version collisions via mergeServiceDocs. Returns
// ErrCatalogUnavailable("empty directory") on zero services.
func assembleCatalog(docs []fetchedDoc) (DiscoveryData, error) {
	out := DiscoveryData{Services: map[string]ServiceDoc{}}
	for _, r := range docs { // directory order → deterministic multi-version merge.
		if !r.ok {
			continue // an unreachable or permanently-gone doc is skipped.
		}
		svc := serviceShortName(r.doc.RootURL, r.name)
		sd := serviceDocFrom(r.doc)
		if existing, ok := out.Services[svc]; ok {
			out.Services[svc] = mergeServiceDocs(existing, sd)
		} else {
			out.Services[svc] = sd
		}
	}
	if len(out.Services) == 0 {
		return DiscoveryData{}, fmt.Errorf("%w: empty directory", ErrCatalogUnavailable)
	}
	return out, nil
}

// parseDiscoveryData unmarshals the cached catalog blob. Pure.
func parseDiscoveryData(raw []byte) (*DiscoveryData, error) {
	var d DiscoveryData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
