package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

// injectMethods replaces the methods of the named service in c's fetcher with
// the provided MethodIndex. It is a test-only helper for pre-populating a
// fakeCatalog with a richer method set (e.g. computeIndex()).
func (c *catalog) injectMethods(service string, methods MethodIndex) {
	orig := c.fetch
	c.fetch = func(ctx context.Context) (DiscoveryData, error) {
		data, err := orig(ctx)
		if err != nil {
			return data, err
		}
		if doc, ok := data.Services[service]; ok {
			doc.Methods = methods
			data.Services[service] = doc
		}
		return data, nil
	}
}

func fakeCatalog(t *testing.T) *catalog {
	t.Helper()
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"compute": {
				RootURL:     "https://compute.googleapis.com/",
				MTLSRootURL: "https://compute.mtls.googleapis.com/",
				ServicePath: "compute/v1/",
				Methods: map[string]MethodDescriptor{
					"compute.instances.list": {
						ID:         "compute.instances.list",
						HTTPMethod: "GET",
						FlatPath:   "projects/{project}/zones/{zone}/instances",
					},
				},
			},
			"storage": { // no flatPath on methods → servicePath+path fallback.
				RootURL:     "https://storage.googleapis.com/",
				ServicePath: "storage/v1/",
				Methods: map[string]MethodDescriptor{
					"storage.buckets.list": {
						ID:          "storage.buckets.list",
						HTTPMethod:  "GET",
						ServicePath: "storage/v1/",
						Path:        "b",
					},
				},
			},
			"oauth2": { // a www.googleapis.com compound API resolved by servicePath.
				RootURL:     "https://www.googleapis.com/",
				ServicePath: "oauth2/v2/",
				Methods: map[string]MethodDescriptor{
					"oauth2.tokeninfo": {
						ID:          "oauth2.tokeninfo",
						HTTPMethod:  "GET",
						ServicePath: "oauth2/v2/",
						Path:        "tokeninfo",
					},
				},
			},
			"aiplatform": {
				RootURL:     "https://aiplatform.googleapis.com/",
				ServicePath: "v1/",
				Endpoints: []string{
					"us-central1-aiplatform.googleapis.com",
					"europe-west1-aiplatform.googleapis.com",
				},
				Methods: map[string]MethodDescriptor{},
			},
		},
	}
	return newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
}

func TestCatalogResolveService(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	ctx := context.Background()

	// plain host → service by name.
	got, err := c.ResolveService(ctx, ParsedHost{Service: "compute"}, "compute.googleapis.com")
	if err != nil || got != "compute" {
		t.Fatalf("compute resolve = %q err=%v", got, err)
	}
	// mtls host present in index.
	_, mtlsErr := c.ResolveService(ctx, ParsedHost{Service: "compute"}, "compute.mtls.googleapis.com")
	if mtlsErr != nil {
		t.Fatalf("mtls resolve: %v", mtlsErr)
	}
	// A5: unknown service rejected even though ParseHost accepted the shape.
	_, unknownErr := c.ResolveService(ctx, ParsedHost{Service: "madeupservice"}, "madeupservice.googleapis.com")
	if !errors.Is(unknownErr, ErrHostPattern) {
		t.Fatalf("madeupservice want ErrHostPattern, got %v", unknownErr)
	}
	// A14: www.googleapis.com compound sentinel is handled by the provider via
	// ResolveWWWService, not directly through ResolveService.
	got, err = c.ResolveService(ctx, ParsedHost{Service: wwwCompoundSentinel}, "www.googleapis.com")
	// ResolveService returns ErrHostPattern for the www sentinel (caller uses
	// ResolveWWWService instead).
	_ = got
	if !errors.Is(err, ErrHostPattern) {
		t.Fatalf("www sentinel via ResolveService want ErrHostPattern, got err=%v", err)
	}

	// Test ResolveWWWService directly for the servicePath table.
	if svc, ok := c.ResolveWWWService(context.Background(), "/oauth2/v2/tokeninfo"); !ok || svc != "oauth2" {
		t.Errorf("www path resolve = %q ok=%v, want oauth2", svc, ok)
	}
	if _, ok := c.ResolveWWWService(context.Background(), "/notaservice/v9/x"); ok {
		t.Error("www path resolve should fail for unknown servicePath")
	}
}

func TestCatalogMethodIndex(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	idx, err := c.MethodIndex(context.Background(), "compute")
	if err != nil {
		t.Fatalf("MethodIndex: %v", err)
	}
	if _, ok := idx["compute.instances.list"]; !ok {
		t.Error("compute.instances.list missing from MethodIndex")
	}
}

func TestCatalogMethodIndexUnknownService(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	_, err := c.MethodIndex(context.Background(), "doesnotexist")
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("want ErrClassifierUnknownOp, got %v", err)
	}
}

func TestCatalogFetcherError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("fetch failed")
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return DiscoveryData{}, sentinel })
	ctx := context.Background()

	_, err := c.ResolveService(ctx, ParsedHost{Service: "compute"}, "compute.googleapis.com")
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Fatalf("ResolveService fetch error: want ErrCatalogUnavailable, got %v", err)
	}

	_, err = c.MethodIndex(ctx, "compute")
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Fatalf("MethodIndex fetch error: want ErrCatalogUnavailable, got %v", err)
	}

	// ResolveWWWService must return (false) when the fetcher fails.
	if _, ok := c.ResolveWWWService(context.Background(), "/oauth2/v2/tokeninfo"); ok {
		t.Fatal("ResolveWWWService with failed fetcher should return ok=false")
	}
}

func TestCatalogResolveServiceViaHostIndex(t *testing.T) {
	t.Parallel()

	// Build a catalog where the service short-name used in the Discovery doc
	// differs from what ParseHost would derive from the hostname. This exercises
	// the host-index fallback branch (line 97): parsed.Service is not in
	// data.Services, but the host IS indexed via rootUrl/endpoints[].
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			// "sqladmin" is what Discovery calls it; ParseHost on
			// "sqladmin.googleapis.com" would derive "sqladmin" — so use an alias
			// scenario: service key is "sqladmin-v1beta4" (hypothetical), rootUrl
			// has the real hostname.
			"sqladmin-v1beta4": {
				RootURL:     "https://sqladmin.googleapis.com/",
				ServicePath: "sql/v1beta4/",
				Methods:     map[string]MethodDescriptor{},
			},
		},
	}
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	ctx := context.Background()

	// ParseHost would give Service="sqladmin", which is NOT a key in data.Services.
	// But "sqladmin.googleapis.com" IS the rootUrl host, so the host-index fallback
	// must return "sqladmin-v1beta4".
	got, err := c.ResolveService(ctx, ParsedHost{Service: "sqladmin"}, "sqladmin.googleapis.com")
	if err != nil || got != "sqladmin-v1beta4" {
		t.Fatalf("host-index fallback: got %q err=%v, want sqladmin-v1beta4", got, err)
	}
}

func TestCatalogResolveServiceViaHostIndexTrailingDot(t *testing.T) {
	t.Parallel()

	// A trailing-dot host (FQDN-absolute) that reaches the host-index fallback
	// must resolve to the same service as its dotless form. Before the lookup is
	// normalized through cloudauth.HostOf, the dotted key misses the dotless
	// index and this denies; after, it resolves.
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"sqladmin-v1beta4": {
				RootURL:     "https://sqladmin.googleapis.com/",
				ServicePath: "sql/v1beta4/",
				Methods:     map[string]MethodDescriptor{},
			},
		},
	}
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })

	got, err := c.ResolveService(
		context.Background(),
		ParsedHost{Service: "sqladmin"},
		"sqladmin.googleapis.com.",
	)
	if err != nil || got != "sqladmin-v1beta4" {
		t.Fatalf("trailing-dot host-index fallback: got %q err=%v, want sqladmin-v1beta4", got, err)
	}
}

func TestCatalogResolveServiceViaHostIndexDottedRootURL(t *testing.T) {
	t.Parallel()

	// Build-side counterpart of the trailing-dot trim: a (hypothetical)
	// trailing-dot Discovery RootURL is normalized to a dotless index key, so a
	// dotless request host still resolves. Pins that build and lookup share the
	// same normalization.
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"sqladmin-v1beta4": {
				RootURL:     "https://sqladmin.googleapis.com./",
				ServicePath: "sql/v1beta4/",
				Methods:     map[string]MethodDescriptor{},
			},
		},
	}
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })

	got, err := c.ResolveService(
		context.Background(),
		ParsedHost{Service: "sqladmin"},
		"sqladmin.googleapis.com",
	)
	if err != nil || got != "sqladmin-v1beta4" {
		t.Fatalf("dotted-rootURL host-index build: got %q err=%v, want sqladmin-v1beta4", got, err)
	}
}

func TestMergeServiceDocs(t *testing.T) {
	t.Parallel()

	a := ServiceDoc{
		RootURL: "https://iam.googleapis.com/",
		Methods: MethodIndex{
			"iam.roles.get":            {ID: "iam.roles.get", HTTPMethod: "GET", FlatPath: "v1/roles/{rolesId}"},
			"iam.serviceAccounts.list": {ID: "iam.serviceAccounts.list", HTTPMethod: "GET"},
		},
		Endpoints: []string{"a.example.com"},
	}
	b := ServiceDoc{
		RootURL: "https://iam.googleapis.com/",
		Methods: MethodIndex{
			"iam.policies.get": {ID: "iam.policies.get", HTTPMethod: "GET"},
			// Same Discovery id as a's, but a different request signature (a later
			// version's path): a cross-version collision that must NOT drop a's
			// method — both signatures stay routable.
			"iam.roles.get": {ID: "iam.roles.get", HTTPMethod: "GET", FlatPath: "v2/roles/{rolesId}"},
		},
		Endpoints: []string{"b.example.com"},
	}

	got := mergeServiceDocs(a, b)

	if len(got.Methods) != 4 {
		t.Fatalf("merged methods = %d, want 4 (disjoint union + both signatures of the shared id)", len(got.Methods))
	}
	// Both version paths of the shared id survive — neither version overwrites the other.
	var rolesGetTemplates []string
	for _, md := range got.Methods {
		if md.ID == "iam.roles.get" {
			rolesGetTemplates = append(rolesGetTemplates, md.FlatPath)
		}
	}
	if len(rolesGetTemplates) != 2 {
		t.Errorf("shared id must keep both version signatures, got flatPaths %v", rolesGetTemplates)
	}
	if _, ok := got.Methods["iam.policies.get"]; !ok {
		t.Error("b-only method must be merged in")
	}
	if len(got.Endpoints) != 2 {
		t.Errorf("merged endpoints = %v, want both", got.Endpoints)
	}
}

// TestMergeServiceDocsSameSignatureOverwrites pins that a genuine re-fetch of the
// SAME method (same id, same method+template signature) overwrites rather than
// accumulating a duplicate — so a re-modeled GA version does not bloat the index.
func TestMergeServiceDocsSameSignatureOverwrites(t *testing.T) {
	t.Parallel()

	a := ServiceDoc{Methods: MethodIndex{
		"svc.res.get": {ID: "svc.res.get", HTTPMethod: "GET", FlatPath: "v1/res/{resId}", Path: "old"},
	}}
	b := ServiceDoc{Methods: MethodIndex{
		"svc.res.get": {ID: "svc.res.get", HTTPMethod: "GET", FlatPath: "v1/res/{resId}", Path: "new"},
	}}

	got := mergeServiceDocs(a, b)

	if len(got.Methods) != 1 {
		t.Fatalf("same-signature merge = %d methods, want 1 (overwrite, no duplicate)", len(got.Methods))
	}
	if got.Methods["svc.res.get"].Path != "new" {
		t.Error("same-signature collision: later-seen (b) entry must overwrite")
	}
}

// TestAssembleCatalogMultiVersionSameID pins the cloudresourcemanager v1+v3
// regression: both versions define cloudresourcemanager.projects.list with the
// SAME Discovery id but DIFFERENT request paths (v1/projects vs v3/projects).
// The id-keyed merge must keep BOTH templates so a request to EITHER version
// classifies — not only the last-fetched (v3) one, which would leave the most
// common enumeration call (GET /v1/projects) unclassifiable and fail-closed.
func TestAssembleCatalogMultiVersionSameID(t *testing.T) {
	t.Parallel()

	crmDoc := func(flatPath string) restDoc {
		return restDoc{
			RootURL:     "https://cloudresourcemanager.googleapis.com/",
			ServicePath: "",
			Methods: map[string]methodDoc{
				"projects.list": {
					ID:         "cloudresourcemanager.projects.list",
					HTTPMethod: "GET",
					FlatPath:   flatPath,
				},
			},
		}
	}
	// Directory order: v1 first, then v3 (mirrors the live directory where v3 is
	// last and "preferred", so it wins the prior overwrite merge).
	data, err := assembleCatalog([]fetchedDoc{
		{name: "cloudresourcemanager", doc: crmDoc("v1/projects"), ok: true},
		{name: "cloudresourcemanager", doc: crmDoc("v3/projects"), ok: true},
	})
	if err != nil {
		t.Fatalf("assembleCatalog: %v", err)
	}

	idx := data.Services["cloudresourcemanager"].Methods
	for _, path := range []string{
		"https://cloudresourcemanager.googleapis.com/v1/projects",
		"https://cloudresourcemanager.googleapis.com/v3/projects",
	} {
		got, cerr := Classify(idx, req(t, "GET", path))
		if cerr != nil || got != "cloudresourcemanager.projects.list" {
			t.Errorf("Classify(%s) = %q err=%v, want cloudresourcemanager.projects.list", path, got, cerr)
		}
	}
}

func TestResolveWWWServiceLongestMatch(t *testing.T) {
	t.Parallel()
	// Build a catalog with two services whose servicePaths share a prefix.
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"short": {RootURL: "https://www.googleapis.com/", ServicePath: "foo/v1/"},
			"long":  {RootURL: "https://www.googleapis.com/", ServicePath: "foo/v1/bar/"},
		},
	}
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	// The longest match wins.
	svc, ok := c.ResolveWWWService(context.Background(), "/foo/v1/bar/something")
	if !ok || svc != "long" {
		t.Errorf("longest match: got %q ok=%v, want long", svc, ok)
	}
	// Shorter path selects the shorter prefix.
	svc, ok = c.ResolveWWWService(context.Background(), "/foo/v1/other")
	if !ok || svc != "short" {
		t.Errorf("shorter match: got %q ok=%v, want short", svc, ok)
	}
}

func TestResolveWWWServiceSegmentBoundary(t *testing.T) {
	t.Parallel()
	// A servicePath WITHOUT a trailing slash must not match a request path that
	// extends beyond it at a sub-segment boundary ("ab" must not match "abcdef/x").
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			// Intentionally omit the trailing slash to exercise the normalization branch.
			"abc": {RootURL: "https://www.googleapis.com/", ServicePath: "ab"},
		},
	}
	c := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })

	// "/abcdef/foo" must NOT match servicePath "ab" (cross-segment boundary).
	if svc, ok := c.ResolveWWWService(context.Background(), "/abcdef/foo"); ok {
		t.Errorf("cross-segment match must not occur: got svc=%q", svc)
	}
	// "/ab/foo" MUST match (exact segment prefix).
	svc, ok := c.ResolveWWWService(context.Background(), "/ab/foo")
	if !ok || svc != "abc" {
		t.Errorf("exact-segment match: got %q ok=%v, want abc", svc, ok)
	}
	// "/ab" alone (exact) must also match.
	svc, ok = c.ResolveWWWService(context.Background(), "/ab")
	if !ok || svc != "abc" {
		t.Errorf("exact match: got %q ok=%v, want abc", svc, ok)
	}
}

func TestServiceShortName(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, rootURL, dirName, want string }{
		{"googleapis short name", "https://compute.googleapis.com/", "compute", "compute"},
		{"compound short name falls back", "https://foo.bar.googleapis.com/", "dirfb", "dirfb"},
		{"www falls back", "https://www.googleapis.com/", "wwwdir", "wwwdir"},
		{"empty short falls back", "https://.googleapis.com/", "emptydir", "emptydir"},
		{"non-googleapis falls back", "https://example.com/", "exdir", "exdir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := serviceShortName(tc.rootURL, tc.dirName); got != tc.want {
				t.Errorf("serviceShortName(%q,%q)=%q want %q", tc.rootURL, tc.dirName, got, tc.want)
			}
		})
	}
}

func TestResolveDocURL(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, base, ref, want string }{
		{"empty base passthrough", "", "v1/apis/compute", "v1/apis/compute"},
		{"absolute ref passthrough", "https://d/", "http://x/doc", "http://x/doc"},
		{"relative joined", "https://d/", "v1/apis/compute", "https://d/v1/apis/compute"},
		{"trailing+leading slash normalized", "https://d/", "/compute", "https://d/compute"},
		{"no trailing slash on base", "https://d", "compute", "https://d/compute"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveDocURL(tc.base, tc.ref); got != tc.want {
				t.Errorf("resolveDocURL(%q,%q)=%q want %q", tc.base, tc.ref, got, tc.want)
			}
		})
	}
}

func TestCollectMethods(t *testing.T) {
	t.Parallel()
	in := map[string]methodDoc{"m": {ID: "compute.instances.list", HTTPMethod: "GET", FlatPath: "fp", Path: "p"}}
	out := MethodIndex{}
	collectMethods(in, "compute/v1/", out)
	got, ok := out["compute.instances.list"]
	if !ok {
		t.Fatal("method id not collected")
	}
	want := MethodDescriptor{
		ID: "compute.instances.list", HTTPMethod: "GET", FlatPath: "fp", ServicePath: "compute/v1/", Path: "p",
	}
	if got != want {
		t.Errorf("descriptor = %+v want %+v", got, want)
	}
}

func TestCollectResourceMethods(t *testing.T) {
	t.Parallel()
	resources := map[string]json.RawMessage{
		"instances": json.RawMessage(`{"methods":{"list":{"id":"compute.instances.list"}},` +
			`"resources":{"sub":{"methods":{"get":{"id":"compute.instances.sub.get"}}}}}`),
		"bad": json.RawMessage(`{not json`),
	}
	out := MethodIndex{}
	collectResourceMethods(resources, "compute/v1/", out)
	if _, ok := out["compute.instances.list"]; !ok {
		t.Error("top resource method missing")
	}
	if _, ok := out["compute.instances.sub.get"]; !ok {
		t.Error("deeply nested method missing")
	}
	if len(out) != 2 {
		t.Errorf("malformed entry not skipped cleanly: out=%v", out)
	}
}

func TestServiceDocFrom(t *testing.T) {
	t.Parallel()
	zonesRaw := json.RawMessage(`{"methods":{"get":{"id":"compute.zones.get"}}}`)
	doc := restDoc{
		RootURL:     "https://compute.googleapis.com/",
		MTLSRootURL: "https://compute.mtls.googleapis.com/",
		ServicePath: "compute/v1/",
		Endpoints: []struct {
			Location string `json:"location"`
			Endpoint string `json:"endpointUrl"`
		}{{Location: "us", Endpoint: "https://compute.us.rep.googleapis.com/"}},
		Methods:   map[string]methodDoc{"list": {ID: "compute.instances.list"}},
		Resources: map[string]json.RawMessage{"zones": zonesRaw},
	}
	sd := serviceDocFrom(doc)
	if _, ok := sd.Methods["compute.instances.list"]; !ok {
		t.Error("top-level method missing")
	}
	if _, ok := sd.Methods["compute.zones.get"]; !ok {
		t.Error("nested resource method missing")
	}
	if len(sd.Endpoints) != 1 || sd.Endpoints[0] != "compute.us.rep.googleapis.com" {
		t.Errorf("endpoints = %v want [compute.us.rep.googleapis.com]", sd.Endpoints)
	}
}

// okFetchedDoc builds a successfully-fetched fetchedDoc with one method, for use
// in assembleCatalog tests. Failure cases are expressed with struct literals.
func okFetchedDoc(name, root, mid string) fetchedDoc {
	return fetchedDoc{
		name: name, ok: true,
		doc: restDoc{RootURL: root, Methods: map[string]methodDoc{"m": {ID: mid}}},
	}
}

func TestAssembleCatalogSingleOK(t *testing.T) {
	t.Parallel()
	out, err := assembleCatalog([]fetchedDoc{
		okFetchedDoc("compute", "https://compute.googleapis.com/", "compute.instances.list"),
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if _, ok := out.Services["compute"].Methods["compute.instances.list"]; !ok {
		t.Error("method missing")
	}
}

func TestAssembleCatalogMergeSameShortName(t *testing.T) {
	t.Parallel()
	out, err := assembleCatalog([]fetchedDoc{
		okFetchedDoc("iam", "https://iam.googleapis.com/", "iam.roles.get"),
		okFetchedDoc("iam", "https://iam.googleapis.com/", "iam.policies.get"),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := out.Services["iam"].Methods
	if _, ok := m["iam.roles.get"]; !ok {
		t.Error("v1 method dropped by merge")
	}
	if _, ok := m["iam.policies.get"]; !ok {
		t.Error("v2 method missing from merge")
	}
}

func TestAssembleCatalogSkipsFailedDoc(t *testing.T) {
	t.Parallel()
	out, err := assembleCatalog([]fetchedDoc{
		okFetchedDoc("compute", "https://compute.googleapis.com/", "compute.instances.list"),
		{name: "svcdown", ok: false}, //nolint:exhaustruct // failed fetch carries only name/ok.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Services["svcdown"]; ok {
		t.Error("failed-fetch service should be absent")
	}
	if _, ok := out.Services["compute"].Methods["compute.instances.list"]; !ok {
		t.Error("the OK doc alongside a failed one must still be assembled")
	}
}

func TestAssembleCatalogZeroServicesErrors(t *testing.T) {
	t.Parallel()
	_, err := assembleCatalog([]fetchedDoc{{name: "a", ok: false}}) //nolint:exhaustruct // failed fetch: name/ok only.
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("err = %v want ErrCatalogUnavailable", err)
	}
	if !strings.Contains(err.Error(), "empty directory") {
		t.Errorf("err = %q want empty directory", err)
	}
}

func TestAssembleCatalogEmptyInputErrors(t *testing.T) {
	t.Parallel()
	_, err := assembleCatalog(nil)
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("err = %v want ErrCatalogUnavailable", err)
	}
}

func TestParseDiscoveryData(t *testing.T) {
	t.Parallel()
	t.Run("valid blob", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{"services":{"compute":{"rootUrl":"https://compute.googleapis.com/","methods":{}}}}`)
		d, err := parseDiscoveryData(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Services["compute"]; !ok {
			t.Error("compute service missing")
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		t.Parallel()
		if _, err := parseDiscoveryData([]byte(`{bad`)); err == nil {
			t.Error("want error for malformed json")
		}
	})
}

func TestApplyDefaults_FillsZeroValues(t *testing.T) {
	t.Parallel()

	got := applyDefaults(CatalogConfig{}) //nolint:exhaustruct // exercising the defaulting path

	if got.DirectoryURL != DefaultDiscoveryDirectoryURL {
		t.Errorf("DirectoryURL default = %q, want %q", got.DirectoryURL, DefaultDiscoveryDirectoryURL)
	}
	if got.HTTPClient == nil || got.HTTPClient.Timeout != defaultHTTPTimeout {
		t.Errorf("HTTPClient default = %#v, want Timeout %s", got.HTTPClient, defaultHTTPTimeout)
	}
	if got.Clock == nil {
		t.Error("Clock default = nil, want non-nil")
	}
}

func TestApplyDefaults_KeepsSuppliedValues(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: time.Second} //nolint:exhaustruct // test value
	got := applyDefaults(CatalogConfig{          //nolint:exhaustruct // only overridden fields matter
		DirectoryURL: "https://example.test/apis",
		HTTPClient:   client,
		Config: cache.Config{
			Clock: func() time.Time { return time.Unix(0, 0) },
		}, //nolint:exhaustruct // only Clock
	})

	if got.DirectoryURL != "https://example.test/apis" {
		t.Error("DirectoryURL was overwritten")
	}
	if got.HTTPClient != client {
		t.Error("HTTPClient was overwritten")
	}
	if got.Clock == nil {
		t.Error("Clock was cleared")
	}
}
