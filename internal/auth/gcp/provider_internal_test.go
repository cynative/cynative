package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// buildProvider builds a Provider wired with a catalog that carries the full
// computeIndex() so DELETE and list can both be tested.
func buildProvider(t *testing.T) *Provider {
	t.Helper()

	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"compute": {
				RootURL:     "https://compute.googleapis.com/",
				MTLSRootURL: "https://compute.mtls.googleapis.com/",
				ServicePath: "compute/v1/",
				Methods:     computeIndex(),
			},
			"oauth2": {
				RootURL:     "https://www.googleapis.com/",
				ServicePath: "oauth2/v2/",
				Methods: MethodIndex{
					"oauth2.tokeninfo": {
						ID:          "oauth2.tokeninfo",
						HTTPMethod:  "GET",
						ServicePath: "oauth2/v2/",
						Path:        "tokeninfo",
					},
				},
			},
		},
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })

	permCat := map[string]bool{"compute.instances.list": true}
	perms := NewPermissionResolver(permCat, defaultPrefixMap(), emptyDataset{})
	eval := newRoleEvaluator(map[string]bool{"compute.instances.list": true})

	return NewProvider(cat, perms, eval, "roles/viewer")
}

func gcpArgs(t *testing.T, svc string) json.RawMessage {
	t.Helper()

	b, _ := json.Marshal(map[string]any{"gcp_auth": map[string]string{"service": svc}})

	return b
}

func httpReq(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()

	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("url: %v", err)
	}

	return (&http.Request{Method: method, URL: u, Header: http.Header{}}).WithContext(context.Background())
}

func TestProviderAuthorizeActionAllowRead(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		gcpArgs(t, "compute"),
	); err != nil {
		t.Fatalf("allowed read errored: %v", err)
	}
}

func TestProviderAuthorizeActionDenyWrite(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// DELETE is a write — PermissionResolver returns SourceNone → ErrPermissionUnresolved.
	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "DELETE", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
		gcpArgs(t, "compute"),
	)
	if !errors.Is(err, ErrPermissionUnresolved) && !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("delete should be denied, got %v", err)
	}
}

func TestProviderAuthorizeActionMissingGCPAuth(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// {} has no gcp_auth key → nil struct → explicit error (A15).
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		json.RawMessage(`{}`),
	); err == nil {
		t.Fatal("missing gcp_auth should error")
	}
}

func TestProviderAuthorizeActionUnknownHost(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// madeupservice is not in the catalog → fail closed.
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://madeupservice.googleapis.com/x"),
		gcpArgs(t, "madeupservice"),
	); err == nil {
		t.Fatal("unknown host should fail closed")
	}
}

func TestProviderAuthorizeActionPermissionDenied(t *testing.T) {
	t.Parallel()

	// eval allows nothing → ErrPermissionDenied.
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"compute": {
				RootURL:     "https://compute.googleapis.com/",
				ServicePath: "compute/v1/",
				Methods:     computeIndex(),
			},
		},
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	permCat := map[string]bool{"compute.instances.list": true}
	perms := NewPermissionResolver(permCat, defaultPrefixMap(), emptyDataset{})
	// Empty union → AllowedAll returns false for any permission.
	eval := newRoleEvaluator(map[string]bool{})
	p := NewProvider(cat, perms, eval, "roles/none")

	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		gcpArgs(t, "compute"),
	)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("empty union should return ErrPermissionDenied, got %v", err)
	}
}

func TestProviderAuthorizeActionWWWPath(t *testing.T) {
	t.Parallel()

	// www.googleapis.com compound: service resolved from path, not host.
	// oauth2 is in the buildProvider catalog via www.googleapis.com / servicePath oauth2/v2/.
	p := buildProvider(t)

	// oauth2.tokeninfo is permissionless → should succeed.
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://www.googleapis.com/oauth2/v2/tokeninfo"),
		gcpArgs(t, "oauth2"),
	); err != nil {
		t.Fatalf("www-path oauth2 tokeninfo should succeed, got %v", err)
	}
}

// TestProviderAuthorizeActionWWWClaimMismatch covers A14: the model declares
// gcp_auth.service="storage" but the www.googleapis.com path resolves to
// "oauth2". Layer 2 must deny with ErrHostClaimMismatch.
func TestProviderAuthorizeActionWWWClaimMismatch(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// Path resolves to "oauth2" (servicePath oauth2/v2/) but claim says "storage".
	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://www.googleapis.com/oauth2/v2/tokeninfo"),
		gcpArgs(t, "storage"),
	)
	if !errors.Is(err, ErrHostClaimMismatch) {
		t.Fatalf("A14 www claim mismatch should return ErrHostClaimMismatch, got %v", err)
	}
}

func TestProviderAuthorizeActionWWWPathUnknown(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// www.googleapis.com path does not match any servicePath → fail closed.
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://www.googleapis.com/notaservice/v9/x"),
		gcpArgs(t, "notaservice"),
	); err == nil {
		t.Fatal("unknown www path should fail closed")
	}
}

func TestProviderAuthorizeActionBadJSON(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		json.RawMessage(`not json`),
	); err == nil {
		t.Fatal("bad JSON should error")
	}
}

func TestProviderAuthorizeActionNonCatalogWWW(t *testing.T) {
	t.Parallel()

	// A Catalog whose ResolveWWWService returns false must fail closed with
	// ErrHostPattern for a www.googleapis.com request (no path → service mapping).
	p := &Provider{
		catalog: &fakeCatalogPort{},
		perms:   NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{}),
		eval:    newRoleEvaluator(map[string]bool{}),
		role:    "",
	}

	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://www.googleapis.com/oauth2/v2/tokeninfo"),
		gcpArgs(t, "oauth2"),
	); !errors.Is(err, ErrHostPattern) {
		t.Fatalf("non-catalog www should return ErrHostPattern, got %v", err)
	}
}

func TestProviderAuthorizeActionBadHost(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)

	// localhost is rejected by ParseHost (SSRF guard) → line 84 error branch.
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://localhost/compute/v1/projects/p/zones/z/instances"),
		gcpArgs(t, "compute"),
	); err == nil {
		t.Fatal("localhost host should fail closed")
	}
}

func TestProviderAuthorizeActionMethodIndexError(t *testing.T) {
	t.Parallel()

	// Catalog resolves the service name but MethodIndex returns an error because
	// the service has no methods doc. Use a service that ResolveService accepts
	// (it's in the data map) but MethodIndex fails on (empty / missing doc).
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			// Has a rootUrl (so ResolveService succeeds via host-index lookup) but
			// the Methods map is nil so MethodIndex returns ErrClassifierUnknownOp.
			"compute": {
				RootURL: "https://compute.googleapis.com/",
				Methods: nil,
			},
		},
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })

	// Override MethodIndex to error: use an interface impl that resolves service
	// OK but returns error on MethodIndex.
	p := NewProvider(
		&methodIndexErrCatalog{inner: cat},
		NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{}),
		newRoleEvaluator(map[string]bool{}),
		"",
	)

	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		gcpArgs(t, "compute"),
	)
	if err == nil {
		t.Fatal("MethodIndex error should propagate")
	}
}

func TestProviderAuthorizeActionClassifyError(t *testing.T) {
	t.Parallel()

	// MethodIndex succeeds but returns an empty index so Classify finds no match.
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"compute": {
				RootURL: "https://compute.googleapis.com/",
				Methods: MethodIndex{}, // empty → Classify returns ErrClassifierUnknownOp.
			},
		},
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	p := NewProvider(
		cat,
		NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{}),
		newRoleEvaluator(map[string]bool{}),
		"",
	)

	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
		gcpArgs(t, "compute"),
	)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("empty method index should return ErrClassifierUnknownOp, got %v", err)
	}
}

// fakeCatalogPort is a minimal Catalog that errors on ResolveService /
// MethodIndex and fails closed on www-compound resolution (no servicePath table).
type fakeCatalogPort struct{}

func (f *fakeCatalogPort) ResolveService(_ context.Context, _ ParsedHost, _ string) (string, error) {
	return "", ErrHostPattern
}

func (f *fakeCatalogPort) MethodIndex(_ context.Context, _ string) (MethodIndex, error) {
	return nil, ErrClassifierUnknownOp
}

func (f *fakeCatalogPort) ResolveWWWService(_ context.Context, _ string) (string, bool) {
	return "", false
}

// methodIndexErrCatalog wraps a *catalog, delegates ResolveService /
// ResolveWWWService, but always returns an error from MethodIndex. Used to cover
// the MethodIndex error branch.
type methodIndexErrCatalog struct{ inner *catalog }

func (m *methodIndexErrCatalog) ResolveService(ctx context.Context, p ParsedHost, host string) (string, error) {
	return m.inner.ResolveService(ctx, p, host)
}

func (m *methodIndexErrCatalog) ResolveWWWService(ctx context.Context, reqPath string) (string, bool) {
	return m.inner.ResolveWWWService(ctx, reqPath)
}

func (m *methodIndexErrCatalog) MethodIndex(_ context.Context, _ string) (MethodIndex, error) {
	return nil, ErrCatalogUnavailable
}

// buildCRMProvider wires a Provider over a faithful v3 cloudresourcemanager catalog
// (the four discovery descriptors, GET, real flatPaths). The permission catalog is
// empty and the dataset is empty, so resolution flows entirely through the pinned
// methodPermissionOverrides; granted is the role's allow-set the eval checks against.
func buildCRMProvider(t *testing.T, granted map[string]bool) *Provider {
	t.Helper()

	crmMethod := func(id, flatPath string) MethodDescriptor {
		// Only FlatPath drives classification (effectiveTemplate ignores Path when
		// FlatPath is non-empty); Path is left empty to make that explicit.
		return MethodDescriptor{ID: id, HTTPMethod: "GET", FlatPath: flatPath, ServicePath: "", Path: ""}
	}
	data := DiscoveryData{
		Services: map[string]ServiceDoc{
			"cloudresourcemanager": {
				RootURL:     "https://cloudresourcemanager.googleapis.com/",
				ServicePath: "",
				Methods: MethodIndex{
					"cloudresourcemanager.projects.list": crmMethod(
						"cloudresourcemanager.projects.list",
						"v3/projects",
					),
					"cloudresourcemanager.projects.search": crmMethod(
						"cloudresourcemanager.projects.search",
						"v3/projects:search",
					),
					"cloudresourcemanager.organizations.search": crmMethod(
						"cloudresourcemanager.organizations.search",
						"v3/organizations:search",
					),
					"cloudresourcemanager.folders.search": crmMethod(
						"cloudresourcemanager.folders.search",
						"v3/folders:search",
					),
				},
			},
		},
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	perms := NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{})
	return NewProvider(cat, perms, newRoleEvaluator(granted), "roles/viewer")
}

// TestProviderAuthorizeActionCRMProjectsListV1Allowed pins the multi-version
// merge regression end to end: when the catalog merges cloudresourcemanager v1
// and v3 (both define cloudresourcemanager.projects.list, at v1/projects vs
// v3/projects), BOTH the GET /v1/projects and GET /v3/projects enumeration calls
// classify and authorize under a role granting the union {projects.get,
// projects.list} (roles/viewer grants both). Before the fix the id-keyed merge
// kept only v3, so GET /v1/projects — the call a read-only audit naturally reaches
// for first — failed closed as ErrClassifierUnknownOp before the permission
// override was ever consulted.
func TestProviderAuthorizeActionCRMProjectsListV1Allowed(t *testing.T) {
	t.Parallel()

	crmDoc := func(flatPath string) restDoc {
		return restDoc{
			RootURL: "https://cloudresourcemanager.googleapis.com/",
			Methods: map[string]methodDoc{
				"projects.list": {ID: "cloudresourcemanager.projects.list", HTTPMethod: "GET", FlatPath: flatPath},
			},
		}
	}
	data, err := assembleCatalog([]fetchedDoc{
		{name: "cloudresourcemanager", doc: crmDoc("v1/projects"), ok: true},
		{name: "cloudresourcemanager", doc: crmDoc("v3/projects"), ok: true},
	})
	if err != nil {
		t.Fatalf("assembleCatalog: %v", err)
	}
	cat := newCatalog(func(context.Context) (DiscoveryData, error) { return data, nil })
	perms := NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{})
	eval := newRoleEvaluator(map[string]bool{
		"resourcemanager.projects.get":  true,
		"resourcemanager.projects.list": true,
	})
	p := NewProvider(cat, perms, eval, "roles/viewer")

	for _, path := range []string{
		"https://cloudresourcemanager.googleapis.com/v1/projects",
		"https://cloudresourcemanager.googleapis.com/v3/projects",
	} {
		if aerr := p.AuthorizeAction(
			context.Background(),
			httpReq(t, "GET", path),
			gcpArgs(t, "cloudresourcemanager"),
		); aerr != nil {
			t.Errorf("AuthorizeAction(%s) under a granting role should be authorized, got %v", path, aerr)
		}
	}
}

// GET /v3/projects under a role granting the projects.list union is authorized.
// This also pins classification of GET /v3/projects -> cloudresourcemanager.projects.list
// (the regression repro): a merge-order regression would surface here as ErrClassifierUnknownOp.
func TestProviderAuthorizeActionCRMProjectsListAllowed(t *testing.T) {
	t.Parallel()

	p := buildCRMProvider(t, map[string]bool{
		"resourcemanager.projects.get":  true,
		"resourcemanager.projects.list": true,
	})
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects"),
		gcpArgs(t, "cloudresourcemanager"),
	); err != nil {
		t.Fatalf("projects.list under a granting role should be authorized, got %v", err)
	}
}

// TestProviderAuthorizeActionCRMProjectsListRequiresGet pins the version-collision
// security fix. v1 GET /v1/projects is an UNFILTERED list that Google authorizes by
// resourcemanager.projects.get (it "Lists Projects that the caller has the
// resourcemanager.projects.get permission on"), while v3's parent-scoped list needs
// resourcemanager.projects.list. Both share the Discovery id
// cloudresourcemanager.projects.list, so the override requires the UNION — a ceiling
// role granting only .list (but not .get) must NOT authorize project enumeration,
// or it would expose .get-level data the operator's ceiling never granted.
func TestProviderAuthorizeActionCRMProjectsListRequiresGet(t *testing.T) {
	t.Parallel()

	p := buildCRMProvider(t, map[string]bool{"resourcemanager.projects.list": true}) // .list but NOT .get.
	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects"),
		gcpArgs(t, "cloudresourcemanager"),
	)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("projects.list with .list but not .get must be ErrPermissionDenied, got %v", err)
	}
}

// GET /v3/projects under a role that does NOT grant the permission is denied
// (ErrPermissionDenied), not ErrPermissionUnresolved — resolution now succeeds.
func TestProviderAuthorizeActionCRMProjectsListDenied(t *testing.T) {
	t.Parallel()

	p := buildCRMProvider(t, map[string]bool{})
	err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects"),
		gcpArgs(t, "cloudresourcemanager"),
	)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("projects.list under an empty role should be ErrPermissionDenied, got %v", err)
	}
}

// GET /v3/projects:search under a role granting resourcemanager.projects.get is authorized.
func TestProviderAuthorizeActionCRMProjectsSearchAllowed(t *testing.T) {
	t.Parallel()

	p := buildCRMProvider(t, map[string]bool{"resourcemanager.projects.get": true})
	if err := p.AuthorizeAction(
		context.Background(),
		httpReq(t, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects:search"),
		gcpArgs(t, "cloudresourcemanager"),
	); err != nil {
		t.Fatalf("projects.search under a granting role should be authorized, got %v", err)
	}
}

// GET /v3/organizations:search and /v3/folders:search under a viewer-like role
// (grants projects.* but not org/folder .get) resolve correctly and deny with the
// precise ErrPermissionDenied — replacing today's confusing ErrPermissionUnresolved.
func TestProviderAuthorizeActionCRMHierarchySearchDenied(t *testing.T) {
	t.Parallel()

	viewerLike := map[string]bool{"resourcemanager.projects.list": true, "resourcemanager.projects.get": true}
	p := buildCRMProvider(t, viewerLike)

	for _, path := range []string{
		"https://cloudresourcemanager.googleapis.com/v3/organizations:search",
		"https://cloudresourcemanager.googleapis.com/v3/folders:search",
	} {
		err := p.AuthorizeAction(
			context.Background(),
			httpReq(t, "GET", path),
			gcpArgs(t, "cloudresourcemanager"),
		)
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s under viewer-like role should be ErrPermissionDenied, got %v", path, err)
		}
	}
}
