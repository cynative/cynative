package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

// fakeCatalog resolves only "compute" → success; anything else errors.
type fakeCatalog struct{}

func (fakeCatalog) ResolveService(_ context.Context, parsed gcphardening.ParsedHost, _ string) (string, error) {
	if parsed.Service == "compute" {
		return "compute", nil
	}
	return "", errors.New("fake: unknown service")
}

func (fakeCatalog) MethodIndex(_ context.Context, _ string) (gcphardening.MethodIndex, error) {
	return nil, errors.New("fake: MethodIndex not used in these tests")
}

func (fakeCatalog) ResolveWWWService(_ context.Context, _ string) (string, bool) {
	return "", false
}

// fakeTokenSource returns a fixed token without error.
type fakeTokenSource struct{ accessToken string }

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: f.accessToken}, nil
}

// fakeErrorTokenSource always returns an error.
type fakeErrorTokenSource struct{}

func (fakeErrorTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("fake: token error")
}

// newTestGCPProvider builds a gcpProvider with injected fake deps.
// lazyScopedToken is what the fake doLazyResolve will set as tokenSource.
func newTestGCPProvider(lazyScopedToken oauth2.TokenSource) *gcpProvider {
	p := &gcpProvider{ //nolint:exhaustruct // test helper; zero values intentional.
		catalog: fakeCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error {
		p.tokenSource = lazyScopedToken
		return nil
	}
	return p
}

// newTestGCPProviderLazyErr builds a gcpProvider whose lazy init always fails.
func newTestGCPProviderLazyErr(msg string) *gcpProvider {
	p := &gcpProvider{ //nolint:exhaustruct // test helper; zero values intentional.
		catalog: fakeCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error {
		return errors.New(msg)
	}
	return p
}

func TestGCPAuthArgs_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	in := GCPAuthArgs{Service: "compute", Location: "us-central1"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out struct {
		Service  string `json:"service"`
		Location string `json:"location"`
	}
	if unmarshalErr := json.Unmarshal(raw, &out); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if out.Service != "compute" || out.Location != "us-central1" {
		t.Errorf("round-trip = %+v, want {compute us-central1}", out)
	}
}

func TestNewGCPProviderConstructor(t *testing.T) {
	t.Parallel()
	// Exercise newGCPProvider directly so the constructor body is covered.
	ts := &fakeTokenSource{"tok"}
	var called bool
	var p *gcpProvider
	p = newGCPProvider(fakeCatalog{}, func(_ context.Context) error {
		called = true
		p.tokenSource = ts
		return nil
	})
	if p == nil {
		t.Fatal("newGCPProvider returned nil")
	}
	if err := p.ensureReady(context.Background()); err != nil {
		t.Fatalf("ensureReady = %v", err)
	}
	if !called {
		t.Error("doLazyResolve was not called")
	}
}

func TestParseGCPArgs(t *testing.T) {
	t.Parallel()

	if _, err := parseGCPArgs(json.RawMessage(`{}`)); err == nil {
		t.Error("missing gcp_auth should error")
	}
	if _, err := parseGCPArgs(json.RawMessage(`{"gcp_auth":{"service":""}}`)); err == nil {
		t.Error("empty service should error")
	}
	args, err := parseGCPArgs(json.RawMessage(`{"gcp_auth":{"service":"compute","location":"us-central1"}}`))
	if err != nil || args.Service != "compute" || args.Location != "us-central1" {
		t.Fatalf("parseGCPArgs = %+v err=%v", args, err)
	}
}

func TestParseGCPArgs_InvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := parseGCPArgs(json.RawMessage(`not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestGCPProvider_Name(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})
	if p.Name() != "gcp" {
		t.Errorf("Name() = %q, want gcp", p.Name())
	}
}

func TestGCPProvider_Description(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})
	if p.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestGCPAuthorizesHost(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})

	ctx := context.Background()
	// Happy path: compute.googleapis.com with claim service=compute.
	ok, err := p.AuthorizesHost(ctx, "compute.googleapis.com",
		json.RawMessage(`{"gcp_auth":{"service":"compute"}}`))
	if err != nil || !ok {
		t.Fatalf("AuthorizesHost accept = %v err=%v", ok, err)
	}
	// A1: claim lies about service.
	_, mismatchErr := p.AuthorizesHost(ctx, "compute.googleapis.com",
		json.RawMessage(`{"gcp_auth":{"service":"iam"}}`))
	if mismatchErr == nil {
		t.Error("A1 mismatch should error")
	}
	// A15: missing gcp_auth.
	_, missingErr := p.AuthorizesHost(ctx, "compute.googleapis.com", json.RawMessage(`{}`))
	if missingErr == nil {
		t.Error("A15 missing gcp_auth should error")
	}
}

func TestGCPAuthorizesHost_UnknownService(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})

	ctx := context.Background()
	// "storage" is not in the fake catalog → ResolveService returns error.
	_, err := p.AuthorizesHost(ctx, "storage.googleapis.com",
		json.RawMessage(`{"gcp_auth":{"service":"storage"}}`))
	if err == nil {
		t.Error("unknown service in catalog should error")
	}
}

func TestGCPAuthorizesHost_InvalidHost(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})

	ctx := context.Background()
	// localhost is rejected by ParseHost.
	_, err := p.AuthorizesHost(ctx, "localhost",
		json.RawMessage(`{"gcp_auth":{"service":"compute"}}`))
	if err == nil {
		t.Error("localhost should be rejected by ParseHost")
	}
}

// TestGCPAuthorizesHost_WWWSentinel covers the www.googleapis.com branch in
// AuthorizesHost: Layer 3 must accept the host unconditionally (return true,
// nil) so that Layer 2 can perform the path-based service resolution and claim
// check on the full request.
func TestGCPAuthorizesHost_WWWSentinel(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"tok"})

	ctx := context.Background()
	// www.googleapis.com is the compound sentinel: Layer 3 accepts it without
	// resolving the service (that happens in AuthorizeAction with the full path).
	ok, err := p.AuthorizesHost(ctx, "www.googleapis.com",
		json.RawMessage(`{"gcp_auth":{"service":"oauth2"}}`))
	if err != nil || !ok {
		t.Fatalf("AuthorizesHost www sentinel = ok=%v err=%v, want true/nil", ok, err)
	}
}

func TestGCPInjectAuth_Success(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(&fakeTokenSource{"scoped-token"})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("InjectAuth = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer scoped-token" {
		t.Errorf("Authorization = %q, want Bearer scoped-token", got)
	}
}

func TestGCPInjectAuth_LazyError(t *testing.T) {
	t.Parallel()
	p := newTestGCPProviderLazyErr("init-failed")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err == nil {
		t.Error("InjectAuth should error when lazy init fails")
	}
}

func TestGCPInjectAuth_TokenError(t *testing.T) {
	t.Parallel()
	p := newTestGCPProvider(fakeErrorTokenSource{})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err == nil {
		t.Error("InjectAuth should propagate token error")
	}
}

// fakeHardeningProvider implements ActionAuthorizer for testing delegation.
type fakeHardeningProvider struct {
	called bool
	retErr error
}

func (f *fakeHardeningProvider) AuthorizeAction(_ context.Context, _ *http.Request, _ json.RawMessage) error {
	f.called = true
	return f.retErr
}

func TestGCPAuthorizeAction_Delegates(t *testing.T) {
	t.Parallel()

	fake := &fakeHardeningProvider{retErr: nil}
	p := &gcpProvider{ //nolint:exhaustruct // test; zero values intentional.
		catalog: fakeCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error {
		p.tokenSource = &fakeTokenSource{"tok"}
		p.hardeningAction = fake
		return nil
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.AuthorizeAction(
		context.Background(),
		req,
		json.RawMessage(`{"gcp_auth":{"service":"compute"}}`),
	); err != nil {
		t.Fatalf("AuthorizeAction = %v", err)
	}
	if !fake.called {
		t.Error("expected hardening.AuthorizeAction to be called")
	}
}

func TestGCPAuthorizeAction_LazyError(t *testing.T) {
	t.Parallel()
	p := newTestGCPProviderLazyErr("init-failed")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
		t.Error("AuthorizeAction should error when lazy init fails")
	}
}

func TestGCPAuthorizeAction_NilHardening(t *testing.T) {
	t.Parallel()
	// Lazy init succeeds but leaves hardeningAction nil.
	p := &gcpProvider{ //nolint:exhaustruct // test; zero values intentional.
		catalog: fakeCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error {
		p.tokenSource = &fakeTokenSource{"tok"}
		p.hardeningAction = nil
		return nil
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://compute.googleapis.com/", nil)
	if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
		t.Error("AuthorizeAction should error when hardeningAction is nil")
	}
}
