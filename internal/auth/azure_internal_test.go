package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

// fakeAzureCatalog resolves only management.azure.com → AzureCloud; else errors.
type fakeAzureCatalog struct{}

func (fakeAzureCatalog) ResolveCloud(
	_ context.Context, p azurehardening.ParsedHost,
) (azurehardening.ParsedHost, error) {
	if p.Host == "management.azure.com" {
		p.Cloud = "AzureCloud"
		return p, nil
	}
	return azurehardening.ParsedHost{}, errors.New("fake: unknown host")
}

func (fakeAzureCatalog) ResourceTypes(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("fake: ResourceTypes not used here")
}

func (fakeAzureCatalog) LookupOperation(
	_ context.Context, _, _, _ string,
) ([]string, map[string]bool, error) {
	return nil, nil, errors.New("fake: LookupOperation not used here")
}

// fakeAzureCred returns a fixed token; tokenErr forces a failure.
type fakeAzureCred struct {
	token    string
	tokenErr error
}

func (f fakeAzureCred) GetToken(
	_ context.Context, _ policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	if f.tokenErr != nil {
		return azcore.AccessToken{}, f.tokenErr
	}
	return azcore.AccessToken{Token: f.token}, nil //nolint:exhaustruct // only Token matters.
}

// newTestAzureProvider builds an azureProvider with injected fakes. The fake
// doLazyResolve sets scopedCredential and hardeningAction.
func newTestAzureProvider(scoped azcore.TokenCredential, action ActionAuthorizer) *azureProvider {
	p := &azureProvider{ //nolint:exhaustruct // test helper; zero values intentional.
		catalog: fakeAzureCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error {
		p.scopedCredential = scoped
		p.hardeningAction = action
		return nil
	}
	return p
}

func newTestAzureProviderLazyErr(msg string) *azureProvider {
	p := &azureProvider{ //nolint:exhaustruct // test helper; zero values intentional.
		catalog: fakeAzureCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error { return errors.New(msg) }
	return p
}

// fakeAzureAction records delegation and returns retErr.
type fakeAzureAction struct {
	called bool
	retErr error
}

func (f *fakeAzureAction) AuthorizeAction(_ context.Context, _ *http.Request, _ json.RawMessage) error {
	f.called = true
	return f.retErr
}

func TestAzureAuthArgs_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	in := AzureAuthArgs{Service: "Microsoft.Compute", Cloud: "AzureCloud"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out struct {
		Service string `json:"service"`
		Cloud   string `json:"cloud"`
	}
	if uErr := json.Unmarshal(raw, &out); uErr != nil {
		t.Fatalf("unmarshal: %v", uErr)
	}
	if out.Service != "Microsoft.Compute" || out.Cloud != "AzureCloud" {
		t.Errorf("round-trip = %+v", out)
	}
}

func TestNewAzureProviderConstructor(t *testing.T) {
	t.Parallel()
	cred := fakeAzureCred{token: "tok"} //nolint:exhaustruct // only token matters.
	var called bool
	var p *azureProvider
	p = newAzureProvider(fakeAzureCatalog{}, "https://management.azure.com/.default", func(_ context.Context) error {
		called = true
		p.scopedCredential = cred
		return nil
	})
	if p == nil {
		t.Fatal("newAzureProvider returned nil")
	}
	if err := p.ensureReady(context.Background()); err != nil {
		t.Fatalf("ensureReady = %v", err)
	}
	if !called {
		t.Error("doLazyResolve was not called")
	}
}

func TestParseAzureArgs(t *testing.T) {
	t.Parallel()
	if _, err := parseAzureArgs(json.RawMessage(`{}`)); err == nil {
		t.Error("missing azure_auth should error")
	}
	if _, err := parseAzureArgs(json.RawMessage(`{"azure_auth":{"service":""}}`)); err == nil {
		t.Error("empty service should error")
	}
	if _, err := parseAzureArgs(json.RawMessage(`{bad`)); err == nil {
		t.Error("invalid JSON should error")
	}
	args, err := parseAzureArgs(json.RawMessage(`{"azure_auth":{"service":"Microsoft.Compute","cloud":"AzureCloud"}}`))
	if err != nil || args.Service != "Microsoft.Compute" {
		t.Fatalf("parseAzureArgs = %+v err=%v", args, err)
	}
}

func TestAzureProvider_NameDescription(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{token: "tok"}, &fakeAzureAction{})
	if p.Name() != "azure" {
		t.Errorf("Name() = %q, want azure", p.Name())
	}
	if p.Description() == "" {
		t.Error("Description() empty")
	}
}

func TestAzureAuthorizesHost(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{token: "tok"}, &fakeAzureAction{})
	ctx := context.Background()
	// Happy: control-plane host, cloud claim matches.
	ok, err := p.AuthorizesHost(ctx, "management.azure.com",
		json.RawMessage(`{"azure_auth":{"service":"Microsoft.Compute","cloud":"AzureCloud"}}`))
	if err != nil || !ok {
		t.Fatalf("AuthorizesHost accept = %v err=%v", ok, err)
	}
	// Missing azure_auth → fail closed.
	if _, mErr := p.AuthorizesHost(ctx, "management.azure.com", json.RawMessage(`{}`)); mErr == nil {
		t.Error("missing azure_auth should error")
	}
	// Data-plane host → rejected by ParseHost (before the catalog is consulted).
	if _, uErr := p.AuthorizesHost(ctx, "myvault.vault.azure.net",
		json.RawMessage(`{"azure_auth":{"service":"Microsoft.KeyVault"}}`)); uErr == nil {
		t.Error("data-plane host should be rejected")
	}
	// Valid control-plane host the fake catalog does not resolve → ResolveCloud
	// rejects (exercises the post-ResolveCloud error branch).
	if _, rErr := p.AuthorizesHost(ctx, "management.usgovcloudapi.net",
		json.RawMessage(`{"azure_auth":{"service":"Microsoft.Compute","cloud":"AzureUSGovernment"}}`)); rErr == nil {
		t.Error("catalog ResolveCloud rejection should propagate")
	}
}

func TestAzureAuthorizesHost_InvalidHost(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{token: "tok"}, &fakeAzureAction{})
	// localhost is rejected by ParseHost before the catalog is consulted.
	if _, err := p.AuthorizesHost(context.Background(), "localhost",
		json.RawMessage(`{"azure_auth":{"service":"Microsoft.Compute"}}`)); err == nil {
		t.Error("localhost should be rejected by ParseHost")
	}
}

func TestAzureAuthorizeAction_Delegates(t *testing.T) {
	t.Parallel()
	fake := &fakeAzureAction{} //nolint:exhaustruct // retErr nil.
	p := newTestAzureProvider(fakeAzureCred{token: "tok"}, fake)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://management.azure.com/subscriptions", nil)
	if err := p.AuthorizeAction(context.Background(), req,
		json.RawMessage(`{"azure_auth":{"service":"Microsoft.Resources"}}`)); err != nil {
		t.Fatalf("AuthorizeAction = %v", err)
	}
	if !fake.called {
		t.Error("hardeningAction.AuthorizeAction not called")
	}
}

func TestAzureAuthorizeAction_LazyError(t *testing.T) {
	t.Parallel()
	p := newTestAzureProviderLazyErr("init-failed")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
		t.Error("AuthorizeAction should error on lazy failure")
	}
}

func TestAzureAuthorizeAction_NilHardening(t *testing.T) {
	t.Parallel()
	p := &azureProvider{ //nolint:exhaustruct // test; nil hardeningAction intentional.
		catalog: fakeAzureCatalog{},
	}
	p.doLazyResolve = func(_ context.Context) error { return nil } // leaves hardeningAction nil.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
		t.Error("AuthorizeAction should error when hardeningAction is nil")
	}
}

func TestAzureInjectAuth_Success(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{token: "scoped-token"}, &fakeAzureAction{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("InjectAuth = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer scoped-token" {
		t.Errorf("Authorization = %q, want Bearer scoped-token", got)
	}
}

// scopeCapturingCred records the scope GetToken was called with.
type scopeCapturingCred struct{ gotScope string }

func (c *scopeCapturingCred) GetToken(
	_ context.Context, opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	if len(opts.Scopes) > 0 {
		c.gotScope = opts.Scopes[0]
	}

	return azcore.AccessToken{Token: "tok"}, nil //nolint:exhaustruct // only Token matters.
}

// TestAzureInjectAuth_UsesResolvedScope pins that InjectAuth mints the bearer for
// the provider's resolved (per-cloud) scope, not a hardcoded public-cloud audience.
func TestAzureInjectAuth_UsesResolvedScope(t *testing.T) {
	t.Parallel()
	cred := &scopeCapturingCred{}
	var p *azureProvider
	p = newAzureProvider(fakeAzureCatalog{}, "https://management.usgovcloudapi.net/.default",
		func(_ context.Context) error { p.scopedCredential = cred; return nil })
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://management.usgovcloudapi.net/x", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("InjectAuth = %v", err)
	}
	if cred.gotScope != "https://management.usgovcloudapi.net/.default" {
		t.Errorf("scope = %q, want the US-Gov ARM scope", cred.gotScope)
	}
}

func TestAzureInjectAuth_LazyError(t *testing.T) {
	t.Parallel()
	p := newTestAzureProviderLazyErr("init-failed")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err == nil {
		t.Error("InjectAuth should error on lazy failure")
	}
}

func TestAzureInjectAuth_TokenError(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{tokenErr: errors.New("boom")}, &fakeAzureAction{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := p.InjectAuth(req, json.RawMessage(`{}`)); err == nil {
		t.Error("InjectAuth should propagate token error")
	}
}

func TestAzureInjectAuth_RejectsModelSAS(t *testing.T) {
	t.Parallel()
	p := newTestAzureProvider(fakeAzureCred{token: "scoped-token"}, &fakeAzureAction{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://management.azure.com/x?sig=abc&sv=2021", nil)
	err := p.InjectAuth(req, json.RawMessage(`{}`))
	if !errors.Is(err, azurehardening.ErrModelSuppliedCredential) {
		t.Errorf("InjectAuth SAS = %v, want ErrModelSuppliedCredential", err)
	}
}
