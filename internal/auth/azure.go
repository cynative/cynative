package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

const azureProviderName = "azure"

// AzureAuthArgs holds Azure-specific authentication arguments declared by the
// model. The service is verified at Layer 2 against the URL path namespace
// (never used as a classification source); cloud is verified at Layer 3.
type AzureAuthArgs struct {
	Service string `json:"service"         jsonschema_description:"ARM resource-provider namespace as in the URL path (e.g. 'Microsoft.Compute'); for provider-less roots use 'Microsoft.Resources'. Required."` //nolint:lll // struct tags are indivisible
	Cloud   string `json:"cloud,omitempty" jsonschema_description:"Azure cloud: 'AzureCloud' (default), 'AzureUSGovernment', or 'AzureChinaCloud'. Optional; derived from the host when omitted."`               //nolint:lll // struct tags are indivisible
}

type azureProvider struct {
	// lazyInit defers scopedCredential + hardeningAction resolution to first
	// need. Defaulted by the shell in buildHardenedAzureProvider; tests
	// substitute a fake closure.
	lazyInit

	catalog          azurehardening.Catalog // Layer-3 host pinning, usable pre-lazy.
	scope            string                 // resolved cloud's ARM audience the bearer is minted for.
	scopedCredential azcore.TokenCredential // home-tenant-authority token source; set by lazy init.
	hardeningAction  ActionAuthorizer       // Layer 2 + Layer 1; set by lazy init.
}

var (
	_ Provider         = (*azureProvider)(nil)
	_ ActionAuthorizer = (*azureProvider)(nil)
)

// newAzureProvider constructs an Azure provider with the catalog available
// immediately (Layer 3 works pre-ready) and a lazy closure that populates
// hardeningAction + scopedCredential on first need. The closure is invoked at
// most once by ensureReady via [sync.Once]. Tests substitute their own closure;
// the production wiring lives in buildHardenedAzureProvider.
func newAzureProvider(
	catalog azurehardening.Catalog,
	scope string,
	doLazyResolve func(ctx context.Context) error,
) *azureProvider {
	return &azureProvider{ //nolint:exhaustruct // zero lazyInit + nil scoped/hardening fields are intentional.
		catalog: catalog,
		scope:   scope,
		lazyInit: lazyInit{
			prefix:           "azure_hardening",
			bootstrapTimeout: hardeningBootstrapTimeout,
			doLazyResolve:    doLazyResolve,
		}, //nolint:exhaustruct // once/err zero.
	}
}

func (p *azureProvider) Name() string { return azureProviderName }

func (p *azureProvider) Description() string {
	return "Azure ARM control-plane authentication (hardened). Discovers credentials via " +
		"the Azure credential chain (CLI/environment/workload identity preferred over " +
		"managed identity), pins the host to the cloud's resource manager, gates every " +
		"request against an allow-list RBAC role and injects the " +
		"operator's raw home-tenant ARM bearer. Requires azure_auth field with service."
}

// parseAzureArgs unmarshals azure_auth; fails closed when nil or Service empty.
func parseAzureArgs(rawArgs json.RawMessage) (*AzureAuthArgs, error) {
	args, err := parseAuthArgs[AzureAuthArgs](rawArgs, "azure_auth")
	if err != nil {
		return nil, err
	}
	if args == nil || args.Service == "" {
		return nil, errors.New("azure_auth.service is required")
	}
	return args, nil
}

// AuthorizesHost runs Layer 3: parse args → ParseHost → catalog.ResolveCloud →
// Verify. The catalog is available pre-lazy so host gating works before ready.
// The service is verified at Layer 2 against the URL path; Layer 3 verifies
// only the host↔cloud pin via Verify.
func (p *azureProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	args, err := parseAzureArgs(rawArgs)
	if err != nil {
		return false, err
	}
	parsed, err := azurehardening.ParseHost(host)
	if err != nil {
		return false, err
	}
	resolved, err := p.catalog.ResolveCloud(ctx, parsed)
	if err != nil {
		return false, err
	}
	return true, azurehardening.Verify(resolved, args.Cloud)
}

// AuthorizeAction implements auth.ActionAuthorizer, delegating to the composed
// Layer 1 + Layer 2 provider after lazy init.
func (p *azureProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	if err := p.ensureReady(ctx); err != nil {
		return err
	}
	if p.hardeningAction == nil {
		return errors.New("azure_hardening: action authorizer not initialized")
	}
	return p.hardeningAction.AuthorizeAction(ctx, req, rawArgs)
}

// InjectAuth rejects a model-supplied SAS credential (the generic credential
// headers are rejected earlier, by auth.Inject), then sets the operator's raw
// home-tenant ARM bearer. Our injector is the sole setter of
// Authorization: Bearer.
func (p *azureProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	if err := p.ensureReady(req.Context()); err != nil {
		return err
	}
	if err := rejectModelSuppliedSAS(req); err != nil {
		return err
	}
	token, err := p.scopedCredential.GetToken(
		req.Context(),
		policy.TokenRequestOptions{ //nolint:exhaustruct // only Scopes set.
			Scopes: []string{p.scope},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to retrieve Azure token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	return nil
}

// rejectModelSuppliedSAS fails closed when the model smuggles an Azure SAS
// credential: a signature (?sig=) in the query string. Credential headers
// are rejected generically by auth.Inject before any provider runs; the SAS
// query form is Azure-specific, so it stays here.
func rejectModelSuppliedSAS(req *http.Request) error {
	if req.URL.Query().Has("sig") {
		return fmt.Errorf("%w: SAS sig= query parameter present", azurehardening.ErrModelSuppliedCredential)
	}
	return nil
}
