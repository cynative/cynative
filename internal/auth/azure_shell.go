package auth

import (
	"context"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

// probeAzureToken validates the credential chain can mint an ARM token for the
// resolved cloud's ARM audience using the caller's (already-bounded) ctx. It
// validates the CHAIN, not the env credential in isolation, so a partial AZURE_*
// env masked by a working interactive session passes (spec exception 3).
func probeAzureToken(ctx context.Context, cred azcore.TokenCredential, scope string) error {
	_, err := cred.GetToken(
		ctx,
		policy.TokenRequestOptions{ //nolint:exhaustruct // only Scopes set.
			Scopes: []string{scope},
		},
	)

	return err
}

// buildHardenedAzureProvider constructs the hardened *azureProvider with all
// Azure I/O deferred to first use. The catalog is built eagerly (cheap, no I/O)
// so Layer 3 host gating works before lazy init completes. The doLazyResolve
// closure performs identity → role-definition permissions → role-evaluator →
// provider → posture on first InjectAuth / AuthorizeAction, populating
// hardeningAction + scopedCredential from the LazyResult.
//
// Azure has no credential-downscoping primitive, so the scoped credential is
// the operator's raw cred; the home-tenant ARM token is minted against the ARM
// audience in InjectAuth (cred_scope=none made permanent).
func buildHardenedAzureProvider(
	cred azcore.TokenCredential, azureCfg AzureHardeningConfig, cc azurehardening.CloudConfig,
) *azureProvider {
	httpClient := &http.Client{Timeout: smithyHTTPTimeout} //nolint:exhaustruct // defaults are fine.
	// armBearer mints the home-tenant ARM bearer against the resolved cloud's ARM
	// audience — the same token InjectAuth uses. The providerOperations GET
	// requires Microsoft.Authorization/providerOperations/read; without it ARM
	// returns 401 and the catalog comes back empty (every Layer-2 check fails).
	armBearer := func(bctx context.Context) (string, error) {
		tok, terr := cred.GetToken(
			bctx,
			policy.TokenRequestOptions{ //nolint:exhaustruct // only Scopes set.
				Scopes: []string{cc.Scope},
			},
		)
		if terr != nil {
			return "", terr
		}
		return tok.Token, nil
	}
	catalog := azurehardening.NewCatalog(
		azurehardening.CatalogConfig{ //nolint:exhaustruct // optional test fields omitted.
			Config:     azureCfg.Config,
			HTTPClient: httpClient,
			BearerFunc: armBearer,
			Cloud:      cc.Name,
		},
	)

	// Build the provider with a nil closure first, then assign one that captures
	// p so it can populate the provider's fields on first call. The cheap clients
	// (role, identity) are constructed inside the closure because their
	// constructors may return an error; the catalog above is infallible.
	p := newAzureProvider(catalog, cc.Scope, nil)
	p.doLazyResolve = func(ctx context.Context) error {
		roles, err := azurehardening.NewRoleClient(
			azurehardening.RoleClientConfig{ //nolint:exhaustruct // test fields omitted.
				Credential: cred,
				Cloud:      cc,
			},
		)
		if err != nil {
			return err
		}
		identity := azurehardening.NewIdentityProber(
			azurehardening.IdentityConfig{ //nolint:exhaustruct // TokenFunc test-only.
				Credential: cred,
				Scope:      cc.Scope,
			},
		)

		res, err := azurehardening.LazyResolve(ctx, azurehardening.LazyDeps{
			RoleDefinition: azureCfg.RoleDefinition,
			Catalog:        catalog,
			Roles:          roles,
			Identity:       identity,
		})
		if err != nil {
			return err
		}
		p.hardeningAction = res.ActionProvider
		p.scopedCredential = cred
		return nil
	}
	return p
}
