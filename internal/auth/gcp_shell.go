package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

// gcpScope is the cloud-platform scope used for ADC discovery and the probe.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform"

// validateGCPRole confirms the configured GCP role resolves (ceiling only; not
// the full lazy bootstrap). Shell: mints a fresh, ctx-bounded credential source
// (like probeGCPToken) so a hung ADC/token endpoint cannot stall startup beyond
// ceilingValidationTimeout. A plain [http.Client] disables ADC auth and 401s,
// so an oauth2-authed client is required for the IAM Roles API.
func validateGCPRole(ctx context.Context, role string) error {
	creds, err := google.FindDefaultCredentials(ctx, gcpScope)
	if err != nil {
		return err
	}
	authedClient := oauth2.NewClient(ctx, creds.TokenSource)
	authedClient.Timeout = ceilingValidationTimeout
	rc, err := gcphardening.NewIAMRolesClient(ctx, gcphardening.IAMClientConfig{HTTPClient: authedClient})
	if err != nil {
		return err
	}
	_, err = gcphardening.FetchRolePermissions(ctx, rc, role)

	return err
}

// probeGCPToken validates that ADC can mint a token, using a SEPARATE
// credentials source bound to the caller's (already-bounded) ctx so the
// registered (Background-bound) source is never poisoned by the probe's
// context cancellation.
func probeGCPToken(ctx context.Context) error {
	creds, err := google.FindDefaultCredentials(ctx, gcpScope)
	if err != nil {
		return err
	}

	_, err = creds.TokenSource.Token()

	return err
}

// buildHardenedGCPProvider constructs the hardened *gcpProvider with all GCP
// I/O deferred to first use. The catalog is built eagerly (cheap, no I/O) so
// Layer 3 host gating works before lazy init completes. The doLazyResolve
// closure performs identity → role-union → permission-catalog on first
// InjectAuth / AuthorizeAction; the injected token is the raw ADC source.
func buildHardenedGCPProvider(root oauth2.TokenSource, gcpCfg GCPHardeningConfig) *gcpProvider {
	httpClient := &http.Client{Timeout: smithyHTTPTimeout} //nolint:exhaustruct // defaults are fine.
	catalog := gcphardening.NewCatalog(gcphardening.CatalogConfig{
		Config:     gcpCfg.Config,
		HTTPClient: httpClient,
	})
	iamDataset := gcphardening.NewIAMDatasetRegistry(gcphardening.IAMDatasetRegistryConfig{
		Config:  gcpCfg.Config,
		Fetcher: gcphardening.NewIAMDatasetFetcher(httpClient, gcphardening.DefaultIAMDatasetURL),
	})

	// Build the provider with a nil closure first, then assign one that
	// captures p so it can populate the provider's fields on first call.
	p := newGCPProvider(catalog, nil)
	p.doLazyResolve = func(ctx context.Context) error {
		// Every per-call client used by the one-time bootstrap (identity probe →
		// role union → queryTestablePermissions) gets the dedicated bootstrap
		// budget rather than the 30s smithyHTTPTimeout: queryTestablePermissions
		// pages through every testable IAM permission on the project, and any
		// bootstrap stage that times out is cached as not_ready for the whole
		// session. The overall resolve is also capped by ctx
		// (hardeningBootstrapTimeout, decoupled from the request).
		//
		// The IAM roles client must be authenticated: a plain http.Client passed
		// via option.WithHTTPClient disables the google library's automatic ADC
		// auth (sends no token → 401), so build an oauth2 client from the root
		// token source. The identity prober uses a token-in-URL plain client. The
		// catalog (per-request host gating) and iam-dataset (per-request action
		// authorization) keep the 30s httpClient — they are NOT on the bootstrap
		// path and are bounded by the request context.
		bootstrapHTTPClient := &http.Client{Timeout: hardeningBootstrapTimeout} //nolint:exhaustruct // defaults fine.
		authedClient := oauth2.NewClient(ctx, root)
		authedClient.Timeout = hardeningBootstrapTimeout

		roles, err := gcphardening.NewIAMRolesClient(ctx, gcphardening.IAMClientConfig{
			HTTPClient: authedClient,
		})
		if err != nil {
			return err
		}
		res, err := gcphardening.LazyResolve(ctx, gcphardening.LazyDeps{
			Role:       gcpCfg.Role,
			Catalog:    catalog,
			Dataset:    iamDataset,
			Roles:      roles,
			Identity:   gcphardening.NewIdentityProber(gcphardening.IdentityConfig{HTTPClient: bootstrapHTTPClient}),
			RootSource: root,
		})
		if err != nil {
			return err
		}
		p.hardeningAction = res.ActionProvider
		p.tokenSource = res.TokenSource
		return nil
	}
	return p
}
