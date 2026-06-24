package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

const gcpProviderName = "gcp"

// GCPAuthArgs holds GCP-specific authentication arguments declared by the model.
// The service is verified against the request host (Layer 3); AuthorizeAction
// (Layer 2) derives the service from the HOST only, never from this claim.
type GCPAuthArgs struct {
	Service  string `json:"service"            jsonschema_description:"Google API service name as in the Discovery doc (e.g. 'compute', 'storage', 'cloudresourcemanager'). Required."`                 //nolint:lll // struct tags are indivisible
	Location string `json:"location,omitempty" jsonschema_description:"GCP location for a regional/locational endpoint (e.g. 'us-central1'); omit for global endpoints or to derive it from the host."` //nolint:lll // struct tags are indivisible
}

type gcpProvider struct {
	// lazyInit defers token-source + hardening resolution to first need.
	// Defaulted by the shell in buildHardenedGCPProvider; tests substitute a
	// fake closure.
	lazyInit

	catalog         gcphardening.Catalog // Layer 3 host resolution, available pre-lazy.
	tokenSource     oauth2.TokenSource   // populated by lazy init; the raw ADC token (no downscoping).
	hardeningAction ActionAuthorizer     // Layer 2; delegates AuthorizeAction, set by the shell on lazy init.
}

var (
	_ Provider         = (*gcpProvider)(nil)
	_ ActionAuthorizer = (*gcpProvider)(nil)
)

// newGCPProvider constructs a GCP provider with the catalog available immediately
// (Layer 3 works pre-ready) and a lazy closure that populates hardening +
// tokenSource on first need. The closure is invoked at most once by
// ensureReady via [sync.Once]. Tests substitute their own closure; the production
// wiring lives in buildHardenedGCPProvider.
func newGCPProvider(
	catalog gcphardening.Catalog,
	doLazyResolve func(ctx context.Context) error,
) *gcpProvider {
	return &gcpProvider{ //nolint:exhaustruct // zero lazyInit + nil tokenSource/hardeningAction are intentional.
		catalog: catalog,
		lazyInit: lazyInit{
			prefix:           "gcp_hardening",
			bootstrapTimeout: hardeningBootstrapTimeout,
			doLazyResolve:    doLazyResolve,
		}, //nolint:exhaustruct // once/err zero.
	}
}

func (p *gcpProvider) Name() string { return gcpProviderName }

func (p *gcpProvider) Description() string {
	return "Google Cloud Platform API authentication (hardened). Discovers Application Default " +
		"Credentials (ADC) and authorizes each request with read-only action authorization and " +
		"host pinning. Requires gcp_auth field."
}

// parseGCPArgs unmarshals gcp_auth; fails closed when nil or Service is empty.
func parseGCPArgs(rawArgs json.RawMessage) (*GCPAuthArgs, error) {
	args, err := parseAuthArgs[GCPAuthArgs](rawArgs, "gcp_auth")
	if err != nil {
		return nil, err
	}
	if args == nil || args.Service == "" {
		return nil, errors.New("gcp_auth.service is required")
	}
	return args, nil
}

// AuthorizesHost runs Layer 3: parse args → ParseHost → catalog.ResolveService →
// Verify. The catalog is available pre-lazy so host gating works before ready.
// For www.googleapis.com (the wwwCompoundSentinel), Layer 3 accepts the host
// unconditionally — the authoritative service resolution and claim check happen
// in Layer 2 (AuthorizeAction), which has access to the full request path.
// For all other googleapis.com hosts, the service is resolved here and verified
// against the gcp_auth.service claim as usual.
func (p *gcpProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	args, err := parseGCPArgs(rawArgs)
	if err != nil {
		return false, err
	}
	parsed, err := gcphardening.ParseHost(host)
	if err != nil {
		return false, err
	}
	// www.googleapis.com service is path-dependent; Layer 2 (AuthorizeAction)
	// has the full request and performs the claim check there.
	if parsed.Service == gcphardening.WWWCompoundSentinel() {
		return true, nil
	}
	svc, err := p.catalog.ResolveService(ctx, parsed, strings.ToLower(host))
	if err != nil {
		return false, err
	}
	return true, gcphardening.Verify(parsed.WithService(svc), args.Service, args.Location)
}

// AuthorizeAction implements auth.ActionAuthorizer, delegating to the composed
// Layer 2 provider after lazy init.
func (p *gcpProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	if err := p.ensureReady(ctx); err != nil {
		return err
	}
	if p.hardeningAction == nil {
		return errors.New("gcp_hardening: action authorizer not initialized")
	}
	return p.hardeningAction.AuthorizeAction(ctx, req, rawArgs)
}

// InjectAuth attaches the raw ADC bearer token. Read-only and host gating are
// enforced by Layer-2 action authorization and Layer-3 host pinning, not by the
// credential itself.
func (p *gcpProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	if err := p.ensureReady(req.Context()); err != nil {
		return err
	}
	token, err := p.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to retrieve GCP token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return nil
}
