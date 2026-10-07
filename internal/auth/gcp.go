package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/cache"
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
	// docs serves api_reference; nil when no docs are wired (bare providers in tests).
	docs *gcphardening.Docs
}

var (
	_ Provider            = (*gcpProvider)(nil)
	_ ActionAuthorizer    = (*gcpProvider)(nil)
	_ OperationDocumenter = (*gcpProvider)(nil)
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
	return &gcpProvider{ //nolint:exhaustruct // zero lazyInit once/err + nil tokenSource/hardeningAction intentional.
		catalog:          catalog,
		prefix:           "gcp_hardening",
		bootstrapTimeout: hardeningBootstrapTimeout,
		doLazyResolve:    doLazyResolve,
	}
}

func (p *gcpProvider) Name() string { return gcpProviderName }

func (p *gcpProvider) Description() string {
	return "Google Cloud Platform API authentication (hardened). Discovers Application Default " +
		"Credentials (ADC) and authorizes each request with read-only action authorization and " +
		"host pinning. Requires gcp_auth field." +
		" For an operation's request template and response format, call the api_reference tool."
}

// newGCPDocs builds the api_reference store under <cache>/gcp/docs. fetch is the anonymous capped download;
// nothing here reaches the gate's catalog cache or the credential bootstrap.
func newGCPDocs(cfg cache.Config, fetch func(ctx context.Context, url string) ([]byte, error)) *gcphardening.Docs {
	return gcphardening.NewDocs(cache.Config{Dir: filepath.Join(cfg.Dir, "docs"), TTL: cfg.TTL, Clock: cfg.Clock},
		gcphardening.DefaultDiscoveryDirectoryURL, fetch)
}

// Reference answers an api_reference lookup from the Discovery documents. It
// never runs the lazy credential bootstrap and never reads the gate's catalog.
func (p *gcpProvider) Reference(ctx context.Context, q apiref.Query) apiref.Result {
	if p.docs == nil {
		return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "GCP API metadata is not configured"}
	}

	return p.docs.Reference(ctx, q)
}

// Hint suggests methods for a request the classifier matched to none, from
// the catalog snapshot the gate already loaded. It never fetches: with no
// snapshot in memory it suggests nothing.
func (p *gcpProvider) Hint(_ context.Context, v authreq.View, e *authreq.UnmatchedRequestError) apiref.Hint {
	return gcphardening.Hint(func() gcphardening.MethodIndex {
		idx, _ := p.catalog.PeekMethodIndex(e.Service)

		return idx
	}, v)
}

// parseGCPArgs decodes gcp_auth; fails closed when absent or Service is empty.
func parseGCPArgs(args authreq.ProviderArgs) (*GCPAuthArgs, error) {
	gcpArgs, err := authreq.Parse[GCPAuthArgs](args)
	if err != nil {
		return nil, err
	}
	if gcpArgs == nil || gcpArgs.Service == "" {
		return nil, errors.New("gcp_auth.service is required")
	}
	return gcpArgs, nil
}

// AuthorizesHost runs Layer 3: parse args → ParseHost → catalog.ResolveService →
// Verify. The catalog is available pre-lazy so host gating works before ready.
// For www.googleapis.com (the wwwCompoundSentinel) the service is path-dependent,
// so Layer 3 accepts the host and Layer 2 (AuthorizeAction) resolves the service
// from the path and checks it against the gcp_auth.service claim. That division is
// only sound because the transport rejects a model-supplied Host header, so the
// host Layer 3 is asked about is always the host Layer 2 classifies and the wire
// sends. For all other googleapis.com hosts the service is resolved here and
// verified against the claim as usual.
func (p *gcpProvider) AuthorizesHost(ctx context.Context, host string, args authreq.ProviderArgs) (bool, error) {
	gcpArgs, err := parseGCPArgs(args)
	if err != nil {
		return false, err
	}
	parsed, err := gcphardening.ParseHost(host)
	if err != nil {
		return false, err
	}
	// www.googleapis.com service is path-dependent; Layer 2 (AuthorizeAction) has
	// the full request and performs the claim check there. Sound only because the
	// transport rejects a Host header, so this host is the one Layer 2 classifies.
	if parsed.Service == gcphardening.WWWCompoundSentinel() {
		return true, nil
	}
	svc, err := p.catalog.ResolveService(ctx, parsed, strings.ToLower(host))
	if err != nil {
		return false, err
	}
	return true, gcphardening.Verify(parsed.WithService(svc), gcpArgs.Service, gcpArgs.Location)
}

// AuthorizeAction implements auth.ActionAuthorizer, delegating to the composed
// Layer 2 provider after lazy init.
func (p *gcpProvider) AuthorizeAction(ctx context.Context, v authreq.View, args authreq.ProviderArgs) error {
	if err := authorizeRequestPort(v, httpsPort); err != nil {
		return err
	}

	if err := p.ensureReady(ctx); err != nil {
		return err
	}
	if p.hardeningAction == nil {
		return errors.New("gcp_hardening: action authorizer not initialized")
	}
	return p.hardeningAction.AuthorizeAction(ctx, v, args)
}

// InjectAuth attaches the raw ADC bearer token. Read-only and host gating are
// enforced by Layer-2 action authorization and Layer-3 host pinning, not by the
// credential itself.
func (p *gcpProvider) InjectAuth(req *http.Request, _ authreq.ProviderArgs) error {
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
