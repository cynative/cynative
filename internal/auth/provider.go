// Package auth provides an extensible registry of credential providers
// for injecting authentication into HTTP requests.
//
//go:generate go tool moq -out tokencredential_mock_test.go . tokenCredential
//go:generate go tool moq -out tokensource_mock_test.go . tokenSource
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/oauth2"
)

// Provider defines an extensible interface for injecting API credentials securely.
type Provider interface {
	Name() string
	Description() string
	InjectAuth(req *http.Request, rawArgs json.RawMessage) error
	// AuthorizesHost reports whether this provider permits requests to host
	// (already lower-cased and port-stripped), consulting rawArgs where needed.
	// K8s providers may await a cached cloud-API lookup to resolve the cluster's
	// real endpoint. Any returned error is treated by callers as "denied".
	AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error)
}

// tokenCredential mirrors [azcore.TokenCredential]'s method set so moq can
// generate a mock for it (azcore.TokenCredential is a type alias whose
// underlying package is internal and cannot be referenced directly). A mock
// of this local interface structurally satisfies azcore.TokenCredential, so
// it can be injected wherever a credential is needed.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// tokenSource mirrors [oauth2.TokenSource] so moq can generate a mock that
// is injected wherever an oauth2.TokenSource is needed.
type tokenSource interface {
	Token() (*oauth2.Token, error)
}

// Compile-time assertions that the local mirror interfaces match the external
// ones they stand in for.
var (
	_ tokenCredential = (azcore.TokenCredential)(nil)
	_ tokenSource     = (oauth2.TokenSource)(nil)
)

// ErrModelSuppliedCredential is returned when a request already carries
// credential material before injection. The providers' injectors are the
// sole setters of credentials; a pre-existing one means the model smuggled
// its own.
var ErrModelSuppliedCredential = errors.New(
	"model-supplied credential rejected; credentials are injected automatically by the auth_provider")

// Inject finds the named provider and injects credentials into the request.
// It fails closed first if the request already carries a model-supplied
// credential, so provider InjectAuth implementations (including the
// no-header mTLS paths) never see one.
func Inject(req *http.Request, name string, providers []Provider, rawArgs json.RawMessage) error {
	p, err := find(providers, name)
	if err != nil {
		return err
	}

	if credErr := rejectModelSuppliedCredential(req, name); credErr != nil {
		return credErr
	}

	if injErr := p.InjectAuth(req, rawArgs); injErr != nil {
		return fmt.Errorf("failed to inject auth for provider %s: %w", name, injErr)
	}

	return nil
}

// rejectModelSuppliedCredential fails closed when the request carries
// credential material before injection. It scans the actual header keys with
// EqualFold rather than a canonical Values lookup: a request constructed by
// direct map assignment can hold a non-canonical key (e.g. "authorization")
// that Go still serializes to the wire but Header.Values("Authorization")
// would miss. Presence (len > 0) is what matters, not the value — a duplicate
// or empty-valued header is still emitted. URL userinfo is rejected because
// Go's [http.Client] mints "Authorization: Basic ..." from it whenever
// injection set no Authorization header (the mTLS no-op case).
func rejectModelSuppliedCredential(req *http.Request, name string) error {
	credentialHeaders := []string{
		"Authorization",
		"Proxy-Authorization",
		"X-Http-Authorization", // Rails authorization fallback (X-HTTP_AUTHORIZATION / X_HTTP_AUTHORIZATION, _→- normalized).
		"X-Ms-Authorization-Auxiliary",
		"Private-Token",
		"Job-Token",
		"Deploy-Token",                 // GitLab package/registry deploy-token credential.
		"X-Gitlab-Static-Object-Token", // GitLab private archive/blob static-object credential.
		"Cookie",                       // e.g. GitLab's _gitlab_session — a documented API session credential.
	}
	for _, h := range credentialHeaders {
		for key, values := range req.Header {
			// Normalize '_' to '-' before matching: Rack-style backends fold an
			// underscore header (e.g. Private_Token) onto the same HTTP_ variable as
			// the hyphenated form, so the underscore variant must not slip past.
			if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), h) && len(values) > 0 {
				return fmt.Errorf("%w: %s header present (provider %s)", ErrModelSuppliedCredential, h, name)
			}
		}
	}

	// GitLab (and GCP) accept a token in URL query parameters; reject those too so
	// the model cannot smuggle a credential alongside the provider-injected one.
	// Parse RawQuery explicitly and fail closed on error: req.URL.Query() silently
	// drops pairs on a malformed query (e.g. a ";" separator, which Go rejects but
	// GitLab/Rack still honors as a separator), which would hide a smuggled token.
	params, perr := url.ParseQuery(req.URL.RawQuery)
	if perr != nil {
		return fmt.Errorf("%w: unparseable URL query (provider %s): %w", ErrModelSuppliedCredential, name, perr)
	}
	// GitLab also authenticates RSS/ICS feed routes via feed_token/rss_token query
	// params, so those are rejected alongside the api-token query params.
	credentialParams := []string{"private_token", "access_token", "job_token", "feed_token", "rss_token"}
	for key := range params {
		base := baseParamName(key)
		for _, p := range credentialParams {
			if strings.EqualFold(base, p) {
				return fmt.Errorf("%w: %s query parameter present (provider %s)", ErrModelSuppliedCredential, key, name)
			}
		}
	}

	if req.URL.User != nil {
		return fmt.Errorf("%w: URL userinfo present (provider %s)", ErrModelSuppliedCredential, name)
	}

	return nil
}

// baseParamName strips a Rack-style bracket suffix from a parameter key, returning
// the base name before the first '['. Rack/GitLab expands nested forms like
// "private_token[]" or "access_token[x]" under the base parameter before
// application code reads params, so credential checks must match the base name.
func baseParamName(key string) string {
	base, _, _ := strings.Cut(key, "[")

	return base
}

// getProviderData is the shared optional-capability dispatcher behind the
// Get*Data accessors. When name is empty, or the named provider does not
// implement capability C, it returns the zero value of T and no error; an
// unknown name returns find's error, and an implementing provider's result
// (or error) is returned via call.
func getProviderData[C, T any](
	ctx context.Context,
	name string,
	providers []Provider,
	rawArgs json.RawMessage,
	call func(context.Context, C, json.RawMessage) (T, error),
) (T, error) {
	var zero T
	if name == "" {
		return zero, nil
	}

	p, err := find(providers, name)
	if err != nil {
		return zero, err
	}

	if cp, ok := p.(C); ok {
		return call(ctx, cp, rawArgs)
	}

	return zero, nil
}

// CACertProvider is optionally implemented by auth providers whose target
// API server uses a non-public CA (e.g. EKS clusters with private CAs).
// The returned value must be a base64-encoded PEM certificate.
type CACertProvider interface {
	CACertData(ctx context.Context, rawArgs json.RawMessage) (string, error)
}

// GetCACertData returns the base64-encoded PEM CA certificate from the named
// provider, or "" if the provider doesn't supply one. It returns an error if
// name is non-empty but no provider with that name exists.
func GetCACertData(ctx context.Context, name string, providers []Provider, rawArgs json.RawMessage) (string, error) {
	return getProviderData(ctx, name, providers, rawArgs,
		func(ctx context.Context, cp CACertProvider, args json.RawMessage) (string, error) {
			return cp.CACertData(ctx, args)
		})
}

// ClientCertProvider is optionally implemented by auth providers whose target
// API server uses mTLS authentication.
// The returned values must be base64-encoded PEM certificate and key.
type ClientCertProvider interface {
	ClientCertData(ctx context.Context, rawArgs json.RawMessage) (cert string, key string, err error)
}

// clientCertData pairs a client certificate and key so the two-value
// ClientCert capability fits the single-result getProviderData dispatcher.
type clientCertData struct{ cert, key string }

// GetClientCertData returns the base64-encoded PEM client certificate and private key from the named
// provider, or ("", "") if the provider doesn't supply one. It returns an error if
// name is non-empty but no provider with that name exists.
func GetClientCertData(
	ctx context.Context,
	name string,
	providers []Provider,
	rawArgs json.RawMessage,
) (string, string, error) {
	cc, err := getProviderData(ctx, name, providers, rawArgs,
		func(ctx context.Context, cp ClientCertProvider, args json.RawMessage) (clientCertData, error) {
			cert, key, certErr := cp.ClientCertData(ctx, args)

			return clientCertData{cert: cert, key: key}, certErr
		})

	return cc.cert, cc.key, err
}

// ServerNameProvider is optionally implemented by auth providers that need to
// override the TLS verified name (SNI) for the request — e.g. a self-managed
// Kubernetes endpoint addressed by IP literal whose private CA leaf carries
// only DNS SANs. The returned value, when non-empty, is set as
// tls.Config.ServerName for the per-request transport.
type ServerNameProvider interface {
	ServerNameData(ctx context.Context, rawArgs json.RawMessage) (string, error)
}

// GetServerNameData returns the TLS ServerName override from the named provider,
// or "" if the provider doesn't supply one. It returns an error if name is
// non-empty but no provider with that name exists.
func GetServerNameData(
	ctx context.Context,
	name string,
	providers []Provider,
	rawArgs json.RawMessage,
) (string, error) {
	return getProviderData(ctx, name, providers, rawArgs,
		func(ctx context.Context, sp ServerNameProvider, args json.RawMessage) (string, error) {
			return sp.ServerNameData(ctx, args)
		})
}

// ActionAuthorizer is optionally implemented by providers that perform per-request
// action-level authorization beyond host gating. transport.do calls it via
// AuthorizeAction after AuthorizeHost and before InjectAuth.
type ActionAuthorizer interface {
	AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error
}

// AuthorizeAction dispatches to the named provider's ActionAuthorizer if it
// implements one. Providers without ActionAuthorizer pass through.
func AuthorizeAction(
	ctx context.Context,
	name string,
	req *http.Request,
	providers []Provider,
	rawArgs json.RawMessage,
) error {
	p, err := find(providers, name)
	if err != nil {
		return err
	}

	if ap, ok := p.(ActionAuthorizer); ok {
		if authErr := ap.AuthorizeAction(ctx, req, rawArgs); authErr != nil {
			return fmt.Errorf("auth: authorize action for provider %s: %w", name, authErr)
		}
	}

	return nil
}

// ResponseAuditor is an optional provider capability: a post-response, advisory
// audit of a successful response (e.g. comparing GitHub's authoritative
// X-Accepted-GitHub-Permissions header against the classified access level). It
// must not block and must not consume the body.
type ResponseAuditor interface {
	AuditResponse(req *http.Request, header http.Header)
}

// AuditResponse dispatches a post-response audit to the named provider when it
// implements ResponseAuditor. It is best-effort: unknown provider or no
// capability is a silent no-op (auditing never affects the response).
func AuditResponse(name string, req *http.Request, header http.Header, providers []Provider) {
	p, err := find(providers, name)
	if err != nil {
		return
	}
	if ra, ok := p.(ResponseAuditor); ok {
		ra.AuditResponse(req, header)
	}
}

// ErrUnknownProvider is returned when no registered provider matches the
// requested auth_provider name.
var ErrUnknownProvider = errors.New("unknown or unavailable auth_provider")

// find returns the provider whose Name matches name case-insensitively, or
// ErrUnknownProvider (wrapped with the name) when none does. It is the single
// lookup used by every dispatcher in this file.
func find(providers []Provider, name string) (Provider, error) {
	for _, p := range providers {
		if strings.EqualFold(p.Name(), name) {
			return p, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, name)
}

// ErrHostNotAuthorized is returned when a provider denies a request's host.
var ErrHostNotAuthorized = errors.New("host not authorized for auth_provider")

// AuthorizeHost verifies the named provider permits a request to host. host is
// lower-cased so providers receive a normalized value. It returns an error if
// name is unknown, the provider denies the host, or resolving its endpoint fails.
func AuthorizeHost(ctx context.Context, name, host string, providers []Provider, rawArgs json.RawMessage) error {
	host = strings.ToLower(host)

	p, err := find(providers, name)
	if err != nil {
		return err
	}

	ok, err := p.AuthorizesHost(ctx, host, rawArgs)
	if err != nil {
		return fmt.Errorf("auth: authorize host %q for provider %s: %w", host, name, err)
	}

	if !ok {
		return fmt.Errorf("%w: %q not allowed for provider %s", ErrHostNotAuthorized, host, name)
	}

	return nil
}
