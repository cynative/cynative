package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
)

const githubProviderName = "github"

// githubCDNHost is the codeload CDN that tarball/zipball downloads redirect to.
const githubCDNHost = "codeload.github.com"

const githubDownloadHostsNote = " Also authorizes the GitHub download hosts codeload.github.com, " +
	"release-assets.githubusercontent.com, and objects.githubusercontent.com (GET/HEAD only); " +
	"api.github.com answers tarball/asset downloads with a redirect there — redirects are not followed, " +
	"so request the Location URL explicitly."

type githubProvider struct {
	token    string
	exposure exposure.Exposure
	tables   *githubhardening.TableSource
	errOut   io.Writer
}

var (
	_ Provider         = (*githubProvider)(nil)
	_ ActionAuthorizer = (*githubProvider)(nil)
	_ ResponseAuditor  = (*githubProvider)(nil)
)

// newGithubProvider constructs the provider with a resolved exposure ceiling and
// a table source. errOut is injected by the shell.
func newGithubProvider(
	token string, exp exposure.Exposure, tables *githubhardening.TableSource,
) *githubProvider {
	return &githubProvider{
		token:    token,
		exposure: exp,
		tables:   tables,
	} //nolint:exhaustruct // errOut injected by the shell.
}

// out returns the provider's diagnostic writer, substituting [io.Discard] for a
// nil errOut (bare providers in tests) so callers never branch on nil. The
// production shell injects stderr.
func (p *githubProvider) out() io.Writer {
	if p.errOut == nil {
		return io.Discard
	}
	return p.errOut
}

func (p *githubProvider) Name() string { return githubProviderName }

func (p *githubProvider) Description() string {
	return "GitHub API authentication (via gh cli). Each request is classified to its " +
		"GitHub category/subcategory and access level and allowed only within the configured " +
		"connectors.github.permissions ceiling (read-only by default; secret-scanning blocked). " +
		"The GraphQL API (/graphql) is not supported; use the REST API. " +
		"Allows reading private GitHub repositories." + githubDownloadHostsNote
}

func (p *githubProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	req.Header.Set("Authorization", "Bearer "+p.token)
	// Strip any model-supplied version so GitHub uses its current default, which the
	// live-fetched OpenAPI spec (raw.githubusercontent.com main branch) describes.
	// This keeps the table and the wire behaviour aligned without pinning a constant.
	req.Header.Del("X-Github-Api-Version")
	return nil
}

// isGithubDownloadHost reports whether host is one of the GitHub-owned download
// hosts that api.github.com redirects tarball/asset downloads to. The transport
// never follows redirects, so the model re-requests these hosts explicitly.
// INVARIANT: every host listed here must be operated by GitHub, because
// InjectAuth attaches the gh token unconditionally — that is exactly why the
// Actions-artifact targets (numbered Azure storage accounts on shared Microsoft
// infrastructure) are NOT listed.
func isGithubDownloadHost(host string) bool {
	switch host {
	case githubCDNHost, // tarball/zipball (302 from /repos/{o}/{r}/tarball).
		"release-assets.githubusercontent.com", // release assets (302, SAS-signed).
		"objects.githubusercontent.com":        // legacy asset host, still serves some classes.
		return true
	}
	return false
}

// normalizeAuthority lower-cases a request authority and strips an optional port
// and IPv6 brackets, mirroring the form AuthorizesHost receives. The bracket trim
// is deliberately broader than transport's hostnameOnly: over-matching here only
// widens the deny-side download-host gate, never a grant.
func normalizeAuthority(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	} else {
		authority = strings.Trim(authority, "[]")
	}
	return strings.ToLower(authority)
}

func (p *githubProvider) AuthorizesHost(_ context.Context, host string, _ json.RawMessage) (bool, error) {
	return host == "api.github.com" || isGithubDownloadHost(host), nil
}

// effectiveDownloadHost returns the download host the request targets, or "" when
// it is not a download host. The Host override (when set) is the served authority
// on GitHub's shared infrastructure, so it takes precedence over the URL hostname.
// A codeload URL with a Host: api.github.com override therefore falls through to
// classification rather than taking the download fast-path.
func effectiveDownloadHost(req *http.Request) string {
	authority := normalizeAuthority(req.URL.Hostname())
	if req.Host != "" {
		authority = normalizeAuthority(req.Host) // Host override is the served authority.
	}
	if isGithubDownloadHost(authority) {
		return authority
	}
	return ""
}

// AuthorizeAction enforces the exposure ceiling. GraphQL is denied unconditionally
// (before the download-host check, so a Host: override cannot bypass it). Download
// hosts are GET/HEAD-only and table-independent; api.github.com requests are
// classified against the live table and allowed iff the configured ceiling permits
// the required level. A missing table fails closed (category table not ready). Runs before InjectAuth.
func (p *githubProvider) AuthorizeAction(ctx context.Context, req *http.Request, _ json.RawMessage) error {
	if githubhardening.IsGraphQLEndpoint(req.URL.EscapedPath()) {
		return fmt.Errorf("%w: %s %s", githubhardening.ErrGraphQLUnsupported, req.Method, req.URL.EscapedPath())
	}

	if host := effectiveDownloadHost(req); host != "" {
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			return nil
		}
		return fmt.Errorf("%w: %s %s to %s (download hosts are GET/HEAD-only)",
			githubhardening.ErrExposureExceeded, req.Method, req.URL.Path, host)
	}

	table := p.tables.Get(ctx)
	if table == nil {
		return fmt.Errorf("%w", githubhardening.ErrTableNotReady)
	}

	// A configured key matching no real category (typically a typo) is fatal —
	// under default:write a typo'd narrowing key would silently over-grant.
	if err := githubhardening.ValidateExposureKeys(p.exposure, table); err != nil {
		return err
	}

	// Use EscapedPath so a branch name like feature%2Ffoo stays as one segment and
	// matches its template (decoded "/" would split into extra segments → no match).
	access, err := githubhardening.ClassifyRequest(table, req.Method, req.URL.EscapedPath())
	if err != nil {
		return err
	}

	ceiling := githubhardening.Resolve(p.exposure, access.Route.Category, access.Route.Subcategory)
	if !exposure.Allows(ceiling, access.Level) {
		return fmt.Errorf("%w: %s %s needs %s on %q (ceiling %s)",
			githubhardening.ErrExposureExceeded, req.Method, req.URL.EscapedPath(),
			exposure.LevelName(access.Level), access.Route.Category, exposure.LevelName(ceiling))
	}
	return nil
}

// githubRateLimitURL is the read-only liveness endpoint that works for ALL gh
// token types (user, fine-grained, GitHub App installation, Actions) and is exempt
// from the primary rate limit.
//
//nolint:gochecknoglobals // constant endpoint, var for test override parity with githubUserURL.
var githubRateLimitURL = "https://api.github.com/rate_limit"

// githubStatusError carries an HTTP status so isTransientProbeErr classifies a
// 429/5xx as transient (it implements HTTPStatusCode).
type githubStatusError struct{ code int }

func (e *githubStatusError) Error() string       { return fmt.Sprintf("github status %d", e.code) }
func (e *githubStatusError) HTTPStatusCode() int { return e.code }

// doGithubUser performs GET /user over the injected client and returns the parsed
// @login on 200 (empty if the body is unparseable — a 200 still means the token is
// live), a *githubStatusError on non-200, or a wrapped transport/build error.
func doGithubUser(ctx context.Context, client *http.Client, url, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("github_hardening: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github_hardening: user probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", &githubStatusError{code: resp.StatusCode}
	}

	// parseGithubLogin (github_shell.go, shell — already covered by TestParseGithubLogin
	// in inventory_internal_test.go) returns "@login" or "" for a 200 body; a 200 with an
	// unparseable/empty login still means the token is live (identity just unknown).
	return parseGithubLogin(resp.StatusCode, resp.Body), nil
}

// doGithubRateLimit performs GET /rate_limit over the injected client: nil on 200,
// a *githubStatusError on non-200, a wrapped error on build/transport failure.
func doGithubRateLimit(ctx context.Context, client *http.Client, url, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("github_hardening: build rate_limit request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github_hardening: rate_limit probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &githubStatusError{code: resp.StatusCode}
	}

	return nil
}

// githubValidate gates github registration: GET /user is preferred (it also yields
// the @login identity), but is NOT universal — GitHub App installation / Actions
// tokens 401/403 it, and a 403 may be a rate limit. So any non-200 / transport
// error from /user falls back to the authoritative GET /rate_limit (universal +
// rate-limit-exempt). Returns the @login (empty when validated via the fallback),
// or the fallback's error (a *githubStatusError, so the caller's retryProbe retries
// transient 429/5xx).
func githubValidate(ctx context.Context, client *http.Client, userURL, rlURL, token string) (string, error) {
	login, userErr := doGithubUser(ctx, client, userURL, token)
	if userErr == nil {
		return login, nil
	}

	if rlErr := doGithubRateLimit(ctx, client, rlURL, token); rlErr != nil {
		return "", rlErr
	}

	return "", nil
}

// githubExtraForbidden are special-use IPv4/IPv6 ranges that isInternalIP
// deliberately PERMITS (private K8s clusters legitimately use CGNAT, etc.) but that
// github — which only ever dials public api.github.com — must additionally deny.
//
//nolint:gochecknoglobals // stateless, parsed-once special-use range list.
var githubExtraForbidden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 6890); 0.x is IsGlobalUnicast beyond 0.0.0.0.
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (RFC 6598).
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890).
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation TEST-NET-1 (RFC 5737).
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast, deprecated (RFC 7526).
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544).
	netip.MustParsePrefix("198.51.100.0/24"), // documentation TEST-NET-2.
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation TEST-NET-3.
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved/future (RFC 1112); IsGlobalUnicast except 255.255.255.255.
	netip.MustParsePrefix("2001:db8::/32"),   // documentation IPv6 (RFC 3849).
}

// githubDialAllowed reports whether ip is a public, globally-routable unicast
// address github may be dialed at. STRICTER than isInternalIP: it denies everything
// isInternalIP denies (floor + RFC1918 + ULA + a NAT64/6to4 IPv6 embedding an
// internal IPv4) PLUS non-global-unicast (multicast, etc.) and the special-use
// ranges in githubExtraForbidden. github has no exact-IP pin and only dials public
// api.github.com, so the strict predicate has no downside.
func githubDialAllowed(ip netip.Addr) bool {
	if isInternalIP(ip) {
		return false
	}

	u := ip.Unmap()
	if !u.IsGlobalUnicast() {
		return false
	}

	for _, p := range githubExtraForbidden {
		if p.Contains(u) {
			return false
		}
	}

	return true
}

// AuditResponse compares GitHub's authoritative required-permission header against
// our classified level and logs a one-line drift warning when read may have been
// insufficient. Advisory only; never blocks or consumes the body.
func (p *githubProvider) AuditResponse(req *http.Request, header http.Header) {
	accepted := header.Get("X-Accepted-Github-Permissions")
	if accepted == "" {
		return
	}
	level, err := githubhardening.RequiredLevel(req.Method, req.URL.EscapedPath())
	if err != nil {
		return
	}
	if msg, warn := githubhardening.DriftWarning(level, accepted); warn {
		fmt.Fprintln(p.out(), msg)
	}
}
