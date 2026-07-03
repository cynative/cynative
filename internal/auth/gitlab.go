package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/cache"

	"golang.org/x/oauth2"
)

// defaultGitLabHost is the public GitLab SaaS instance used when no host is
// configured.
const defaultGitLabHost = "gitlab.com"

// errGitLabProbe wraps a failed GitLab API probe — the eager /user validation
// (a transport, status, or parse error). It fails closed: registration treats it
// as a token-validation failure.
var errGitLabProbe = errors.New("gitlab API probe failed")

// resolveGitLabHost returns the configured host or the gitlab.com default.
func resolveGitLabHost(configHost string) string {
	if configHost == "" {
		return defaultGitLabHost
	}
	return configHost
}

// gitlabEnvToken returns the first non-empty token environment variable in glab's
// documented precedence — GITLAB_TOKEN, then GITLAB_ACCESS_TOKEN, then OAUTH_TOKEN
// — or "" when none is set. lookup is injected (the shell passes [os.LookupEnv])
// so the precedence logic stays pure and testable.
func gitlabEnvToken(lookup func(string) (string, bool)) string {
	for _, name := range []string{"GITLAB_TOKEN", "GITLAB_ACCESS_TOKEN", "OAUTH_TOKEN"} {
		if v, ok := lookup(name); ok && v != "" {
			return v
		}
	}

	return ""
}

// glabConfigPaths returns the candidate glab config.yml paths in glab's search
// order. GLAB_CONFIG_DIR is an exclusive override: when set, glab uses only that
// directory and does not fall back, so this returns that single path. Otherwise it
// returns the legacy ~/.config/glab-cli first (glab checks it before XDG for
// backward compatibility), then $XDG_CONFIG_HOME/glab-cli, then
// [os.UserConfigDir]/glab-cli — glab resolves the user-config dir via adrg/xdg,
// whose ConfigHome equals [os.UserConfigDir] on macOS (~/Library/Application
// Support), Linux ($XDG_CONFIG_HOME or ~/.config), and Windows (%AppData%). That
// macOS/Windows default is the candidate cynative previously missed; on Linux it
// overlaps the legacy ~/.config entry harmlessly. The shell (glabConfigExists) stats
// the first that exists as a presence signal. Pure: callers do the env/home/file I/O.
func glabConfigPaths(glabConfigDir, xdgConfigHome, userConfigDir, homeDir string) []string {
	if glabConfigDir != "" {
		return []string{filepath.Join(glabConfigDir, "config.yml")}
	}

	var paths []string
	if homeDir != "" {
		paths = append(paths, filepath.Join(homeDir, ".config", "glab-cli", "config.yml"))
	}
	if xdgConfigHome != "" {
		paths = append(paths, filepath.Join(xdgConfigHome, "glab-cli", "config.yml"))
	}
	if userConfigDir != "" {
		paths = append(paths, filepath.Join(userConfigDir, "glab-cli", "config.yml"))
	}

	return paths
}

// parseGitLabUser returns the authenticating user's username from a GET
// /api/v4/user response. It fails closed unless "username" is a present non-empty
// string, so an error/empty JSON cannot validate as an anonymous identity.
func parseGitLabUser(raw []byte) (string, error) {
	var resp struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("%w: invalid /user JSON: %w", errGitLabProbe, err)
	}
	if resp.Username == "" {
		return "", fmt.Errorf("%w: /user response has no username", errGitLabProbe)
	}

	return resp.Username, nil
}

// gitlabIdentity renders the startup-inventory identity: the validated @username,
// and — for a self-managed instance (served host other than gitlab.com) — the
// served host too, so the operator sees which instance was reached. Falls back to
// the served host when the username could not be determined.
func gitlabIdentity(username, servedHost string) string {
	if username == "" {
		return servedHost
	}
	id := "@" + username
	if stripHostPort(servedHost) != defaultGitLabHost {
		id += " · " + servedHost
	}

	return id
}

const gitlabProviderName = "gitlab"

// gitlabProvider is the auth.Provider for GitLab (gitlab.com and self-managed).
// It classifies each request to its GitLab category and required access level and
// allows it only within the configured per-category exposure ceiling (read-only
// by default; ci-variables blocked). It pins to the configured host at the dial
// layer. Implements Provider, ActionAuthorizer, AddrAuthorizer, and
// CACertProvider.
type gitlabProvider struct {
	tokenSource         oauth2.TokenSource // static for env/PAT; caching glab-helper source for a glab credential.
	host                string
	apiHost             string
	allowPrivateNetwork bool
	caData              string // base64 PEM; "" = system roots.
	exposure            exposure.Exposure
	tables              *cache.TTLCache[gitlabclass.Table]
	resolver            addrResolver
}

var (
	_ Provider         = (*gitlabProvider)(nil)
	_ ActionAuthorizer = (*gitlabProvider)(nil)
	_ AddrAuthorizer   = (*gitlabProvider)(nil)
	_ CACertProvider   = (*gitlabProvider)(nil)
)

// Name returns the provider's canonical name used as the auth_provider value.
func (p *gitlabProvider) Name() string { return gitlabProviderName }

// servedHostOf returns apiHost when non-empty, else host. It is the free-function
// form of servedHost, usable before a gitlabProvider is built (e.g. to discover
// the token against the host requests actually go to).
func servedHostOf(host, apiHost string) string {
	if apiHost != "" {
		return apiHost
	}

	return host
}

// servedHost returns the API host override when set, else the primary host.
// It may include a :port suffix (self-managed GitLab on a non-443 port); it is
// the value interpolated into the probe URL, so the port is preserved.
func (p *gitlabProvider) servedHost() string {
	return servedHostOf(p.host, p.apiHost)
}

// stripHostPort returns host with any :port suffix removed; a host with no port
// is returned unchanged.
func stripHostPort(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return hostname
	}
	return host
}

// portOfAuthority returns the explicit port of a host[:port] authority, or "443"
// (the https default) when none is present.
func portOfAuthority(authority string) string {
	if _, port, err := net.SplitHostPort(authority); err == nil {
		return port
	}
	return "443"
}

// servedHostname returns servedHost with any :port suffix stripped. The
// transport compares a port-stripped host in AuthorizesHost, and the resolver
// requires a bare hostname, so both use this rather than servedHost.
func (p *gitlabProvider) servedHostname() string {
	return stripHostPort(p.servedHost())
}

// expectedPort returns the port the connector is configured to serve on: the
// explicit :port from servedHost, or "443" (the https default) when none is set.
func (p *gitlabProvider) expectedPort() string {
	return portOfAuthority(p.servedHost())
}

// authorizeRequestPort rejects a request whose port differs from the connector's
// configured (or default-443) port. AuthorizesHost only sees the port-stripped
// hostname (the transport passes req.URL.Hostname() and pins only the hostname of
// a Host override), so without this gate a model could target a different TLS port
// on the pinned host/IP — or send a mismatched Host-override authority — and have
// the injected Bearer token attached under an unpinned port.
func (p *gitlabProvider) authorizeRequestPort(req *http.Request) error {
	want := p.expectedPort()
	if got := portOfAuthority(req.URL.Host); got != want {
		return fmt.Errorf("%w: request port %s does not match configured GitLab port %s (provider gitlab)",
			ErrHostNotAuthorized, got, want)
	}
	// A model-supplied Host header overrides the request authority; the transport
	// pins only its hostname, so pin its port here too.
	if req.Host != "" && req.Host != req.URL.Host {
		if got := portOfAuthority(req.Host); got != want {
			return fmt.Errorf("%w: Host override port %s does not match configured GitLab port %s (provider gitlab)",
				ErrHostNotAuthorized, got, want)
		}
	}
	return nil
}

// Description returns a human-readable description of the provider's posture. It
// names the served host so the model knows the exact base URL to call (e.g. a
// self-managed instance) rather than defaulting to gitlab.com.
func (p *gitlabProvider) Description() string {
	return fmt.Sprintf("GitLab API authentication for https://%s (via GITLAB_TOKEN or glab config). "+
		"Each request is classified to its GitLab category and access level and allowed only within "+
		"the configured connectors.gitlab.permissions ceiling (read-only by default; ci-variables blocked). "+
		"The GraphQL API (/api/graphql) is not supported; use the REST API. Allows reading "+
		"GitLab projects, issues, merge requests, and other resources.", p.servedHost())
}

// InjectAuth resolves the current access token (via glab's credential-helper for a
// glab OAuth credential) and sets Authorization: Bearer. Bearer authenticates
// PAT/project/group AND OAuth tokens. A token-resolution failure fails closed:
// the token is never attached.
func (p *gitlabProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	accessToken, err := p.currentToken()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return nil
}

// currentToken resolves the current access token through the token source. Shared
// by InjectAuth, the eager /user validation, and the lazy scope probe so all carry a
// freshly-resolved token. A genuinely dead glab session surfaces here as
// errGitLabHelperUnavailable (a transient helper failure does NOT surface here - the
// source adopts a still-valid cached token).
func (p *gitlabProvider) currentToken() (string, error) {
	tok, err := p.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("gitlab: resolve access token: %w", err)
	}

	return tok.AccessToken, nil
}

// AuthorizesHost reports whether host is the provider's served host. The
// transport passes a port-stripped, lower-cased host, so the comparison is
// against the port-stripped served hostname and is case-insensitive.
func (p *gitlabProvider) AuthorizesHost(_ context.Context, host string, _ json.RawMessage) (bool, error) {
	return host == strings.ToLower(p.servedHostname()), nil
}

// CACertData returns the base64-encoded PEM CA certificate for the provider's
// host, or "" when system roots should be used.
func (p *gitlabProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caData, nil
}

// errGitLabSudoBlocked is returned when a request carries a model-supplied GitLab
// sudo impersonation control. The model must never act as another user.
var errGitLabSudoBlocked = errors.New(
	"gitlab_hardening: model-supplied sudo impersonation is not permitted")

// rejectGitLabSmuggledControls fails closed when the request carries a
// model-supplied GitLab control the connector must own and the central denylist
// does not cover: a sudo impersonation directive (the "sudo" query parameter or
// "Sudo" header — admin-token impersonation, blocked regardless of exposure),
// or the "token" query parameter that GitLab's pipeline-trigger endpoints
// authenticate with (a smuggled credential alongside the injected Bearer).
func rejectGitLabSmuggledControls(req *http.Request) error {
	// Parse RawQuery explicitly and fail closed on error: req.URL.Query() silently
	// drops pairs on a ";"-separated query that GitLab/Rack still honors, which
	// would hide a smuggled sudo/token parameter.
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: unparseable URL query (provider gitlab): %w", ErrModelSuppliedCredential, err)
	}
	for key := range params {
		switch base := baseParamName(key); {
		case strings.EqualFold(base, "sudo"):
			return fmt.Errorf("%w (sudo query parameter)", errGitLabSudoBlocked)
		case strings.EqualFold(base, "token"):
			return fmt.Errorf("%w: token query parameter present (provider gitlab)", ErrModelSuppliedCredential)
		}
	}
	for key := range req.Header {
		if strings.EqualFold(key, "Sudo") {
			return fmt.Errorf("%w (Sudo header)", errGitLabSudoBlocked)
		}
	}

	return nil
}

// gitlabBodyCredentialParams are the request-parameter names GitLab's AuthFinders
// reads as credentials from params — which Rails populates from the query string
// AND a parsed urlencoded/multipart/JSON body: the pipeline-trigger / runner
// "token", the OAuth "access_token", the "private_token", and the CI "job_token".
// A model-supplied value for any of these in the body is smuggled credential
// material and fails closed.
//
//nolint:gochecknoglobals // stateless credential-name list.
var gitlabBodyCredentialParams = []string{"token", "private_token", "access_token", "job_token"}

// multipartFoldRe matches an RFC822 header continuation (a CR?LF followed by
// leading whitespace), used to unfold a multipart Content-Disposition split across
// lines before scanning it.
var multipartFoldRe = regexp.MustCompile(`\r?\n[ \t]+`)

// isGitLabCredentialParam reports whether name (case-insensitively, ignoring a
// Rack-style bracket suffix) is one of the GitLab request-parameter credential
// names — so "private_token[]" matches like "private_token".
func isGitLabCredentialParam(name string) bool {
	name = baseParamName(name)
	for _, c := range gitlabBodyCredentialParams {
		if strings.EqualFold(name, c) {
			return true
		}
	}

	return false
}

// rejectGitLabBodyCredential fails closed when the request body carries a GitLab
// credential parameter (see gitlabBodyCredentialParams). GitLab/Rails reads these
// from a urlencoded, multipart, OR JSON body, so all three encodings are
// inspected. It runs regardless of the exposure ceiling, so it applies to reads
// and writes alike. Supplying a literal credential field (e.g. a webhook secret
// named "token") in a write body is unsupported by design; see
// docs/connectors/gitlab.md.
func rejectGitLabBodyCredential(body string) error {
	if body != "" && bodyCarriesCredential(body) {
		return fmt.Errorf("%w: credential parameter in request body (provider gitlab)", ErrModelSuppliedCredential)
	}

	return nil
}

// bodyCarriesCredential reports whether body carries a GitLab credential parameter
// in any encoding GitLab reads into params. A valid JSON value is checked
// structurally (only a top-level object key counts — arrays/scalars carry no
// params credential); any other body is treated as a form body (urlencoded,
// lenient on ';'; or multipart).
func bodyCarriesCredential(body string) bool {
	var jsonVal any
	if json.Unmarshal([]byte(body), &jsonVal) == nil {
		obj, ok := jsonVal.(map[string]any)

		return ok && objectHasCredentialKey(obj)
	}

	return bodyFormHasCredential(body) || bodyMultipartHasCredential(body)
}

// objectHasCredentialKey reports whether obj has a top-level credential key
// (case-insensitive).
func objectHasCredentialKey(obj map[string]any) bool {
	for key := range obj {
		if isGitLabCredentialParam(key) {
			return true
		}
	}

	return false
}

// bodyFormHasCredential reports whether a urlencoded body has a credential field.
// It splits on '&' AND ';' because GitLab/Rack honors ';' as a separator that Go's
// [url.ParseQuery] rejects, so "token=x;ref=y" cannot evade detection.
func bodyFormHasCredential(body string) bool {
	for _, pair := range strings.FieldsFunc(body, func(r rune) bool { return r == '&' || r == ';' }) {
		key, _, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(strings.TrimSpace(key)); err == nil && isGitLabCredentialParam(k) {
			return true
		}
	}

	return false
}

// bodyMultipartHasCredential reports whether body contains a multipart/form-data
// part whose field name is a credential parameter, matching the
// Content-Disposition header curl emits for `--form name=value`. It parses each
// Content-Disposition line with [mime.ParseMediaType] so quoting/parameter order
// do not matter, and scans the raw body rather than trusting the model-supplied
// Content-Type boundary, so a mangled/absent Content-Type cannot evade it.
func bodyMultipartHasCredential(body string) bool {
	// Unfold RFC822 header continuations first (a newline followed by leading
	// whitespace continues the prior line), which Rack's multipart parser does, so a
	// `Content-Disposition: form-data;\r\n name="token"` split across lines is read
	// whole rather than seeing only the first line and missing the name.
	body = multipartFoldRe.ReplaceAllString(body, " ")

	const prefix = "content-disposition:"
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), prefix) {
			continue
		}
		if _, params, err := mime.ParseMediaType(line[len(prefix):]); err == nil {
			if isGitLabCredentialParam(params["name"]) {
				return true
			}
		}
	}

	return false
}

// AuthorizeAction enforces the per-category exposure ceiling. It rejects smuggled
// controls and a port/Host-override mismatch, denies the GraphQL endpoint
// unconditionally, rejects a smuggled body credential, then classifies the
// request to its GitLab category and required level and allows it only when the
// configured ceiling permits that level. A request that cannot be classified (any
// non-/api/v4 path fails closed here), a missing table, an unknown configured key,
// or an exceeded ceiling all fail closed. Runs before InjectAuth.
func (p *gitlabProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	if err := rejectGitLabSmuggledControls(req); err != nil {
		return err
	}
	if err := p.authorizeRequestPort(req); err != nil {
		return err
	}
	if gitlabclass.IsGraphQLEndpoint(req.URL.EscapedPath()) {
		return fmt.Errorf("%w: %s", gitlabclass.ErrGraphQLUnsupported, req.URL.EscapedPath())
	}
	var parsed struct {
		Body string `json:"body"`
	}
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &parsed); err != nil {
			return fmt.Errorf("failed to parse http_request args for classification: %w", err)
		}
	}
	if err := rejectGitLabBodyCredential(parsed.Body); err != nil {
		return err
	}

	table := p.tables.Get(ctx)
	if table == nil {
		return fmt.Errorf("%w", gitlabclass.ErrTableNotReady)
	}
	// A configured key matching no real category (typically a typo) is fatal —
	// under default:write a typo'd narrowing key would silently over-grant.
	if err := gitlabclass.ValidateExposureKeys(p.exposure, table); err != nil {
		return err
	}

	// Classify on the ESCAPED path: req.URL.Path is percent-decoded, so a write to
	// a repository-files path whose encoded segment decodes to end with a
	// read-only endpoint (e.g. .../files/x%2Fapi%2Fv4%2Fmarkdown) would otherwise
	// forge the read suffix; EscapedPath keeps %2F encoded so only real endpoints
	// match. The variables→ci-variables override lives at distill-time (over the
	// trusted spec template), so a "variables" value in a path PARAMETER does not
	// inherit the sensitive ceiling here.
	escaped := req.URL.EscapedPath()
	access, cerr := gitlabclass.ClassifyRequest(table, req.Method, escaped)
	if cerr != nil {
		return cerr
	}
	category := access.Category
	ceiling := gitlabclass.Resolve(p.exposure, category)
	if !exposure.Allows(ceiling, access.Level) {
		return fmt.Errorf("%w: %s %s needs %s on %q (ceiling %s)",
			gitlabclass.ErrExposureExceeded, req.Method, escaped,
			exposure.LevelName(access.Level), category, exposure.LevelName(ceiling))
	}
	return nil
}

// authorizesDialIP reports whether ip may be dialed for the provider's served
// host. When allowPrivateNetwork is false (the default) it denies all internal
// IPs (RFC1918, loopback, link-local, ULA, cloud metadata). When
// allowPrivateNetwork is true it still denies the unconditional floor (loopback,
// link-local, metadata, AND all ULA IPv6 fc00::/7). In both cases it then
// fresh-resolves the served host and pins the dial to the resolved IP set. Fails
// closed on a resolve error.
//
// The opt-in deliberately does NOT re-permit ULA IPv6: every cloud parks its IPv6
// metadata service in ULA space, and the exact-IP pin below is not a rebind
// defense (a DNS rebind moves the dial resolution and this re-resolution in
// lockstep, so contains() would still match a rebound metadata address). The
// floor is the rebind defense; relaxing it for ULA would re-expose IPv6 metadata.
// A self-managed instance must therefore be reached over RFC1918 IPv4 or
// global-unicast IPv6 (documented in docs/connectors/gitlab.md).
func (p *gitlabProvider) authorizesDialIP(ctx context.Context, ip netip.Addr) (bool, error) {
	if p.allowPrivateNetwork {
		if floorForbidden(ip) {
			return false, nil
		}
	} else if isInternalIP(ip) {
		return false, nil
	}
	addrs, err := p.resolver(ctx, p.servedHostname())
	if err != nil {
		return false, fmt.Errorf("gitlab: resolve %q: %w", p.servedHostname(), err)
	}
	return contains(addrs, ip), nil
}

// AuthorizesAddr implements AddrAuthorizer by delegating to authorizesDialIP.
func (p *gitlabProvider) AuthorizesAddr(ctx context.Context, ip netip.Addr, _ json.RawMessage) (bool, error) {
	return p.authorizesDialIP(ctx, ip)
}
