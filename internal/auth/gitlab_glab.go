package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// credKind classifies a credential-helper outcome.
type credKind int

const (
	credOK               credKind = iota // a usable token was returned.
	credNotAuthenticated                 // glab ran but reports no credential (type:error).
	credIncompatible                     // non-JSON / unknown / malformed: glab too old or broken.
)

// helperResult is the classified result of one credential-helper invocation.
type helperResult struct {
	kind        credKind
	token       *oauth2.Token
	instanceURL string
	message     string // redacted advisory (glab's error message); never raw stdout.
}

// parseCredentialHelperOutput classifies glab's stdout. The binary exits 0 even on
// error, so the parsed "type" field is authoritative, never the exit code. It never
// echoes raw stdout (which carries the access token) into any result field; glab's
// error message is passed through redact before being surfaced as advisory text.
func parseCredentialHelperOutput(stdout []byte, redact func(string) string) helperResult {
	var raw struct {
		Type        string `json:"type"`
		InstanceURL string `json:"instance_url"`
		Message     string `json:"message"`
		Token       struct {
			Type            string    `json:"type"`
			Token           string    `json:"token"`
			ExpiryTimestamp time.Time `json:"expiry_timestamp"`
		} `json:"token"`
	}
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return helperResult{kind: credIncompatible} //nolint:exhaustruct // classification only.
	}
	switch raw.Type {
	case "success":
		if raw.Token.Token == "" || !glabTokenTypeOK(raw.Token.Type, raw.Token.ExpiryTimestamp.IsZero()) {
			return helperResult{kind: credIncompatible} //nolint:exhaustruct // malformed or unknown type.
		}
		return helperResult{
			kind: credOK,
			token: &oauth2.Token{ //nolint:exhaustruct // access + expiry only.
				AccessToken: raw.Token.Token,
				Expiry:      raw.Token.ExpiryTimestamp,
			},
			instanceURL: raw.InstanceURL,
		}
	case "error":
		return helperResult{kind: credNotAuthenticated, message: redact(raw.Message)} //nolint:exhaustruct // no token.
	default:
		return helperResult{kind: credIncompatible} //nolint:exhaustruct // unknown type.
	}
}

// glabTokenTypeOK reports whether glab's credential token type is one cynative accepts
// as a Bearer credential. glab emits "oauth2" (refreshable, must carry a real expiry so
// the caching source knows when to re-fetch) and "pat" (non-expiring, cached for the
// session), both of which authenticate over Authorization: Bearer. glab's "job-token"
// (CI job token) is rejected: GitLab requires job tokens over the JOB-TOKEN header, not
// Bearer, so injecting one as a bearer token would authenticate incorrectly. Any other
// type is rejected too, so an unexpected future glab type is not silently attached.
func glabTokenTypeOK(tokenType string, expiryZero bool) bool {
	switch tokenType {
	case "oauth2":
		return !expiryZero
	case "pat":
		return true
	default:
		return false
	}
}

// glabEnvAllowlist is the exact set of parent env vars passed to the glab child.
// Everything else (LLM API keys, cloud credentials, GITLAB_TOKEN, arbitrary vars) is
// dropped so cynative's secrets never reach the first subprocess exec. The kept vars
// are what glab needs to locate its config (HOME/XDG/GLAB_CONFIG_DIR on unix,
// APPDATA/LOCALAPPDATA/USERPROFILE on Windows), reach the OS keyring
// (DBUS_SESSION_BUS_ADDRESS on Linux Secret Service), run (PATH, or Path on Windows),
// honor proxies, and trust custom CAs.
//
//nolint:gochecknoglobals // stateless allowlist.
var glabEnvAllowlist = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "GLAB_CONFIG_DIR",
	"APPDATA", "LOCALAPPDATA", "USERPROFILE", // Windows: glab config lives under %AppData%.
	"DBUS_SESSION_BUS_ADDRESS", "PATH", "Path", // Path is the Windows PATH casing.
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// glabHelperEnv curates the child env by allowlist and pins host selection. GITLAB_HOST
// is set to the port-stripped login host (the credential key, which glab does not
// port-normalize); GITLAB_API_HOST is set to the served API host authority (api_host when
// set, else host, including any :port) so glab's own OAuth refresh reaches the operator's
// exact API endpoint and port in a self-managed or split login/API-host setup; telemetry
// and update checks are disabled so stderr stays clean and no background network call fires.
func glabHelperEnv(parent []string, loginHost, apiHost string) []string {
	keep := make(map[string]bool, len(glabEnvAllowlist))
	for _, k := range glabEnvAllowlist {
		keep[k] = true
	}
	injected := []string{
		"GITLAB_HOST=" + loginHost,
		"GLAB_CHECK_UPDATE=false",
		"GLAB_SEND_TELEMETRY=false",
	}
	if apiHost != "" {
		injected = append(injected, "GITLAB_API_HOST="+apiHost)
	}
	out := make([]string, 0, len(glabEnvAllowlist)+len(injected))
	for _, kv := range parent {
		if name, _, ok := strings.Cut(kv, "="); ok && keep[name] {
			out = append(out, kv)
		}
	}
	return append(out, injected...)
}

// glabLoginHost returns the port-stripped host to pass as GITLAB_HOST (the credential
// key glab authenticated). glab keys its credential store by the bare hostname (one
// credential per host, no port) and does not port-normalize GITLAB_HOST, so the port
// MUST be stripped or glab reports "not authenticated". The login host is the explicitly
// configured host; when only api_host distinguishes the instance (no explicit non-default
// login host), the api_host is used so glab is queried for the served instance's own
// credential rather than the un-configured public default (fetching the gitlab.com token
// for a private api_host would leak it). Because glab holds at most one credential per
// hostname, there is no cross-port token to confuse; the eager GET /user validation
// additionally confirms the token against the configured host:port at registration.
func glabLoginHost(configHost, apiHost string) string {
	host := stripHostPort(resolveGitLabHost(configHost))
	if host == defaultGitLabHost && apiHost != "" {
		return stripHostPort(apiHost)
	}
	return host
}

// errGitLabInstanceMismatch means glab returned a token for a different instance than
// the requested login host.
var errGitLabInstanceMismatch = errors.New(
	"gitlab: credential-helper returned a token for a different instance")

// validateInstanceURL fails closed unless instanceURL's host matches the login host or,
// for a split login/API-host setup, the configured api_host (both case- and
// port-insensitive). glab reports instance_url for the API client, which in a split
// setup is the api_host rather than the login/config key. loginHost and apiHost are
// trusted config; instanceURL comes from glab stdout and is never echoed into the error.
func validateInstanceURL(instanceURL, loginHost, apiHost string) error {
	u, err := url.Parse(instanceURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: unparseable instance_url", errGitLabInstanceMismatch)
	}
	got := stripHostPort(u.Host)
	if strings.EqualFold(got, stripHostPort(loginHost)) {
		return nil
	}
	if apiHost != "" && strings.EqualFold(got, stripHostPort(apiHost)) {
		return nil
	}
	return fmt.Errorf("%w (expected %s)", errGitLabInstanceMismatch, loginHost)
}

// glabHelperArgs is the fixed argv for the credential-helper invocation.
func glabHelperArgs() []string {
	return []string{"auth", "credential-helper"}
}

// capWriter accumulates up to max bytes and silently discards the rest, always
// reporting a full consume so a child process's pipe never blocks on a full buffer
// (the reader drains to EOF, letting cmd.Wait return cleanly).
type capWriter struct {
	max int
	buf []byte
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		take := p
		if len(take) > room {
			take = take[:room]
		}
		w.buf = append(w.buf, take...)
	}
	return len(p), nil
}

func (w *capWriter) Bytes() []byte { return w.buf }

// Token-source tuning. glabRefreshSkew re-fetches slightly before hard expiry (matches
// the connector's historical 60s skew). glabFailCooldown bounds re-exec storms when the
// helper is failing.
const (
	glabRefreshSkew  = 60 * time.Second
	glabFailCooldown = 30 * time.Second
)

// errGitLabHelperUnavailable is the terminal "no usable glab token right now" error;
// its message steers the operator to re-auth or set a PAT.
var errGitLabHelperUnavailable = errors.New(
	"gitlab: glab credential unavailable - run `glab auth login`, or set GITLAB_TOKEN to a PAT for unattended use")

// glabHelperSource is the caching oauth2.TokenSource backing a glab credential. It
// returns the cached token while valid, re-fetches via the injected helper near expiry,
// tolerates a transient helper failure by adopting a still-valid cached token
// (adopt-on-failure), and suppresses re-exec storms with a failure cooldown. A zero
// Expiry means non-expiring (PAT) and is cached for the session. Token() is
// mutex-serialized and safe for concurrent use.
type glabHelperSource struct {
	fetch func() (*oauth2.Token, error)
	now   func() time.Time

	mu       sync.Mutex
	cached   *oauth2.Token
	lastFail time.Time
}

var _ oauth2.TokenSource = (*glabHelperSource)(nil)

// newGlabHelperSource wires a caching helper source seeded with the discovered token.
func newGlabHelperSource(
	fetch func() (*oauth2.Token, error), now func() time.Time, seed *oauth2.Token,
) *glabHelperSource {
	return &glabHelperSource{fetch: fetch, now: now, cached: seed} //nolint:exhaustruct // mu/lastFail zero.
}

// Token returns the current access token, re-fetching via the helper only when the
// cached token is near expiry and no failure cooldown is active.
func (s *glabHelperSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.cached != nil && !glabNeedsRefresh(s.cached, now) {
		return s.cached, nil
	}
	if !s.lastFail.IsZero() && now.Before(s.lastFail.Add(glabFailCooldown)) {
		return s.cachedIfUsable(now)
	}

	tok, err := s.fetch()
	if err != nil {
		s.lastFail = now
		return s.cachedIfUsable(now)
	}
	s.cached = tok
	s.lastFail = time.Time{}
	return tok, nil
}

// cachedIfUsable returns the cached token when it is not hard-expired, else the
// terminal steer error.
func (s *glabHelperSource) cachedIfUsable(now time.Time) (*oauth2.Token, error) {
	if s.cached != nil && !glabHardExpired(s.cached, now) {
		return s.cached, nil
	}
	return nil, errGitLabHelperUnavailable
}

// glabNeedsRefresh reports whether tok is within the refresh skew of a real expiry. A
// zero Expiry is non-expiring and never needs refresh.
func glabNeedsRefresh(tok *oauth2.Token, now time.Time) bool {
	return !tok.Expiry.IsZero() && now.Add(glabRefreshSkew).After(tok.Expiry)
}

// glabHardExpired reports whether tok is at or past its real expiry. A zero Expiry is
// non-expiring and never hard-expired.
func glabHardExpired(tok *oauth2.Token, now time.Time) bool {
	return !tok.Expiry.IsZero() && !now.Before(tok.Expiry)
}

// tokenFromHelper parses one refresh-time helper invocation into a token, validating
// the instance. Any non-success outcome (error JSON or incompatible) is a dead session
// at refresh time and surfaces as errGitLabHelperUnavailable. Never echoes stdout.
func tokenFromHelper(
	loginHost, apiHost string,
	stdout []byte,
	execErr error,
	redact func(string) string,
) (*oauth2.Token, error) {
	if execErr != nil {
		return nil, errGitLabHelperUnavailable // non-zero exit: untrustworthy, fail closed.
	}
	res := parseCredentialHelperOutput(stdout, redact)
	if res.kind != credOK {
		return nil, errGitLabHelperUnavailable
	}
	if err := validateInstanceURL(res.instanceURL, loginHost, apiHost); err != nil {
		return nil, err
	}
	return res.token, nil
}

// glabCredential is the credential discovered from the environment or via glab. For an
// env/PAT token, Host/APIHost/Expiry/GlabPath are empty and IsOAuth2 is false. For a glab
// credential, Host is the port-stripped login host, APIHost is the served API host
// authority (may include a :port; for the refresh env and instance validation), GlabPath
// is the resolved glab binary (for re-exec), Expiry seeds the caching source, and IsOAuth2
// is true. AccessToken == "" means none found.
type glabCredential struct {
	Host        string
	APIHost     string
	AccessToken string
	Expiry      time.Time
	IsOAuth2    bool
	GlabPath    string
}

// seedToken converts a discovered credential into the initial cached token, or nil.
func seedToken(cred glabCredential) *oauth2.Token {
	if cred.AccessToken == "" {
		return nil
	}
	return &oauth2.Token{AccessToken: cred.AccessToken, Expiry: cred.Expiry} //nolint:exhaustruct // access+expiry.
}

// Discovery-time steer sentinels. All are LOUD-skip reasons gated on config presence.
var (
	errGlabMissingWithConfig = errors.New(
		"gitlab: glab not installed but a glab config exists - install glab or set GITLAB_TOKEN")
	errGlabTooOld = errors.New(
		"gitlab: installed glab is too old for the credential-helper (need v1.85.2+) - upgrade glab or set GITLAB_TOKEN",
	)
	errGlabSessionUnusable = errors.New(
		"gitlab: glab session is not usable - run `glab auth login` or set GITLAB_TOKEN")
	errGlabExecFailed = errors.New(
		"gitlab: glab credential-helper failed - set GITLAB_TOKEN for unattended use")
)

// decideGlab classifies a discovery-time helper attempt into a usable credential, a
// quiet empty credential (ambient skip), or a loud sentinel error. Loudness is gated on
// configExists (the user demonstrably uses glab). glabPath is stamped onto a usable
// credential so the source can re-exec the same binary. stderr is redacted before it
// can enter errGlabExecFailed.
func decideGlab(
	loginHost, apiHost, glabPath string,
	lookPathOK, configExists bool,
	stdout, stderr []byte,
	execErr error,
	redact func(string) string,
) (glabCredential, error) {
	if !lookPathOK {
		return loudIfConfig(configExists, errGlabMissingWithConfig)
	}
	// glab exits 0 for BOTH success and its own "not authenticated" error JSON, so a
	// non-zero exit (a crash, a timeout kill, or an unknown-command from a too-old glab)
	// means the output is untrustworthy: fail closed before parsing it for success.
	if execErr != nil {
		return loudIfConfig(configExists, fmt.Errorf("%w: %s", errGlabExecFailed, redact(string(stderr))))
	}
	res := parseCredentialHelperOutput(stdout, redact)
	if res.kind == credOK {
		if err := validateInstanceURL(res.instanceURL, loginHost, apiHost); err != nil {
			return glabCredential{}, err //nolint:exhaustruct // loud mismatch.
		}
		return glabCredential{ //nolint:exhaustruct // no refresh token held.
			Host: loginHost, APIHost: apiHost, AccessToken: res.token.AccessToken,
			Expiry: res.token.Expiry, IsOAuth2: true, GlabPath: glabPath,
		}, nil
	}
	if res.kind == credNotAuthenticated {
		return loudIfConfig(configExists, errGlabSessionUnusable)
	}
	// credIncompatible with a clean exit: glab printed help text (too old) or malformed JSON.
	return loudIfConfig(configExists, errGlabTooOld)
}

// loudIfConfig returns the loud sentinel when a glab config exists, else a quiet empty
// credential (ambient skip).
func loudIfConfig(configExists bool, loud error) (glabCredential, error) {
	if configExists {
		return glabCredential{}, loud //nolint:exhaustruct // loud skip.
	}
	return glabCredential{}, nil //nolint:exhaustruct // quiet ambient skip.
}
