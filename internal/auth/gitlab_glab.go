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
		if raw.Token.Token == "" {
			return helperResult{kind: credIncompatible} //nolint:exhaustruct // malformed.
		}
		// An oauth2 credential must carry a real expiry; a zero expiry is only valid
		// for a positively non-expiring type (PAT/job), so refresh logic can trust it.
		if raw.Token.Type == "oauth2" && raw.Token.ExpiryTimestamp.IsZero() {
			return helperResult{kind: credIncompatible} //nolint:exhaustruct // malformed oauth2.
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

// glabEnvAllowlist is the exact set of parent env vars passed to the glab child.
// Everything else (LLM API keys, cloud credentials, GITLAB_TOKEN, arbitrary vars) is
// dropped so cynative's secrets never reach the first subprocess exec. The kept vars
// are what glab needs to locate its config (HOME/XDG/GLAB_CONFIG_DIR), reach the OS
// keyring (DBUS_SESSION_BUS_ADDRESS on Linux Secret Service), run (PATH), honor
// proxies, and trust custom CAs.
//
//nolint:gochecknoglobals // stateless allowlist.
var glabEnvAllowlist = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
	"GLAB_CONFIG_DIR", "DBUS_SESSION_BUS_ADDRESS", "PATH",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// glabHelperEnv curates the child env by allowlist and pins host selection.
// GITLAB_HOST is set to the resolved login host; telemetry and update checks are
// disabled so stderr stays clean and no background network call fires.
func glabHelperEnv(parent []string, loginHost string) []string {
	keep := make(map[string]bool, len(glabEnvAllowlist))
	for _, k := range glabEnvAllowlist {
		keep[k] = true
	}
	out := make([]string, 0, len(glabEnvAllowlist)+3)
	for _, kv := range parent {
		if name, _, ok := strings.Cut(kv, "="); ok && keep[name] {
			out = append(out, kv)
		}
	}
	return append(out,
		"GITLAB_HOST="+loginHost,
		"GLAB_CHECK_UPDATE=false",
		"GLAB_SEND_TELEMETRY=false",
	)
}

// glabLoginHost returns the port-stripped login host to pass as GITLAB_HOST, and
// whether the glab path applies. glab keys its credential store by the login host, so
// an api_host override whose only login host is the un-configured public default
// returns ok=false: querying gitlab.com and using that token against a private
// api_host would leak the public token. An explicit login host (self-managed) always
// applies, even paired with an api_host (intended same-instance split).
func glabLoginHost(configHost, apiHost string) (string, bool) {
	host := resolveGitLabHost(configHost)
	if apiHost != "" && stripHostPort(host) == defaultGitLabHost {
		return "", false
	}
	return stripHostPort(host), true
}

// errGitLabInstanceMismatch means glab returned a token for a different instance than
// the requested login host.
var errGitLabInstanceMismatch = errors.New(
	"gitlab: credential-helper returned a token for a different instance")

// validateInstanceURL fails closed unless instanceURL's host matches loginHost (case-
// and port-insensitive). loginHost is trusted config; instanceURL comes from glab
// stdout and is never echoed into the error.
func validateInstanceURL(instanceURL, loginHost string) error {
	u, err := url.Parse(instanceURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: unparseable instance_url", errGitLabInstanceMismatch)
	}
	if !strings.EqualFold(stripHostPort(u.Host), stripHostPort(loginHost)) {
		return fmt.Errorf("%w (expected %s)", errGitLabInstanceMismatch, loginHost)
	}
	return nil
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
