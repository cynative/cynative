package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
