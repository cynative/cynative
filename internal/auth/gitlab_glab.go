package auth

import (
	"encoding/json"
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
