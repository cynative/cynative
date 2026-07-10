package llm

import (
	"errors"
	"fmt"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// ErrGenerate is the sentinel every chat-generation failure wraps, so callers
// can identify an LLM/transport failure (vs. an audit/interrupt/budget error)
// with [errors.Is] and reframe it into the operator-facing LLM status block.
var ErrGenerate = errors.New("llm generate failed")

// credentialsExhaustedType is the Type Bifrost stamps on the synthetic 502 it
// returns when every configured key failed with a permanent per-key error
// (401/402/403) inside its retry loop: the key is marked dead, the next
// attempt's key selection finds no live key, and the original status code is
// discarded. Hand-pinned string literal (Bifrost exports no constant for it);
// re-check executeRequestWithRetries in bifrost core on every Bifrost bump.
const credentialsExhaustedType = "upstream_credentials_exhausted" //nolint:gosec // machine error-type label, not a credential.

// GenerateError carries the structured, operator-renderable facts of a failed
// chat generation. StatusCode/Code/Type come from the provider (or, for a
// synthetic failure, from Bifrost itself); Message is the human text, REDACTED
// at the RedactingChatModel boundary before it reaches any renderer (see
// redactmodel.go). StatusCode is 0 and Code/Type "" when absent.
type GenerateError struct {
	StatusCode int
	Code       string
	Type       string
	Message    string
}

// CredentialsExhausted reports whether this failure is Bifrost's synthetic 502
// for "every configured key was rejected with a permanent 401/402/403". With
// retries enabled that collapse hides the original status, so status renderers
// use this predicate (an equality match on the machine Type, never provider
// text) to keep the credential/billing guidance a raw 401/402/403 would get.
// The type can also arrive parsed verbatim from an upstream body when base_url
// points at a Bifrost-based gateway whose own upstream keys died; there is no
// provenance signal to tell the two apart, so callers should word guidance to
// cover both (the dead credential may be the gateway's, not the operator's).
func (e *GenerateError) CredentialsExhausted() bool {
	return e.Type == credentialsExhaustedType
}

// Error renders the failure for logs/%v. Message is already redacted by the
// time any caller can observe it (RedactingChatModel wraps every agent call).
func (e *GenerateError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("llm generate (HTTP %d): %s", e.StatusCode, e.Message)
	}

	return "llm generate: " + e.Message
}

// Unwrap ties GenerateError to the ErrGenerate sentinel for [errors.Is].
func (e *GenerateError) Unwrap() error { return ErrGenerate }

// newGenerateError builds a *GenerateError from a Bifrost error, nil-safely
// dereferencing the optional status code, provider error code, and error type
// (the nested field first, then the top-level one Bifrost also stamps on its
// synthetic errors).
func newGenerateError(bErr *bschemas.BifrostError) *GenerateError {
	ge := &GenerateError{Message: bErr.GetErrorString()} //nolint:exhaustruct // fields set below when present.
	if bErr.StatusCode != nil {
		ge.StatusCode = *bErr.StatusCode
	}
	if bErr.Error != nil && bErr.Error.Code != nil {
		ge.Code = *bErr.Error.Code
	}
	switch {
	case bErr.Error != nil && bErr.Error.Type != nil:
		ge.Type = *bErr.Error.Type
	case bErr.Type != nil:
		ge.Type = *bErr.Type
	}

	return ge
}
