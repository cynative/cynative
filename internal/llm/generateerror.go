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

// GenerateError carries the structured, operator-renderable facts of a failed
// chat generation. StatusCode/Code come from the provider; Message is the
// human text — REDACTED at the RedactingChatModel boundary before it reaches
// any renderer (see redactmodel.go). StatusCode is 0 and Code "" when absent.
type GenerateError struct {
	StatusCode int
	Code       string
	Message    string
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
// dereferencing the optional status code and provider error code.
func newGenerateError(bErr *bschemas.BifrostError) *GenerateError {
	ge := &GenerateError{Message: bErr.GetErrorString()} //nolint:exhaustruct // status/code set below when present.
	if bErr.StatusCode != nil {
		ge.StatusCode = *bErr.StatusCode
	}
	if bErr.Error != nil && bErr.Error.Code != nil {
		ge.Code = *bErr.Error.Code
	}

	return ge
}
