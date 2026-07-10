package llm_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

func TestGenerateError_IsAndFields(t *testing.T) {
	t.Parallel()

	ge := &llm.GenerateError{StatusCode: http.StatusUnauthorized, Code: "invalid_api_key", Message: "bad key"}

	if !errors.Is(ge, llm.ErrGenerate) {
		t.Error("GenerateError should match ErrGenerate via errors.Is")
	}
	var as *llm.GenerateError
	if !errors.As(error(ge), &as) || as.StatusCode != http.StatusUnauthorized || as.Code != "invalid_api_key" {
		t.Errorf("errors.As lost fields: %#v", as)
	}
	if ge.Error() == "" {
		t.Error("Error() must be non-empty")
	}
}

// TestGenerateError_CredentialsExhausted pins the predicate to Bifrost's
// synthetic-502 machine type (the literal wire value, duplicated here on
// purpose so an accidental constant change fails the test) and verifies that
// ordinary provider types and an absent type do not match.
func TestGenerateError_CredentialsExhausted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  string
		want bool
	}{
		{"bifrost synthetic type matches", "upstream_credentials_exhausted", true},
		{"ordinary provider type does not match", "invalid_request_error", false},
		{"absent type does not match", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ge := &llm.GenerateError{Type: tt.typ} //nolint:exhaustruct // only Type drives the predicate.
			if got := ge.CredentialsExhausted(); got != tt.want {
				t.Errorf("CredentialsExhausted() with Type=%q = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}
