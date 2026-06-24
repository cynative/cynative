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
