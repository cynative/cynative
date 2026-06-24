package llm_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	cases := []error{
		llm.ErrProviderNotConfigured,
		llm.ErrNoKeysForProvider,
		llm.ErrEnvVarUnset,
	}
	for _, e := range cases {
		if e == nil {
			t.Errorf("sentinel is nil")
			continue
		}
		wrapped := fmt.Errorf("outer: %w", e)
		if !errors.Is(wrapped, e) {
			t.Errorf("%v: errors.Is failed to unwrap", e)
		}
	}
}
