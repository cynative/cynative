package llm_test

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

// TestValidateReasoning_Valid verifies every accepted effort level and
// max-tokens combination passes validation.
func TestValidateReasoning_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		effort string
		max    int
	}{
		{"both unset", "", 0},
		{"effort none", "none", 0},
		{"effort minimal", "minimal", 0},
		{"effort low", "low", 0},
		{"effort medium", "medium", 0},
		{"effort high", "high", 0},
		{"max tokens only", "", 2048},
		{"effort and max tokens", "high", 2048},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			entry := &llm.ProviderEntry{ //nolint:exhaustruct // only fields under test
				ReasoningEffort:    tc.effort,
				ReasoningMaxTokens: tc.max,
			}
			if err := llm.ValidateReasoning(entry); err != nil {
				t.Errorf("ValidateReasoning(%q, %d) = %v, want nil", tc.effort, tc.max, err)
			}
		})
	}
}

// TestValidateReasoning_Invalid verifies each rejected configuration returns
// its sentinel error.
func TestValidateReasoning_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		effort  string
		max     int
		wantErr error
	}{
		{"junk effort", "max", 0, llm.ErrInvalidReasoningEffort},
		{"uppercase effort", "HIGH", 0, llm.ErrInvalidReasoningEffort},
		{"negative max tokens", "", -1, llm.ErrInvalidReasoningMaxTokens},
		{"none with budget", "none", 1024, llm.ErrReasoningConflict},
		{"junk effort wins over negative tokens", "max", -1, llm.ErrInvalidReasoningEffort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			entry := &llm.ProviderEntry{ //nolint:exhaustruct // only fields under test
				ReasoningEffort:    tc.effort,
				ReasoningMaxTokens: tc.max,
			}
			if err := llm.ValidateReasoning(entry); !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateReasoning(%q, %d) = %v, want %v", tc.effort, tc.max, err, tc.wantErr)
			}
		})
	}
}

// TestValidateReasoning_NilEntry verifies a nil entry is nothing to validate.
func TestValidateReasoning_NilEntry(t *testing.T) {
	t.Parallel()

	if err := llm.ValidateReasoning(nil); err != nil {
		t.Errorf("ValidateReasoning(nil) = %v, want nil", err)
	}
}
