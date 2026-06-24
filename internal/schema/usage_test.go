package schema_test

import (
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

func TestUsage_ZeroValue(t *testing.T) {
	t.Parallel()

	var u schema.Usage
	if u.PromptTokens != 0 || u.CompletionTokens != 0 || u.TotalTokens != 0 {
		t.Errorf("zero Usage has non-zero tokens: %+v", u)
	}
	if u.CachedReadTokens != 0 || u.CachedWriteTokens != 0 {
		t.Errorf("zero Usage has non-zero cache tokens: %+v", u)
	}
}

func TestUsage_PopulatedFields(t *testing.T) {
	t.Parallel()

	u := schema.Usage{
		PromptTokens:      100,
		CompletionTokens:  20,
		TotalTokens:       120,
		CachedReadTokens:  80,
		CachedWriteTokens: 5,
	}
	if u.PromptTokens != 100 || u.CompletionTokens != 20 || u.TotalTokens != 120 ||
		u.CachedReadTokens != 80 || u.CachedWriteTokens != 5 {
		t.Errorf("fields not stored: %+v", u)
	}
}
