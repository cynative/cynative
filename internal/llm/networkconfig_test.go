package llm_test

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

// TestValidateNetworkConfig pins the network_config sanity checks: a negative
// llm.network_config.max_retries is rejected at load time (Bifrost's retry
// loop runs `attempts <= MaxRetries`, so a negative value would silently make
// zero provider requests), while zero (retries disabled) and positive values
// pass, as does a nil entry.
func TestValidateNetworkConfig(t *testing.T) {
	t.Parallel()

	entryWithRetries := func(n int) *llm.ProviderEntry {
		e := &llm.ProviderEntry{Provider: "openai", Model: "gpt-5"}
		e.NetworkConfig.MaxRetries = n

		return e
	}

	tests := []struct {
		name    string
		entry   *llm.ProviderEntry
		wantErr error
	}{
		{name: "nil entry is nothing to validate", entry: nil, wantErr: nil},
		{name: "zero disables retries", entry: entryWithRetries(0), wantErr: nil},
		{name: "positive is valid", entry: entryWithRetries(3), wantErr: nil},
		{name: "negative is rejected", entry: entryWithRetries(-1), wantErr: llm.ErrInvalidMaxRetries},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := llm.ValidateNetworkConfig(tc.entry)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateNetworkConfig() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
