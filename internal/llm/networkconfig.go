package llm

import (
	"errors"
	"fmt"
)

// ErrInvalidMaxRetries is returned when llm.network_config.max_retries is
// negative. Bifrost's retry loop runs `attempts <= MaxRetries`, so a negative
// value would silently make zero provider requests; 0 (retries disabled) is
// the smallest valid setting.
var ErrInvalidMaxRetries = errors.New("invalid llm.network_config.max_retries")

// ValidateNetworkConfig rejects an invalid llm.network_config at load time,
// before the request path could send it. A nil entry is treated as nothing to
// validate.
func ValidateNetworkConfig(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	if entry.NetworkConfig.MaxRetries < 0 {
		return fmt.Errorf(
			"%w: %d; llm.network_config.max_retries (CYNATIVE_LLM_NETWORK_CONFIG_MAX_RETRIES) must be 0"+
				" (retries disabled) or a positive retry count",
			ErrInvalidMaxRetries, entry.NetworkConfig.MaxRetries,
		)
	}

	return nil
}
