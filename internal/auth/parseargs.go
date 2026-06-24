package auth

import (
	"encoding/json"
	"fmt"
)

// parseAuthArgs extracts the typed provider args nested under key (e.g.
// "eks_auth") from the raw tool arguments. It returns (nil, nil) when the key
// is absent or explicitly null — matching the struct-unmarshal convention the
// per-provider parsers used — and an error only when the JSON is malformed or
// the nested value is not an object of type T.
func parseAuthArgs[T any](raw json.RawMessage, key string) (*T, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse %s args: %w", key, err)
	}

	sub, ok := fields[key]
	if !ok || string(sub) == "null" {
		return nil, nil //nolint:nilnil // absent/null key is not an error; matches the per-provider parser convention.
	}

	var args T
	if err := json.Unmarshal(sub, &args); err != nil {
		return nil, fmt.Errorf("failed to parse %s args: %w", key, err)
	}

	return &args, nil
}
