package authreq

import (
	"encoding/json"
	"fmt"
	"strings"
)

// argsKeySuffix is the suffix every connector's tool-call arguments key carries,
// so the key is derived from the provider name rather than a hand-kept table.
const argsKeySuffix = "_auth"

// ProviderArgs is the narrowed, read-only projection of the model's tool call
// handed to a provider: that provider's own "<name>_auth" block and nothing
// else. It exists so a gate cannot take a second, un-narrowed view of the
// request alongside [View].
//
// The zero value is the absent state, meaning no arguments were supplied for
// this call. Outside this package a PRESENT value can only come from
// [NewProviderArgs], which extracts a single key, so no caller can hand a gate
// the whole tool call.
//
// Three states are distinguished, and the distinction is load bearing: absent
// (no block), present (the block), and invalid (the tool call could not be
// projected). Collapsing invalid into absent would turn a malformed call into a
// normal-looking one, and the self-managed Kubernetes connector's action
// validation is a deliberate no-op, so absent means allow there.
type ProviderArgs struct {
	key   string          // "<name>_auth"; retained so Parse can name it in errors.
	block json.RawMessage // nil when the key is absent or explicitly null.
	err   error           // non-nil when toolCall could not be projected.
}

// NewProviderArgs projects toolCall down to provider's own "<provider>_auth"
// block, discarding every other key.
//
// provider is the matched provider's own Name(), which is what every dispatcher
// passes. Once a dispatcher has resolved who will run, deriving the key from
// that provider's identity keeps "who is being called" and "whose block they
// get" one fact instead of two. The name is lower-cased, so a provider that
// spells its own name with capitals still reaches its lower-case block.
//
// It cannot fail: a projection error is carried and surfaced by [Parse], where
// the caller already has an error path. Returning it here would add a
// decision-free error arm to every dispatcher instead.
//
// An empty toolCall is invalid rather than absent. A caller that means "no
// arguments were supplied" says so with the zero ProviderArgs; a caller handing
// over an empty tool call gets a fail-closed error.
func NewProviderArgs(toolCall json.RawMessage, provider string) ProviderArgs {
	key := strings.ToLower(provider) + argsKeySuffix

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(toolCall, &fields); err != nil {
		return ProviderArgs{key: key, block: nil, err: fmt.Errorf("failed to parse %s args: %w", key, err)}
	}

	// A top-level null decodes into a nil map, which reads as "key absent" and
	// matches how the tool call's own arguments have always been treated.
	block, ok := fields[key]
	if !ok || string(block) == "null" {
		return ProviderArgs{key: key, block: nil, err: nil}
	}

	return ProviderArgs{key: key, block: block, err: nil}
}

// Parse decodes the provider's own arguments block into T. It returns
// (nil, nil) when the block is absent, so callers keep their existing "absent is
// not an error, but a missing required field is" shape, and it returns the
// carried projection error when the tool call could not be projected at all.
func Parse[T any](a ProviderArgs) (*T, error) {
	if a.err != nil {
		return nil, a.err
	}

	if len(a.block) == 0 {
		return nil, nil //nolint:nilnil // absent args are not an error; callers enforce required fields.
	}

	var args T
	if err := json.Unmarshal(a.block, &args); err != nil {
		return nil, fmt.Errorf("failed to parse %s args: %w", a.key, err)
	}

	return &args, nil
}
