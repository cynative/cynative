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
// [Parse] is the only accessor, and it decodes exactly one key, so a gate can
// reach its own block and nothing beside it. Both fields are unexported, so
// that is the whole surface a provider in another package has.
//
// The zero value is the absent state, meaning no arguments were supplied for
// this call. Outside this package a PRESENT value can only come from
// [NewProviderArgs], so no caller can hand a gate a value that yields anything
// but one connector's block.
//
// Three states are distinguished, and the distinction is load bearing: absent
// (no block), present (the block), and invalid (the tool call could not be
// projected). Collapsing invalid into absent would turn a malformed call into a
// normal-looking one, and the self-managed Kubernetes connector's action
// validation is a deliberate no-op, so absent means allow there.
type ProviderArgs struct {
	// key is "<name>_auth". It is empty only in the zero value, because
	// NewProviderArgs always appends the suffix, so an empty key is exactly the
	// absent state and needs no separate flag.
	key string
	// toolCall is the whole tool call, projected by Parse rather than here. See
	// NewProviderArgs for why the work is deferred.
	toolCall json.RawMessage
}

// NewProviderArgs binds toolCall to the provider's own "<provider>_auth" block.
// [Parse] then decodes that block and discards every other key.
//
// provider is the matched provider's own Name(), which is what every dispatcher
// passes. Once a dispatcher has resolved who will run, deriving the key from
// that provider's identity keeps "who is being called" and "whose block they
// get" one fact instead of two. The name is lower-cased, so a provider that
// spells its own name with capitals still reaches its lower-case block.
//
// The projection is deferred to Parse so that constructing this costs nothing.
// A dispatcher builds one on every gated call, and most gates ignore their
// arguments entirely: github reads none across three gates, gitlab none across
// five (one of them per dial attempt). Extracting eagerly would scan and copy
// the whole tool call, model-authored request body included, once per gate for
// arguments nobody reads. Deferring makes those calls free and leaves the gates
// that do parse paying for exactly one scan, as they did before the narrowing.
//
// It cannot fail: a malformed tool call is surfaced by Parse, where the caller
// already has an error path. Returning it here would add a decision-free error
// arm to every dispatcher instead.
func NewProviderArgs(toolCall json.RawMessage, provider string) ProviderArgs {
	return ProviderArgs{key: strings.ToLower(provider) + argsKeySuffix, toolCall: toolCall}
}

// Parse projects the tool call down to the provider's own arguments block and
// decodes it into T. It returns (nil, nil) when the block is absent, so callers
// keep their existing "absent is not an error, but a missing required field is"
// shape, and an error when the tool call cannot be projected at all.
//
// An empty tool call is invalid rather than absent. A caller that means "no
// arguments were supplied" says so with the zero ProviderArgs; a caller that
// hands over an empty tool call gets a fail-closed error.
func Parse[T any](a ProviderArgs) (*T, error) {
	if a.key == "" {
		return nil, nil //nolint:nilnil // the zero value is the absent state; callers enforce required fields.
	}

	block, err := projectBlock(a.toolCall, a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s args: %w", a.key, err)
	}

	// An explicit null is the absent state too, matching how the tool call's own
	// arguments have always been treated.
	if block == nil || string(block) == "null" {
		return nil, nil //nolint:nilnil // absent args are not an error; callers enforce required fields.
	}

	var args T
	if err = json.Unmarshal(block, &args); err != nil {
		return nil, fmt.Errorf("failed to parse %s args: %w", a.key, err)
	}

	return &args, nil
}
