// Package llm adapts the embedded Bifrost SDK to the internal schema. It exposes
// BifrostChatModel, a schema.ChatModel backed by Bifrost, along with the provider
// catalog and the config plumbing for the single active provider cynative runs.
package llm

import "errors"

// Sentinel errors raised at startup by the account configuration loader.
var (
	// ErrProviderNotConfigured is returned when a requested provider name has
	// no matching entry in the configured providers map. Surfaced at startup
	// (when validating llm.provider) and at runtime (when the agent's
	// provider lookup misses).
	ErrProviderNotConfigured = errors.New("provider not found in configured providers")
	// ErrNoKeysForProvider is returned when a provider has zero keys after expansion.
	ErrNoKeysForProvider = errors.New("provider has no keys configured")
	// ErrEnvVarUnset is returned when an env.VAR reference resolves to the empty string.
	ErrEnvVarUnset = errors.New("referenced env var is empty")
	// ErrKeyConfigRequired is returned when the active provider requires a
	// per-key config block (e.g. Azure's endpoint, Vertex's project/region)
	// but a configured key omits it. Bifrost dereferences these configs
	// without a nil guard, so cynative rejects the config at load time rather
	// than letting the SDK panic at request time.
	ErrKeyConfigRequired = errors.New("provider requires a per-key config block")
	// ErrUnknownProvider is returned when llm.provider is not one of the
	// providers Bifrost supports (AllBifrostProviders). It is rejected at load
	// time because Bifrost fails to prepare an unknown provider and then its
	// chat request blocks forever instead of returning an error, deadlocking
	// the agent's event loop.
	ErrUnknownProvider = errors.New("unknown llm.provider")
)
