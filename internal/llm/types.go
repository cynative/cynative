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
	// chat-capable providers cynative can drive (ChatProviders). Bifrost
	// would error cleanly on the first chat request anyway; rejecting at
	// load time surfaces the misconfiguration before a run starts.
	ErrUnknownProvider = errors.New("unknown llm.provider")
)
