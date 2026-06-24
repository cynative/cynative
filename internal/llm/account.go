package llm

import (
	"context"
	"fmt"

	"github.com/maximhq/bifrost/core/schemas"
)

// ProviderEntry is the single active LLM provider's complete configuration.
// It embeds Bifrost's ProviderConfig directly via the json:",squash" modifier
// (so every Bifrost field is exposed under the entry without per-field
// translation) and adds the cynative-specific selectors (Provider, Model)
// plus a Keys slice (Bifrost's Account interface separates keys from config).
//
// json:",squash" is honored by mapstructure when DecoderConfig.TagName="json";
// encoding/json tolerates the unknown "squash" option, so a single tag
// suffices.
type ProviderEntry struct {
	//nolint:staticcheck // squash is a mapstructure modifier honored via TagName="json"
	schemas.ProviderConfig `json:",squash"`

	Provider string `json:"provider"`
	Model    string `json:"model"`

	// ReasoningEffort selects the reasoning effort sent with every chat
	// request ("none" | "minimal" | "low" | "medium" | "high"). Empty means no
	// reasoning parameter is sent (provider default). Validated by
	// ValidateReasoning.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// ReasoningMaxTokens caps the reasoning/thinking token budget per request.
	// Anthropic-style providers use it directly; OpenAI-style providers
	// convert it to an estimated effort. Zero means unset. Validated by
	// ValidateReasoning.
	ReasoningMaxTokens int `json:"reasoning_max_tokens,omitempty"`

	// APIKey is a top-level alias that synthesizes a single-key Keys slice
	// during config.Load's materialize step. After materialize, this field
	// is empty and downstream code reads Keys directly.
	APIKey string `json:"api_key,omitempty"`

	Keys []schemas.Key `json:"keys,omitempty"`

	// Hoisted per-provider key configs. These are cynative-side aliases that
	// expose Bifrost's keys[].*_key_config blocks at the top level with clean
	// json tags (so env names drop the "_key_config" noise, e.g.
	// CYNATIVE_LLM_AZURE_ENDPOINT). materializeLLM folds whichever is set into
	// the synthesized keys[0]; after materialize these are nil.
	Azure     *schemas.AzureKeyConfig     `json:"azure,omitempty"`
	Vertex    *schemas.VertexKeyConfig    `json:"vertex,omitempty"`
	Bedrock   *schemas.BedrockKeyConfig   `json:"bedrock,omitempty"`
	VLLM      *schemas.VLLMKeyConfig      `json:"vllm,omitempty"`
	Ollama    *schemas.OllamaKeyConfig    `json:"ollama,omitempty"`
	SGL       *schemas.SGLKeyConfig       `json:"sgl,omitempty"`
	Replicate *schemas.ReplicateKeyConfig `json:"replicate,omitempty"`
}

// FileAccount implements schemas.Account by exposing a single configured
// provider entry. The Bifrost Account interface is multi-provider; cynative
// only ever runs against one, so this implementation returns its single
// Entry from every method (and surfaces ErrProviderNotConfigured if asked
// about a different provider id).
type FileAccount struct {
	Entry ProviderEntry
}

// GetConfiguredProviders returns the single provider this account exposes.
func (a *FileAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.ModelProvider(a.Entry.Provider)}, nil
}

// GetKeysForProvider returns the configured keys for the named provider.
// Returns ErrProviderNotConfigured if p does not match the entry's Provider,
// and ErrNoKeysForProvider if the entry has no keys.
func (a *FileAccount) GetKeysForProvider(
	_ context.Context,
	p schemas.ModelProvider,
) ([]schemas.Key, error) {
	if string(p) != a.Entry.Provider {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotConfigured, p)
	}
	if len(a.Entry.Keys) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKeysForProvider, p)
	}
	return a.Entry.Keys, nil
}

// defaultRequestTimeoutSeconds is cynative's request timeout for LLM calls. It
// replaces Bifrost's 30s default, which is too short for the long,
// reasoning-heavy completions a research run makes (a single call routinely
// exceeds 30s). Overridable per-config via
// network_config.default_request_timeout_in_seconds.
const defaultRequestTimeoutSeconds = 300

// GetConfigForProvider returns the ProviderConfig for the named provider with
// cynative's and Bifrost's defaults applied. Returns ErrProviderNotConfigured
// if p does not match the entry's Provider.
func (a *FileAccount) GetConfigForProvider(
	p schemas.ModelProvider,
) (*schemas.ProviderConfig, error) {
	if string(p) != a.Entry.Provider {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotConfigured, p)
	}
	cfg := a.Entry.ProviderConfig
	// Apply cynative's request-timeout default before CheckAndSetDefaults so its
	// own <= 0 fallback (Bifrost's 30s) does not win for an unset timeout.
	if cfg.NetworkConfig.DefaultRequestTimeoutInSeconds <= 0 {
		cfg.NetworkConfig.DefaultRequestTimeoutInSeconds = defaultRequestTimeoutSeconds
	}
	cfg.CheckAndSetDefaults()
	return &cfg, nil
}
