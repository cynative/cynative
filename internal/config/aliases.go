package config

import (
	"errors"
	"fmt"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// ErrAliasConflict is returned when an alias on llm.ProviderEntry (e.g.
// llm.api_key) is set at the same time as its nested equivalent
// (e.g. llm.keys). Pick one, not both.
var ErrAliasConflict = errors.New("alias conflicts with nested value")

// materializeLLM folds the cynative-side aliases on ProviderEntry into the
// squashed Bifrost fields. After materialize, the alias fields are zeroed
// and downstream code reads only the Bifrost structures. env resolves the
// api_key "env.X" form and the canonical-env fallback.
func materializeLLM(entry *llm.ProviderEntry, env llm.LookupEnv) {
	materializeKey(entry, env)
}

// materializeKey synthesizes keys[0] from the api_key alias, the canonical-env
// fallback, and/or any hoisted per-provider key config, then clears those
// aliases. Explicit keys[] (validated by detectAliasConflicts to be mutually
// exclusive with the aliases) are left untouched.
func materializeKey(entry *llm.ProviderEntry, env llm.LookupEnv) {
	value, hasValue := keyValueForEntry(entry, env)

	if len(entry.Keys) == 0 && (hasValue || anyHoistedKeyConfig(entry)) {
		key := schemas.Key{ //nolint:exhaustruct // optional Bifrost key fields intentionally omitted
			Value:  value,
			Models: schemas.WhiteList{"*"},
			Weight: 1.0,
		}
		applyHoistedKeyConfigs(entry, &key)
		entry.Keys = []schemas.Key{key}
	}

	entry.APIKey = ""
	clearHoistedKeyConfigs(entry)
}

// keyValueForEntry resolves the synthesized key's Value: the api_key alias if
// set, else the provider's canonical env var when no keys are configured. The
// bool is false when no value source applies (e.g. Bedrock's AWS chain).
func keyValueForEntry(entry *llm.ProviderEntry, env llm.LookupEnv) (schemas.EnvVar, bool) {
	if entry.APIKey != "" {
		// Route through ResolveEnvVar so an "env.X" value resolves the variable
		// through env (FromEnv=true); a literal passes through unchanged. This
		// matches keys[].value and lets ValidateEnvVars surface an unset
		// reference as a clean load-time error.
		return llm.ResolveEnvVar(entry.APIKey, env), true
	}
	if len(entry.Keys) == 0 {
		if envName, ok := llm.CanonicalEnvKey(schemas.ModelProvider(entry.Provider)); ok {
			if val, found := env(envName); found && val != "" {
				return schemas.EnvVar{Val: val, FromEnv: true, EnvVar: envName}, true
			}
		}
	}

	return schemas.EnvVar{Val: "", FromEnv: false, EnvVar: ""}, false
}

// anyHoistedKeyConfig reports whether any hoisted per-provider key config is set.
func anyHoistedKeyConfig(entry *llm.ProviderEntry) bool {
	return entry.Azure != nil || entry.Vertex != nil || entry.Bedrock != nil ||
		entry.VLLM != nil || entry.Ollama != nil || entry.SGL != nil || entry.Replicate != nil
}

// applyHoistedKeyConfigs copies the hoisted key configs onto key. Absent ones
// are nil, matching the field's zero value.
func applyHoistedKeyConfigs(entry *llm.ProviderEntry, key *schemas.Key) {
	key.AzureKeyConfig = entry.Azure
	key.VertexKeyConfig = entry.Vertex
	key.BedrockKeyConfig = entry.Bedrock
	key.VLLMKeyConfig = entry.VLLM
	key.OllamaKeyConfig = entry.Ollama
	key.SGLKeyConfig = entry.SGL
	key.ReplicateKeyConfig = entry.Replicate
}

// clearHoistedKeyConfigs zeroes the hoisted aliases after they have been folded.
func clearHoistedKeyConfigs(entry *llm.ProviderEntry) {
	entry.Azure = nil
	entry.Vertex = nil
	entry.Bedrock = nil
	entry.VLLM = nil
	entry.Ollama = nil
	entry.SGL = nil
	entry.Replicate = nil
}

// detectAliasConflicts returns ErrAliasConflict if any alias on entry is set
// at the same time as its nested equivalent. Each alias check is independent
// and lists the offending pair in the error message.
func detectAliasConflicts(entry *llm.ProviderEntry) error {
	if entry.APIKey != "" && len(entry.Keys) > 0 {
		return fmt.Errorf("%w: llm.api_key and llm.keys are both set — pick one", ErrAliasConflict)
	}
	if len(entry.Keys) > 0 && anyHoistedKeyConfig(entry) {
		return fmt.Errorf(
			"%w: a provider key-config alias (llm.azure/llm.vertex/...) and llm.keys are both set — pick one",
			ErrAliasConflict,
		)
	}
	return nil
}
