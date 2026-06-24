package llm

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// keyConfigRequired lists the providers whose Bifrost implementation
// dereferences key.<X>KeyConfig WITHOUT a nil guard, so a key that omits that
// config panics at request time instead of returning a clean error. Verified
// against github.com/maximhq/bifrost/core@v1.5.10:
//   - azure:  providers/azure/azure.go:249   key.AzureKeyConfig.Endpoint.GetValue()
//   - vertex: providers/vertex/vertex.go:519  key.VertexKeyConfig.ProjectID.GetValue()
//
// The other KeyConfig-bearing providers are intentionally absent: Replicate
// nil-checks (replicate.go:96); Bedrock's config is optional (AWS credential
// chain / bare API-key Value); Ollama/VLLM/SGL accept the endpoint URL via
// NetworkConfig.BaseURL. Requiredness is provider behavior, not type
// information, so it is the one fact reflection cannot supply; this set is
// pinned to real schemas.Key fields by TestKeyConfigRequired_FieldsExist.
var keyConfigRequired = []schemas.ModelProvider{ //nolint:gochecknoglobals // lookup table
	schemas.Azure,
	schemas.Vertex,
}

// ValidateKeyConfigs returns ErrKeyConfigRequired when entry's provider needs a
// per-key config (keyConfigRequired) but a configured key lacks it. It runs on
// the materialized entry.Keys, so it covers both the synthesized key (api_key /
// canonical env / hoisted config) and an explicit keys[]. Presence is
// sufficient: a nil config panics inside Bifrost, while a present-but-empty
// config yields Bifrost's own ConfigurationError.
//
// The provider→field mapping is reflective: a schemas.Key field named
// "<X>KeyConfig" belongs to provider lower(X). Adding a provider to
// keyConfigRequired is the only change needed to protect it.
func ValidateKeyConfigs(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	provider := schemas.ModelProvider(entry.Provider)
	for field := range reflect.TypeFor[schemas.Key]().Fields() {
		name, isKeyConfig := strings.CutSuffix(field.Name, "KeyConfig")
		if !isKeyConfig || !strings.EqualFold(name, string(provider)) {
			continue
		}
		if !slices.Contains(keyConfigRequired, provider) {
			return nil // provider has a config field, but it is optional
		}
		if len(entry.Keys) == 0 {
			return keyConfigError(provider)
		}
		for i := range entry.Keys {
			if reflect.ValueOf(entry.Keys[i]).FieldByIndex(field.Index).IsNil() {
				return keyConfigError(provider)
			}
		}
		return nil
	}
	return nil // provider has no per-key config field (most providers)
}

// keyConfigError builds the ErrKeyConfigRequired error for a provider that needs
// structured per-key configuration. It covers both "no keys at all" and "a key
// present but missing the config block".
func keyConfigError(provider schemas.ModelProvider) error {
	return fmt.Errorf(
		"%w: provider %q requires structured llm.%s.* configuration; set it via "+
			"llm.%s.* (an api_key or environment fallback alone is not sufficient) — "+
			"see docs/providers/%s.md",
		ErrKeyConfigRequired, provider, provider, provider, provider)
}

// ValidateKeyPresence returns ErrNoKeysForProvider when no key ENTRY exists after
// materialize. This applies to EVERY provider: FileAccount.GetKeysForProvider
// rejects an empty Keys slice unconditionally (even with a base_url override), so a
// provider with zero keys is a guaranteed runtime failure regardless of whether it
// is "key-requiring" — an OpenAI run needs an API key, and a keyless provider like
// Ollama/vLLM/SGL still needs its provider-specific config (e.g.
// CYNATIVE_LLM_OLLAMA_URL) which materializes into a key entry. Catching the empty
// case here renders an actionable "no credentials configured" up front instead of a
// misleading runtime "could not reach the provider". The signal is the presence of
// a key ENTRY, not a non-empty value: Azure legitimately authenticates via a key
// synthesized from its endpoint/service-principal config with an empty Value
// (bearer-token auth), and a wrong/empty literal key otherwise surfaces as a clean
// runtime 401 — so an empty value is deliberately NOT flagged.
func ValidateKeyPresence(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}
	if len(entry.Keys) == 0 {
		return fmt.Errorf("%w", ErrNoKeysForProvider)
	}
	return nil
}
