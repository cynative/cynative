package llm

import (
	"fmt"

	"github.com/maximhq/bifrost/core/schemas"
)

// ValidateKeyConfigs returns ErrKeyConfigRequired when entry's provider needs a
// per-key config but a configured key lacks it. It runs on the materialized
// entry.Keys, so it covers both the synthesized key (api_key / canonical env /
// hoisted config) and an explicit keys[]. Only presence is checked here, and
// Bifrost's later check is uneven: it rejects an empty azure endpoint but its
// vertex branch tests only for nil. So this catches the common
// misconfiguration, not every one.
//
// Two providers form the closed required set. Re-verified against
// github.com/maximhq/bifrost/core@v1.12.0, where the failure mode is not a panic:
// validateKey (utils.go:132) rejects the key, key selection logs a warning and
// skips it (bifrost.go:10761-10763), and the request then fails at
// bifrost.go:10777 with "no keys found that support model: X", naming neither
// the provider nor the field that was missing. Mirroring the check here turns
// that into a load-time error that says what to set.
//   - azure:  validateKey requires azure_key_config and a non-empty endpoint
//     (utils.go:135-141).
//   - vertex: validateKey requires vertex_key_config (utils.go:152-155). The
//     unguarded dereference earlier versions of this comment cited still exists
//     (getAuthTokenSource, providers/vertex/vertex.go:236), but nothing reaches
//     it with a nil config because validateKey rejects the key first.
//
// Bifrost hard-requires a config for ollama, vllm, sgl and cloudflare too
// (utils.go:156-183), and for github-copilot whenever the key value is empty
// (utils.go:184-213). Cynative does not mirror those, so they still surface as
// the opaque runtime error above; extending the set is a separate decision,
// not a bump. validateKey also rejects an oauth_key_config on any provider but
// openai (utils.go:234-237), which cynative does not mirror either.
//
// The remaining KeyConfig-bearing providers need no check at all: Replicate
// nil-checks (replicate.go:107); Databricks nil-checks each of its four reads
// (databricks.go:127, 169, 265, 286) and runs from a token plus a base_url with
// no config whatsoever; Bedrock's config is optional (AWS credential chain /
// bare API-key Value). The fields are checked directly (no reflection), so an
// upstream rename of AzureKeyConfig/VertexKeyConfig fails at compile time.
func ValidateKeyConfigs(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	provider := schemas.ModelProvider(entry.Provider)
	if provider == schemas.Azure {
		return requireKeyConfigs(entry.Keys, provider, func(k schemas.Key) bool { return k.AzureKeyConfig != nil })
	}
	if provider == schemas.Vertex {
		return requireKeyConfigs(entry.Keys, provider, func(k schemas.Key) bool { return k.VertexKeyConfig != nil })
	}
	return nil // every other provider's per-key config is optional or absent.
}

// requireKeyConfigs returns keyConfigError unless every configured key carries
// the provider's required config (zero keys also fail).
func requireKeyConfigs(
	keys []schemas.Key, provider schemas.ModelProvider, present func(schemas.Key) bool,
) error {
	if len(keys) == 0 {
		return keyConfigError(provider)
	}
	for i := range keys {
		if !present(keys[i]) {
			return keyConfigError(provider)
		}
	}
	return nil
}

// keyConfigError builds the ErrKeyConfigRequired error for a provider that needs
// structured per-key configuration. It covers both "no keys at all" and "a key
// present but missing the config block".
func keyConfigError(provider schemas.ModelProvider) error {
	return fmt.Errorf(
		"%w: provider %q requires structured llm.%s.* configuration; set it via "+
			"llm.%s.* (an api_key or environment fallback alone is not sufficient) — "+
			"see docs/providers/%s.md",
		ErrKeyConfigRequired, provider, provider, provider, provider,
	)
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
