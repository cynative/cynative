package llm

import (
	"fmt"
	"slices"

	"github.com/maximhq/bifrost/core/schemas"
)

// ValidateProvider returns ErrUnknownProvider when entry.Provider is not one
// of the chat-capable providers cynative can drive (ChatProviders). Bifrost
// errors cleanly on the first chat request against an unsupported provider;
// rejecting here moves that failure to config-load time, where the operator
// sees it before a run starts. A nil entry is treated as nothing to validate.
func ValidateProvider(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	if slices.Contains(ChatProviders(), schemas.ModelProvider(entry.Provider)) {
		return nil
	}

	return fmt.Errorf(
		"%w: %q — see docs/providers/ for the supported providers",
		ErrUnknownProvider, entry.Provider,
	)
}

// nonChatProviders are the Bifrost providers whose ChatCompletion
// implementation hard-returns an unsupported-operation error. Cynative's
// backend drives only chat, so selecting one could never work; they are
// rejected at config load. Chat capability cannot be verified mechanically:
// re-verify this triage against each provider's ChatCompletion body in the
// Bifrost sources on every bump. A mis-triaged non-chat provider degrades to
// Bifrost's clear runtime error rather than load-time rejection.
//
//nolint:gochecknoglobals,exhaustive // static exclusion set; deliberately partial, lists only the non-chat providers
var nonChatProviders = map[schemas.ModelProvider]bool{
	schemas.Elevenlabs: true,
	schemas.Runway:     true,
	schemas.Runware:    true,
}

// ChatProviders returns every provider cynative can select: Bifrost's
// canonical schemas.StandardProviders minus the non-chat exclusions. Deriving
// the catalog keeps it current across Bifrost bumps; the package tests pin
// the exclusion triple and tie each chat provider to a CanonicalEnvKeyLookup
// row and a docs/providers/<name>.md guide.
func ChatProviders() []schemas.ModelProvider {
	providers := make([]schemas.ModelProvider, 0, len(schemas.StandardProviders))
	for _, p := range schemas.StandardProviders {
		if !nonChatProviders[p] {
			providers = append(providers, p)
		}
	}
	return providers
}

// CanonicalEnvKeyLookup maps each chat-capable Bifrost provider to the
// conventional environment variable cynative reads when neither llm.api_key
// nor llm.keys were configured. An empty string means "this provider has no
// canonical single-env fallback" (Bedrock uses the AWS credential chain;
// Vertex needs structured project/region config in llm.vertex.* and gets
// credentials via the Google ADC chain; Ollama/VLLM/SGL authenticate via the
// local endpoint URL). The "ok bool" returned by CanonicalEnvKey distinguishes
// "provider not configured here" from "configured, but no env fallback".
//
// The key set MUST stay set-equal to ChatProviders(); the
// TestCanonicalEnvKeyLookup_MatchesChatProviders test enforces this.
//
//nolint:gochecknoglobals,exhaustive // lookup table; covers exactly ChatProviders(), not every Bifrost provider
var CanonicalEnvKeyLookup = map[schemas.ModelProvider]string{
	schemas.OpenAI:      "OPENAI_API_KEY",
	schemas.Anthropic:   "ANTHROPIC_API_KEY",
	schemas.Azure:       "AZURE_OPENAI_API_KEY",
	schemas.Gemini:      "GEMINI_API_KEY",
	schemas.Vertex:      "",
	schemas.Cohere:      "COHERE_API_KEY",
	schemas.Mistral:     "MISTRAL_API_KEY",
	schemas.Groq:        "GROQ_API_KEY",
	schemas.Perplexity:  "PERPLEXITY_API_KEY",
	schemas.Cerebras:    "CEREBRAS_API_KEY",
	schemas.OpenRouter:  "OPENROUTER_API_KEY",
	schemas.XAI:         "XAI_API_KEY",
	schemas.HuggingFace: "HUGGINGFACE_API_KEY",
	schemas.Nebius:      "NEBIUS_API_KEY",
	schemas.Parasail:    "PARASAIL_API_KEY",
	schemas.Fireworks:   "FIREWORKS_API_KEY",
	schemas.Replicate:   "REPLICATE_API_TOKEN",
	schemas.OpencodeGo:  "OPENCODE_API_KEY",
	schemas.OpencodeZen: "OPENCODE_API_KEY",
	schemas.Bedrock:     "",
	schemas.Ollama:      "",
	schemas.VLLM:        "",
	schemas.SGL:         "",
}

// CanonicalEnvKey reports the conventional environment variable for the given
// Bifrost provider. The bool is true when the provider is known AND has a
// non-empty fallback var; it is false when the provider is unknown OR when
// the provider is known but has no canonical single-env fallback.
func CanonicalEnvKey(p schemas.ModelProvider) (string, bool) {
	key, known := CanonicalEnvKeyLookup[p]
	if !known || key == "" {
		return "", false
	}
	return key, true
}
