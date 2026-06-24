package llm

import (
	"fmt"
	"slices"

	"github.com/maximhq/bifrost/core/schemas"
)

// ValidateProvider returns ErrUnknownProvider when entry.Provider is not one of
// the providers Bifrost supports (AllBifrostProviders). An unknown provider must
// be caught here: Bifrost cannot prepare it, and its chat request then blocks
// forever rather than returning an error, deadlocking the agent. The check is
// against the canonical catalog, so it stays correct as Bifrost's provider set
// evolves. A nil entry is treated as nothing to validate.
func ValidateProvider(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	if slices.Contains(AllBifrostProviders, schemas.ModelProvider(entry.Provider)) {
		return nil
	}

	return fmt.Errorf(
		"%w: %q — see docs/providers/ for the supported providers",
		ErrUnknownProvider, entry.Provider,
	)
}

// AllBifrostProviders enumerates every ModelProvider that Bifrost currently
// exposes. It is the single source of truth tying the canonical-env fallback
// table and the docs/providers/ tree together. When Bifrost adds, removes,
// or renames a provider, this list is updated and the package-level
// completeness test fails until the canonical-env row and the
// docs/providers/<name>.md are added too.
var AllBifrostProviders = []schemas.ModelProvider{ //nolint:gochecknoglobals // canonical provider catalog
	schemas.OpenAI,
	schemas.Azure,
	schemas.Anthropic,
	schemas.Bedrock,
	schemas.Cohere,
	schemas.Vertex,
	schemas.Mistral,
	schemas.Ollama,
	schemas.OpencodeGo,
	schemas.OpencodeZen,
	schemas.Groq,
	schemas.SGL,
	schemas.Parasail,
	schemas.Perplexity,
	schemas.Cerebras,
	schemas.Gemini,
	schemas.OpenRouter,
	schemas.Elevenlabs,
	schemas.HuggingFace,
	schemas.Nebius,
	schemas.XAI,
	schemas.Replicate,
	schemas.VLLM,
	schemas.Runway,
	schemas.Fireworks,
}

// CanonicalEnvKeyLookup maps each Bifrost provider to the conventional
// environment variable cynative reads when neither llm.api_key nor llm.keys
// were configured. An empty string means "this provider has no canonical
// single-env fallback" (Bedrock uses the AWS credential chain; Vertex needs
// structured project/region config in llm.vertex.* and gets credentials via
// the Google ADC chain; Ollama/VLLM/SGL authenticate via the local endpoint
// URL; Elevenlabs/Runway aren't chat-capable). The "ok bool" returned by
// CanonicalEnvKey distinguishes
// "provider not configured here" from "configured, but no env fallback".
//
// Every entry in AllBifrostProviders MUST appear here; the
// TestCanonicalEnvKey_CoversAllBifrostProviders test enforces this.
var CanonicalEnvKeyLookup = map[schemas.ModelProvider]string{ //nolint:gochecknoglobals // lookup table
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
	schemas.Elevenlabs:  "",
	schemas.Runway:      "",
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
