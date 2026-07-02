package llm_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// TestCanonicalEnvKeyLookup_MatchesChatProviders pins the env-fallback table
// to the derived chat catalog by set equality: a Bifrost bump that adds a
// provider fails here until a row (and doc) is added or the provider is
// triaged into the non-chat exclusions, and a removed or renamed provider
// leaves a stale row that fails the same way.
func TestCanonicalEnvKeyLookup_MatchesChatProviders(t *testing.T) {
	t.Parallel()

	got := make([]schemas.ModelProvider, 0, len(llm.CanonicalEnvKeyLookup))
	for p := range llm.CanonicalEnvKeyLookup {
		got = append(got, p)
	}
	want := llm.ChatProviders()
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("CanonicalEnvKeyLookup keys drift from ChatProviders():\n got: %v\nwant: %v", got, want)
	}
}

// TestChatProviders_ExcludedTriple hardcodes the non-chat exclusions:
// StandardProviders minus ChatProviders() must be exactly
// {elevenlabs, runway, runware}, and each must be rejected at config
// validation. An exclusion silently added, dropped, or no longer present
// upstream fails here until re-triaged against the Bifrost sources.
func TestChatProviders_ExcludedTriple(t *testing.T) {
	t.Parallel()

	chat := llm.ChatProviders()
	var got []schemas.ModelProvider
	for _, p := range schemas.StandardProviders {
		if !slices.Contains(chat, p) {
			got = append(got, p)
		}
	}
	want := []schemas.ModelProvider{schemas.Elevenlabs, schemas.Runway, schemas.Runware}
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("excluded providers drift:\n got: %v\nwant: %v", got, want)
	}

	for _, p := range want {
		entry := &llm.ProviderEntry{Provider: string(p)} //nolint:exhaustruct // only Provider matters here
		if err := llm.ValidateProvider(entry); !errors.Is(err, llm.ErrUnknownProvider) {
			t.Errorf("ValidateProvider(%q) = %v, want ErrUnknownProvider", p, err)
		}
	}
}

func TestCanonicalEnvKey_HappyPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		provider schemas.ModelProvider
		wantKey  string
		wantOk   bool
	}{
		{schemas.OpenAI, "OPENAI_API_KEY", true},
		{schemas.Anthropic, "ANTHROPIC_API_KEY", true},
		{schemas.Azure, "AZURE_OPENAI_API_KEY", true},
		{schemas.Gemini, "GEMINI_API_KEY", true},
		{schemas.Vertex, "", false},
		{schemas.Cohere, "COHERE_API_KEY", true},
		{schemas.Mistral, "MISTRAL_API_KEY", true},
		{schemas.Groq, "GROQ_API_KEY", true},
		{schemas.Perplexity, "PERPLEXITY_API_KEY", true},
		{schemas.Cerebras, "CEREBRAS_API_KEY", true},
		{schemas.OpenRouter, "OPENROUTER_API_KEY", true},
		{schemas.XAI, "XAI_API_KEY", true},
		{schemas.HuggingFace, "HUGGINGFACE_API_KEY", true},
		{schemas.Nebius, "NEBIUS_API_KEY", true},
		{schemas.Parasail, "PARASAIL_API_KEY", true},
		{schemas.Fireworks, "FIREWORKS_API_KEY", true},
		{schemas.Replicate, "REPLICATE_API_TOKEN", true},
		{schemas.OpencodeGo, "OPENCODE_API_KEY", true},
		{schemas.OpencodeZen, "OPENCODE_API_KEY", true},
		{schemas.Bedrock, "", false},
		{schemas.Ollama, "", false},
		{schemas.VLLM, "", false},
		{schemas.SGL, "", false},
	}

	for _, c := range cases {
		t.Run(string(c.provider), func(t *testing.T) {
			t.Parallel()
			gotKey, gotOk := llm.CanonicalEnvKey(c.provider)
			if gotKey != c.wantKey || gotOk != c.wantOk {
				t.Errorf("CanonicalEnvKey(%q) = (%q, %v), want (%q, %v)",
					c.provider, gotKey, gotOk, c.wantKey, c.wantOk)
			}
		})
	}
}

func TestCanonicalEnvKey_UnknownProvider(t *testing.T) {
	t.Parallel()

	gotKey, gotOk := llm.CanonicalEnvKey("not-a-real-provider")
	if gotOk {
		t.Errorf("CanonicalEnvKey(unknown) returned ok=true, want false")
	}
	if gotKey != "" {
		t.Errorf("CanonicalEnvKey(unknown) returned %q, want empty", gotKey)
	}
}

func TestValidateProvider_KnownProviders(t *testing.T) {
	t.Parallel()

	for _, p := range llm.ChatProviders() {
		entry := &llm.ProviderEntry{Provider: string(p)} //nolint:exhaustruct // only Provider matters here
		if err := llm.ValidateProvider(entry); err != nil {
			t.Errorf("ValidateProvider(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateProvider_UnknownProvider(t *testing.T) {
	t.Parallel()

	entry := &llm.ProviderEntry{Provider: "claude"} //nolint:exhaustruct // only Provider matters here
	err := llm.ValidateProvider(entry)
	if !errors.Is(err, llm.ErrUnknownProvider) {
		t.Errorf("got %v, want ErrUnknownProvider", err)
	}
	if !strings.Contains(err.Error(), "claude") {
		t.Errorf("error should name the offending provider, got: %v", err)
	}
}

func TestValidateProvider_NilEntry(t *testing.T) {
	t.Parallel()

	if err := llm.ValidateProvider(nil); err != nil {
		t.Errorf("nil entry: got %v, want nil", err)
	}
}
