package llm_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

func TestAllBifrostProviders_NonEmpty(t *testing.T) {
	t.Parallel()

	if len(llm.AllBifrostProviders) == 0 {
		t.Fatal("AllBifrostProviders is empty")
	}
}

func TestAllBifrostProviders_NoDuplicates(t *testing.T) {
	t.Parallel()

	seen := make(map[schemas.ModelProvider]bool, len(llm.AllBifrostProviders))
	for _, p := range llm.AllBifrostProviders {
		if seen[p] {
			t.Errorf("duplicate entry: %s", p)
		}
		seen[p] = true
	}
}

// TestAllBifrostProviders_MatchesBifrostSchemas pins the cynative-side catalog
// to schemas.StandardProviders — Bifrost's own enumeration of every built-in
// provider. If Bifrost adds, removes, or renames a provider in that slice,
// this test fails until AllBifrostProviders is updated. Asserting against
// the upstream slice (rather than a hand-maintained want list) catches
// silent drift when new constants land upstream.
func TestAllBifrostProviders_MatchesBifrostSchemas(t *testing.T) {
	t.Parallel()

	got := slices.Clone(llm.AllBifrostProviders)
	want := slices.Clone(schemas.StandardProviders)
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("AllBifrostProviders drift from schemas.StandardProviders:\n got: %v\nwant: %v", got, want)
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
		{schemas.Elevenlabs, "", false},
		{schemas.Runway, "", false},
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

func TestCanonicalEnvKey_CoversAllBifrostProviders(t *testing.T) {
	t.Parallel()

	for _, p := range llm.AllBifrostProviders {
		if _, ok := llm.CanonicalEnvKeyLookup[p]; !ok {
			t.Errorf("provider %q is in AllBifrostProviders but missing from CanonicalEnvKeyLookup", p)
		}
	}
}

func TestValidateProvider_KnownProviders(t *testing.T) {
	t.Parallel()

	for _, p := range llm.AllBifrostProviders {
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
