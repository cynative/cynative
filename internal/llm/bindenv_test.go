package llm_test

import (
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

func TestProviderEnvKeys_IncludesHoistedAndNested(t *testing.T) {
	t.Parallel()

	keys := llm.ProviderEnvKeys()
	want := []string{
		"llm.provider",
		"llm.model",
		"llm.reasoning_effort",
		"llm.reasoning_max_tokens",
		"llm.api_key",
		"llm.azure.endpoint",
		"llm.azure.client_id",
		"llm.vertex.project_id",
		"llm.vertex.region",
		"llm.bedrock.region",
		"llm.bedrock_mantle.region",
		"llm.vllm.url",
		"llm.vllm.model_name",
		"llm.sgl.url",
		"llm.network_config.base_url",
		"llm.network_config.max_retries",
		"llm.openai_config.disable_store",
	}
	for _, w := range want {
		if !slices.Contains(keys, w) {
			t.Errorf("ProviderEnvKeys missing %q", w)
		}
	}
}

func TestProviderEnvKeys_SkipsSlicesMapsAndEnvVarInternals(t *testing.T) {
	t.Parallel()

	keys := llm.ProviderEnvKeys()
	for _, bad := range []string{
		"llm.keys",          // slice, skipped.
		"llm.extra_headers", // map, skipped (config.Load no longer enumerates it).
		"llm.azure.scopes",  // []string slice, skipped.
		"llm.network_config.beta_header_overrides", // map, skipped.
		"llm.azure.endpoint.val",                   // EnvVar is a leaf, not recursed.
		"llm.azure.endpoint.envvar",                // ditto.
	} {
		if slices.Contains(keys, bad) {
			t.Errorf("ProviderEnvKeys should not contain %q", bad)
		}
	}
}

func TestProviderEnvKeys_NoDuplicates(t *testing.T) {
	t.Parallel()

	keys := llm.ProviderEnvKeys()
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if seen[k] {
			t.Errorf("duplicate env key path: %q", k)
		}
		seen[k] = true
	}
}
