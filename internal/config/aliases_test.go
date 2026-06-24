package config_test

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/llm"
)

func TestLoad_APIKeyAlias_LiteralValue(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  api_key: literal-sk
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected exactly 1 synthesized key, got %d", len(cfg.LLM.Keys))
	}
	if cfg.LLM.Keys[0].Value.Val != "literal-sk" {
		t.Errorf("Key[0].Value.Val: got %q, want literal-sk", cfg.LLM.Keys[0].Value.Val)
	}
	if cfg.LLM.APIKey != "" {
		t.Errorf("APIKey should be cleared after materialize, got %q", cfg.LLM.APIKey)
	}
}

func TestLoad_APIKeyAlias_FromEnvViper(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"CYNATIVE_LLM_API_KEY":  "from-env",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(cfg.LLM.Keys))
	}
	if cfg.LLM.Keys[0].Value.Val != "from-env" {
		t.Errorf("Key[0].Value.Val: got %q, want from-env", cfg.LLM.Keys[0].Value.Val)
	}
}

func TestLoad_APIKeyAndKeys_Conflict(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  api_key: shorthand-sk
  keys:
    - value: long-form-sk
      models: ["*"]
      weight: 1.0
`

	_, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if !errors.Is(err, config.ErrAliasConflict) {
		t.Errorf("got %v, want ErrAliasConflict", err)
	}
}

func TestLoad_CanonicalEnvFallback_OpenAI(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"OPENAI_API_KEY":        "sk-canonical",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected 1 synthesized key, got %d", len(cfg.LLM.Keys))
	}
	got := cfg.LLM.Keys[0].Value
	if got.Val != "sk-canonical" {
		t.Errorf("Val: got %q, want sk-canonical", got.Val)
	}
	if !got.FromEnv {
		t.Errorf("FromEnv: got false, want true")
	}
	if got.EnvVar != "OPENAI_API_KEY" {
		t.Errorf("EnvVar: got %q, want OPENAI_API_KEY", got.EnvVar)
	}
}

func TestLoad_CanonicalEnvFallback_NoFallbackForBedrock(t *testing.T) {
	t.Parallel()

	// Bedrock has no canonical-env fallback. Load should succeed with
	// no Keys synthesized — Bifrost picks up AWS credentials at request time.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "bedrock",
		"CYNATIVE_LLM_MODEL":    "anthropic.claude-opus-4-v1:0",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 0 {
		t.Errorf("expected zero synthesized keys for bedrock, got %d", len(cfg.LLM.Keys))
	}
}

func TestLoad_CanonicalEnvFallback_AlreadySetSkipsFallback(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"CYNATIVE_LLM_API_KEY":  "from-cynative-env",
		"OPENAI_API_KEY":        "from-canonical-env",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.Keys[0].Value.Val != "from-cynative-env" {
		t.Errorf("Val: got %q, want from-cynative-env", cfg.LLM.Keys[0].Value.Val)
	}
}

func TestLoad_CanonicalEnvFallback_EnvUnset_NoKeysAdded(t *testing.T) {
	t.Parallel()

	// The canonical env is omitted, so the hermetic lookup reports it unset and
	// no key is synthesized.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 0 {
		t.Errorf("expected zero keys when canonical env is unset, got %d", len(cfg.LLM.Keys))
	}
}

func TestLoad_CanonicalEnvFallback_AllProviders(t *testing.T) {
	t.Parallel()

	// Table-driven: for every provider that HAS a canonical env var,
	// load with only the provider+model env vars + that canonical env set,
	// and assert the key was synthesized from the right source.
	cases := []struct {
		provider string
		envName  string
		model    string
	}{
		{"openai", "OPENAI_API_KEY", "gpt-5"},
		{"anthropic", "ANTHROPIC_API_KEY", "claude-opus-4-7"},
		{"gemini", "GEMINI_API_KEY", "gemini-2.5-pro"},
		{"cohere", "COHERE_API_KEY", "command-r-plus"},
		{"mistral", "MISTRAL_API_KEY", "mistral-large-latest"},
		{"groq", "GROQ_API_KEY", "llama-3.3-70b"},
		{"perplexity", "PERPLEXITY_API_KEY", "sonar-pro"},
		{"cerebras", "CEREBRAS_API_KEY", "llama-3.3-70b"},
		{"openrouter", "OPENROUTER_API_KEY", "anthropic/claude-opus-4"},
		{"xai", "XAI_API_KEY", "grok-3"},
		{"huggingface", "HUGGINGFACE_API_KEY", "meta-llama/Llama-3.3-70B"},
		{"nebius", "NEBIUS_API_KEY", "meta-llama/Llama-3.3-70B"},
		{"parasail", "PARASAIL_API_KEY", "parasail-l3.3-70b"},
		{"fireworks", "FIREWORKS_API_KEY", "accounts/fireworks/models/llama-v3p3-70b-instruct"},
		{"replicate", "REPLICATE_API_TOKEN", "meta/meta-llama-3.3-70b-instruct"},
	}

	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			t.Parallel()

			cfg, err := loaderEnv(t, map[string]string{
				"CYNATIVE_LLM_PROVIDER": c.provider,
				"CYNATIVE_LLM_MODEL":    c.model,
				c.envName:               "synth-" + c.provider,
			}).Load("")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.LLM.Keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(cfg.LLM.Keys))
			}
			got := cfg.LLM.Keys[0].Value
			if got.Val != "synth-"+c.provider {
				t.Errorf("Val: got %q, want synth-%s", got.Val, c.provider)
			}
			if got.EnvVar != c.envName {
				t.Errorf("EnvVar: got %q, want %s", got.EnvVar, c.envName)
			}
		})
	}
}

func TestLoad_AzureKeyConfigAlias_FoldsIntoKey(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: azure
  model: gpt-4o-prod
  api_key: az-key
  azure:
    endpoint: https://r.openai.azure.com
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(cfg.LLM.Keys))
	}
	if cfg.LLM.Keys[0].AzureKeyConfig == nil {
		t.Fatal("AzureKeyConfig was not folded into keys[0]")
	}
	if got := cfg.LLM.Keys[0].AzureKeyConfig.Endpoint.Val; got != "https://r.openai.azure.com" {
		t.Errorf("endpoint: got %q", got)
	}
	if cfg.LLM.Azure != nil {
		t.Error("Azure alias should be cleared after materialize")
	}
}

func TestLoad_VertexKeyConfig_NoAPIKey_StillSynthesizesKey(t *testing.T) {
	t.Parallel()

	// No canonical creds set, so the key Value is empty; the vertex config
	// alone must still trigger a synthesized key.
	yaml := `llm:
  provider: vertex
  model: gemini-2.5-pro
  vertex:
    project_id: my-proj
    region: us-central1
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(cfg.LLM.Keys))
	}
	if cfg.LLM.Keys[0].VertexKeyConfig == nil {
		t.Fatal("VertexKeyConfig was not folded into keys[0]")
	}
	if cfg.LLM.Keys[0].VertexKeyConfig.ProjectID.Val != "my-proj" {
		t.Errorf("project_id: got %q", cfg.LLM.Keys[0].VertexKeyConfig.ProjectID.Val)
	}
	if cfg.LLM.Keys[0].VertexKeyConfig.Region.Val != "us-central1" {
		t.Errorf("region: got %q", cfg.LLM.Keys[0].VertexKeyConfig.Region.Val)
	}
	if cfg.LLM.Vertex != nil {
		t.Error("Vertex alias should be cleared after materialize")
	}
}

func TestLoad_HoistedConfigAndKeys_Conflict(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: azure
  model: gpt-4o-prod
  azure:
    endpoint: https://alias
  keys:
    - value: az
      models: ["*"]
      weight: 1.0
      azure_key_config:
        endpoint: https://nested
`

	if _, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml)); !errors.Is(err, config.ErrAliasConflict) {
		t.Errorf("got %v, want ErrAliasConflict", err)
	}
}

func TestLoad_APIKeyAlias_EnvForm_Resolves(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  api_key: env.CYN_TEST_APIKEY
`

	l := config.NewLoader(envMap(map[string]string{"CYN_TEST_APIKEY": "resolved-sk"}))

	cfg, err := l.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 {
		t.Fatalf("expected 1 synthesized key, got %d", len(cfg.LLM.Keys))
	}
	got := cfg.LLM.Keys[0].Value
	if got.Val != "resolved-sk" {
		t.Errorf("Val: got %q, want resolved-sk", got.Val)
	}
	if !got.FromEnv {
		t.Errorf("FromEnv: got false, want true")
	}
	if got.EnvVar != "env.CYN_TEST_APIKEY" {
		t.Errorf("EnvVar: got %q, want env.CYN_TEST_APIKEY", got.EnvVar)
	}
}

func TestLoad_APIKeyAlias_EnvForm_Unset_Errors(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  api_key: env.CYN_TEST_UNSET
`

	// Load must succeed; LLM validation (including env-var checks) moved to ValidateLLM.
	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrEnvVarUnset) {
		t.Fatalf("ValidateLLM = %v, want ErrEnvVarUnset", vErr)
	}
}
