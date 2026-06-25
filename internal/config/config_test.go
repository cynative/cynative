package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/sandbox"
)

// validYAML is a happy-path config covering the flat llm block.
const validYAML = `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: openai-key
      value: literal-key
      models: ["*"]
      weight: 1.0
`

// envMap returns a llm.LookupEnv backed by m, so tests resolve CYNATIVE_* and
// canonical env vars hermetically without touching the process environment.
func envMap(m map[string]string) llm.LookupEnv {
	return func(k string) (string, bool) {
		v, ok := m[k]

		return v, ok
	}
}

// writeConfig writes content to a fresh temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return cfgPath
}

// loaderEnv builds a Loader whose env is m and whose default-config home dir is
// an empty temp dir, so Load("") resolves the default path but finds no file.
func loaderEnv(t *testing.T, m map[string]string) *config.Loader {
	t.Helper()

	home := t.TempDir()

	return config.NewLoader(envMap(m), config.WithHomeDir(func() (string, error) { return home, nil }))
}

func TestLoad_HomeDirError(t *testing.T) {
	t.Parallel()

	errHome := errors.New("home dir unavailable")
	l := config.NewLoader(envMap(nil), config.WithHomeDir(func() (string, error) { return "", errHome }))

	_, err := l.Load("")
	if err == nil {
		t.Fatal("expected error when home dir resolution fails")
	}

	if !errors.Is(err, errHome) {
		t.Errorf("expected wrapped errHome, got: %v", err)
	}
}

func TestLoad_NoConfigFile_MissingModel(t *testing.T) {
	t.Parallel()

	// Load must succeed now; LLM validation moved to ValidateLLM.
	cfg, err := loaderEnv(t, map[string]string{"CYNATIVE_LLM_PROVIDER": "openai"}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, config.ErrLLMModelMissing) {
		t.Errorf("ValidateLLM = %v, want ErrLLMModelMissing", vErr)
	}
}

func TestLoad_NoConfigFile_MissingProvider(t *testing.T) {
	t.Parallel()

	// Load must succeed now; LLM validation moved to ValidateLLM.
	cfg, err := loaderEnv(t, map[string]string{"CYNATIVE_LLM_MODEL": "gpt-5"}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, config.ErrLLMProviderMissing) {
		t.Errorf("ValidateLLM = %v, want ErrLLMProviderMissing", vErr)
	}
}

func TestLoad_NoConfigFile_UnknownProvider(t *testing.T) {
	t.Parallel()

	// "claude" is a common mistake for the "anthropic" provider; ValidateLLM
	// must reject it. Load itself must succeed now.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "claude",
		"CYNATIVE_LLM_MODEL":    "claude-3-5-sonnet",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrUnknownProvider) {
		t.Errorf("ValidateLLM = %v, want ErrUnknownProvider", vErr)
	}
}

func TestValidateLLM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   llm.ProviderEntry
		wantErr error
	}{
		{
			"missing provider",
			llm.ProviderEntry{},
			config.ErrLLMProviderMissing,
		}, //nolint:exhaustruct // partial entry by design
		{
			"missing model",
			llm.ProviderEntry{Provider: "openai"},
			config.ErrLLMModelMissing,
		}, //nolint:exhaustruct // partial entry by design
		{
			"unknown provider",
			llm.ProviderEntry{Provider: "nope", Model: "x"},
			llm.ErrUnknownProvider,
		}, //nolint:exhaustruct // partial entry by design
		{
			"no key for key-requiring provider",
			llm.ProviderEntry{Provider: "openai", Model: "gpt-5.5"},
			llm.ErrNoKeysForProvider,
		}, //nolint:exhaustruct // partial entry by design
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := config.ValidateLLM(&tt.entry)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateLLM() = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateLLM_MissingAPIKey verifies that provider+model set but no key for a
// key-requiring provider surfaces ErrNoKeysForProvider before any network call.
func TestValidateLLM_MissingAPIKey(t *testing.T) {
	t.Parallel()

	// Provider and model set but no API key provided for a key-requiring provider
	// (openai requires a key when no base_url override is given). ValidateLLM must
	// surface ErrNoKeysForProvider so it can be classified as "API key not set"
	// before any network call is made.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5.5",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed for a partial config; got: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrNoKeysForProvider) {
		t.Errorf("ValidateLLM = %v, want ErrNoKeysForProvider", vErr)
	}
}

func TestLoad_DoesNotHardFailOnEmptyLLM(t *testing.T) {
	t.Parallel()

	// No provider set: Load must SUCCEED now (validation moved to ValidateLLM).
	cfg, err := loaderEnv(t, map[string]string{}).Load("")
	if err != nil {
		t.Fatalf("Load should not fail on empty LLM block, got: %v", err)
	}
	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, config.ErrLLMProviderMissing) {
		t.Errorf("ValidateLLM(empty) = %v, want ErrLLMProviderMissing", vErr)
	}
}

func TestLoad_ExplicitFile_HappyPath(t *testing.T) {
	t.Parallel()

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Model != "gpt-5" {
		t.Errorf("expected llm.model 'gpt-5', got %q", cfg.LLM.Model)
	}

	if cfg.LLM.Provider != "openai" {
		t.Errorf("expected llm.provider 'openai', got %q", cfg.LLM.Provider)
	}

	if len(cfg.LLM.Keys) == 0 {
		t.Fatal("expected at least one key in llm.keys")
	}

	if cfg.LLM.Keys[0].Value.Val != "literal-key" {
		t.Errorf("expected key value 'literal-key', got %q", cfg.LLM.Keys[0].Value.Val)
	}
}

func TestLoad_DefaultConfigPath(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	cynativeDir := filepath.Join(home, ".cynative")

	if err := os.MkdirAll(cynativeDir, 0o750); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	cfgPath := filepath.Join(cynativeDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	l := config.NewLoader(envMap(nil), config.WithHomeDir(func() (string, error) { return home, nil }))

	cfg, err := l.Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Model != "gpt-5" {
		t.Errorf("expected model 'gpt-5', got %q", cfg.LLM.Model)
	}
}

func TestLoad_MalformedConfigFile(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfig(t, ":\n  not: valid: yaml: [")

	_, err := config.NewLoader(envMap(nil)).Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for malformed explicit config file")
	}

	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("expected 'failed to read config file' in error, got: %v", err)
	}
}

func TestLoad_UnmarshalError(t *testing.T) {
	t.Parallel()

	// A scalar "llm" cannot be decoded into the ProviderEntry struct, forcing
	// Unmarshal to fail.
	cfgPath := writeConfig(t, "llm: not-a-struct\n")

	_, err := config.NewLoader(envMap(nil)).Load(cfgPath)
	if err == nil {
		t.Fatal("expected unmarshal error when llm is not a map")
	}

	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected 'unmarshal' in error message, got: %v", err)
	}
}

func TestLoad_ValidationError_InvalidRenderStyle(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: openai-key
      value: literal-key
      models: ["*"]
      weight: 1.0
render_style: neon
`

	_, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for invalid render style")
	}

	if !strings.Contains(err.Error(), "render style must be one of") {
		t.Errorf("expected friendly render style error, got: %v", err)
	}
}

func TestLoad_AdaptiveRenderStyleValid(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: openai-key
      value: literal-key
      models: ["*"]
      weight: 1.0
render_style: adaptive
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("adaptive render_style should validate, got: %v", err)
	}
	if cfg.RenderStyle != "adaptive" {
		t.Errorf("expected render_style 'adaptive', got: %q", cfg.RenderStyle)
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if cfg.LLM.Model != "" {
		t.Errorf("expected empty default llm.model, got: %q", cfg.LLM.Model)
	}

	if cfg.LLM.Provider != "" {
		t.Errorf("expected empty default llm.provider, got: %q", cfg.LLM.Provider)
	}

	if cfg.RenderStyle != "adaptive" {
		t.Errorf("expected default render_style 'adaptive', got: %q", cfg.RenderStyle)
	}

	if cfg.MaxIterations != 32 {
		t.Errorf("expected default max_iterations 32, got: %d", cfg.MaxIterations)
	}

	if cfg.MaxSubagentIterations != 10 {
		t.Errorf("expected default max_subagent_iterations 10, got: %d", cfg.MaxSubagentIterations)
	}

	if cfg.SandboxMaxConcurrency != 16 {
		t.Errorf("expected default sandbox_max_concurrency 16, got: %d", cfg.SandboxMaxConcurrency)
	}

	if cfg.MaxTotalTokens != 0 {
		t.Errorf("expected default max_total_tokens 0 (unbounded), got: %d", cfg.MaxTotalTokens)
	}

	if cfg.MaxConsecutiveFailures != 5 {
		t.Errorf("expected default max_consecutive_failures 5, got: %d", cfg.MaxConsecutiveFailures)
	}
}

func TestDefaultConfig_SandboxMaxConcurrencyMatchesSandboxDefault(t *testing.T) {
	t.Parallel()

	if got, want := config.DefaultConfig().SandboxMaxConcurrency, sandbox.DefaultMaxConcurrency; got != want {
		t.Errorf(
			"config default sandbox_max_concurrency = %d, want sandbox.DefaultMaxConcurrency (%d); keep them in lockstep",
			got,
			want,
		)
	}
}

func TestValidate_Valid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		RenderStyle:           "adaptive",
		MaxIterations:         32,
		MaxSubagentIterations: 10,
		SandboxMaxConcurrency: 16,
		Cache: config.CacheConfig{
			Dir: "~/.cynative/cache",
			TTL: time.Hour,
		},
		Audit: config.AuditConfig{
			Enabled:       true,
			Path:          "~/.cynative/audit.log",
			MaxSizeMB:     100,
			RetentionDays: 30,
			Compress:      false,
		},
		Connectors: config.ConnectorsConfig{ //nolint:exhaustruct // Github left at its zero value
			AWS:        config.AWSConfig{Policy: "arn:aws:iam::aws:policy/SecurityAudit"},
			EKS:        config.ClusterRoleConfig{ClusterRole: "view"},
			GCP:        config.GCPConfig{Role: "roles/viewer"},
			GKE:        config.ClusterRoleConfig{ClusterRole: "view"},
			Azure:      config.AzureConfig{RoleDefinition: "Reader", Cloud: "auto"},
			AKS:        config.ClusterRoleConfig{ClusterRole: "view"},
			Kubernetes: config.ClusterRoleConfig{ClusterRole: "view"},
		},
		LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
			Provider: "openai",
			Model:    "gpt-5",
			Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
				Value: schemas.SecretVar{Val: "k"},
			}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	t.Parallel()

	// RenderStyle is `required` per the struct tag; leaving it empty
	// exercises the validator's required-field path.
	cfg := config.Config{
		RenderStyle:           "",
		MaxIterations:         32,
		MaxSubagentIterations: 10,
		SandboxMaxConcurrency: 16,
		LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
			Provider: "openai",
			Model:    "gpt-5",
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for empty render style")
	}

	if !strings.Contains(err.Error(), "render style must be one of") {
		t.Errorf("expected friendly render style error, got: %v", err)
	}
}

func TestValidate_InvalidRenderStyle(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		RenderStyle:           "neon",
		MaxIterations:         32,
		MaxSubagentIterations: 10,
		SandboxMaxConcurrency: 16,
		LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
			Provider: "openai",
			Model:    "gpt-5",
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid render style")
	}

	if !strings.Contains(err.Error(), "render style must be one of") {
		t.Errorf("expected friendly render style error, got: %v", err)
	}
}

func TestValidate_InvalidMaxSubagentIterations(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		RenderStyle:           "adaptive",
		MaxIterations:         32,
		MaxSubagentIterations: 0,
		SandboxMaxConcurrency: 16,
		LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
			Provider: "openai",
			Model:    "gpt-5",
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for zero max_subagent_iterations")
	}

	if !strings.Contains(err.Error(), "max_subagent_iterations must be at least 1") {
		t.Errorf("expected friendly max_subagent_iterations error, got: %v", err)
	}
}

func TestValidate_SandboxMaxConcurrencyBounds(t *testing.T) {
	t.Parallel()

	for name, n := range map[string]int{"zero": 0, "negative": -1, "too large": 65} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				RenderStyle:           "adaptive",
				MaxIterations:         32,
				MaxSubagentIterations: 10,
				SandboxMaxConcurrency: n,
				LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
					Provider: "openai",
					Model:    "gpt-5",
				},
			}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for sandbox_max_concurrency %d", n)
			}
			if !strings.Contains(err.Error(), "sandbox_max_concurrency must be between 1 and 64") {
				t.Errorf("expected friendly sandbox_max_concurrency error, got: %v", err)
			}
		})
	}
}

func TestErrMsg_ShortNamespace(t *testing.T) {
	t.Parallel()

	stub := config.StubFieldError{NamespaceVal: "Config"} //nolint:exhaustruct // only Namespace under test
	if msg := config.ErrMsg(stub); msg != "" {
		t.Errorf("expected empty string for short namespace, got: %q", msg)
	}
}

func TestErrMsg_UnknownField(t *testing.T) {
	t.Parallel()

	stub := config.StubFieldError{
		NamespaceVal: "Config.LLM.NonExistent",
	} //nolint:exhaustruct // only Namespace under test
	if msg := config.ErrMsg(stub); msg != "" {
		t.Errorf("expected empty string for unknown field, got: %q", msg)
	}
}

func TestFormatValidationErrors_Fallback(t *testing.T) {
	t.Parallel()

	stub := config.StubFieldError{
		NamespaceVal: "Config.LLM.NonExistent",
		TagVal:       "required",
	} //nolint:exhaustruct // only Namespace and Tag under test

	result := config.FormatValidationErrors([]validator.FieldError{stub})

	if !strings.Contains(result, "Config.LLM.NonExistent failed validation (required)") {
		t.Errorf("expected fallback message, got: %q", result)
	}
}

func TestErrMsg_NamespaceAtParentStruct(t *testing.T) {
	t.Parallel()

	// "Config.LLM" walks to the LLM field which is a struct type, not a leaf
	// with an errmsg tag — should return empty string.
	stub := config.StubFieldError{NamespaceVal: "Config.LLM"} //nolint:exhaustruct // only Namespace under test
	if msg := config.ErrMsg(stub); msg != "" {
		t.Errorf("expected empty string for struct-level namespace, got: %q", msg)
	}
}

func TestErrMsgFromType_NonStructGuard(t *testing.T) {
	t.Parallel()

	// Custom type whose leaf field (Name) is a string with no errmsg tag.
	// Walking "Root.Name.Bogus" will: find Name (string, no errmsg) → set
	// t = string → next iteration hits the non-struct guard.
	type root struct {
		Name string
	}

	stub := config.StubFieldError{NamespaceVal: "Root.Name.Bogus"} //nolint:exhaustruct // only Namespace under test
	if msg := config.ErrMsgFromType(stub, reflect.TypeFor[root]()); msg != "" {
		t.Errorf("expected empty string for non-struct type, got: %q", msg)
	}
}

func TestErrMsgFromType_DereferencesPointerToStruct(t *testing.T) {
	t.Parallel()

	// A pointer-to-struct field must be dereferenced so its leaf errmsg tag is
	// reachable (the production tree has no pointer-to-struct fields today, so this
	// pins the defensive deref directly).
	type inner struct {
		Mode string `errmsg:"inner mode bad"`
	}
	type root struct {
		Block *inner
	}

	stub := config.StubFieldError{NamespaceVal: "Root.Block.Mode"} //nolint:exhaustruct // only Namespace under test
	if msg := config.ErrMsgFromType(stub, reflect.TypeFor[root]()); msg != "inner mode bad" {
		t.Errorf("ErrMsgFromType through *inner = %q, want \"inner mode bad\"", msg)
	}
}

func TestFormatValidationErrors_MultipleErrors(t *testing.T) {
	t.Parallel()

	stubs := []validator.FieldError{
		config.StubFieldError{ //nolint:exhaustruct // only Namespace and Tag under test
			NamespaceVal: "Config.LLM.NonExistent",
			TagVal:       "required",
		},
		config.StubFieldError{ //nolint:exhaustruct // only Namespace and Tag under test
			NamespaceVal: "Config.RenderStyle",
			TagVal:       "required",
		},
	}

	result := config.FormatValidationErrors(stubs)

	if !strings.Contains(result, "\n") {
		t.Errorf("expected newline separator between errors, got: %q", result)
	}

	if !strings.Contains(result, "render style must be one of") {
		t.Errorf("expected friendly render style error, got: %q", result)
	}
}

func TestValidate_NonValidationError(t *testing.T) {
	t.Parallel()

	errUnexpected := errors.New("unexpected validator error")
	cfg := config.Config{} //nolint:exhaustruct // intentionally empty

	err := config.ValidateConfig(cfg, func(_ any) error { return errUnexpected })
	if err == nil {
		t.Fatal("expected error from validateConfig")
	}

	if !errors.Is(err, errUnexpected) {
		t.Errorf("expected wrapped errUnexpected, got: %v", err)
	}

	if !strings.Contains(err.Error(), "config validation failed") {
		t.Errorf("expected fallback message, got: %v", err)
	}
}

func TestLoad_FutureProofedBifrostFields_OpenAI(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: prod
      value: literal-key
      models: ["*"]
      weight: 1.0
  network_config:
    base_url: https://api.openai.com/v1
    default_request_timeout_in_seconds: 30
    max_retries: 3
    extra_headers:
      x-custom-header: hello
    retry_backoff_initial: "500ms"
    retry_backoff_max: "5s"
  openai_config:
    disable_store: true
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.NetworkConfig.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("BaseURL: got %q", cfg.LLM.NetworkConfig.BaseURL)
	}
	if cfg.LLM.NetworkConfig.MaxRetries != 3 {
		t.Errorf("MaxRetries: got %d, want 3", cfg.LLM.NetworkConfig.MaxRetries)
	}
	if cfg.LLM.NetworkConfig.RetryBackoffInitial != 500*time.Millisecond {
		t.Errorf("RetryBackoffInitial: got %v, want 500ms", cfg.LLM.NetworkConfig.RetryBackoffInitial)
	}
	if cfg.LLM.NetworkConfig.RetryBackoffMax != 5*time.Second {
		t.Errorf("RetryBackoffMax: got %v, want 5s", cfg.LLM.NetworkConfig.RetryBackoffMax)
	}
	if cfg.LLM.NetworkConfig.ExtraHeaders["x-custom-header"] != "hello" {
		t.Errorf("ExtraHeaders: got %v", cfg.LLM.NetworkConfig.ExtraHeaders)
	}
	if cfg.LLM.OpenAIConfig == nil || !cfg.LLM.OpenAIConfig.DisableStore {
		t.Errorf("OpenAIConfig.DisableStore: got %+v", cfg.LLM.OpenAIConfig)
	}
}

func TestLoad_OllamaKeyConfig(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: ollama
  model: llama3
  keys:
    - name: ollama
      value: literal
      models: ["llama3"]
      weight: 1.0
      ollama_key_config:
        url: http://localhost:11434
`

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.LLM.Keys) != 1 || cfg.LLM.Keys[0].OllamaKeyConfig == nil {
		t.Fatalf("ollama key not populated: %+v", cfg.LLM)
	}
	if cfg.LLM.Keys[0].OllamaKeyConfig.URL.Val != "http://localhost:11434" {
		t.Errorf("OllamaKeyConfig.URL: got %q", cfg.LLM.Keys[0].OllamaKeyConfig.URL.Val)
	}
}

func TestLoad_EnvVarReferenceResolved(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: prod
      value: env.CYN_LOAD_TEST_OPENAI_KEY
      models: ["*"]
      weight: 1.0
`

	l := config.NewLoader(envMap(map[string]string{"CYN_LOAD_TEST_OPENAI_KEY": "sk-resolved"}))

	cfg, err := l.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := cfg.LLM.Keys[0].Value
	if !got.IsFromEnv() {
		t.Errorf("FromEnv: got false, want true")
	}
	if got.Val != "sk-resolved" {
		t.Errorf("Val: got %q, want sk-resolved", got.Val)
	}
}

func TestLoad_EnvVarReferenceUnset_FailsAtStartup(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: prod
      value: env.CYN_UNSET_PROBE_VAR_X1
      models: ["*"]
      weight: 1.0
`

	// Load must succeed; LLM validation (including env-var checks) moved to ValidateLLM.
	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrEnvVarUnset) {
		t.Errorf("ValidateLLM = %v, want ErrEnvVarUnset", vErr)
	}
}

func TestLoad_DurationAsInt_Rejected(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: prod
      value: literal-key
      models: ["*"]
      weight: 1.0
  network_config:
    retry_backoff_initial: 500
`

	_, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for int retry_backoff_initial")
	}
	if !strings.Contains(err.Error(), "duration string") {
		t.Errorf("error should mention 'duration string', got: %v", err)
	}
}

func TestLoad_AzureEndpoint_ResolvesFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":       "azure",
		"CYNATIVE_LLM_MODEL":          "gpt-4o-prod",
		"AZURE_OPENAI_API_KEY":        "az-canonical",
		"CYNATIVE_LLM_AZURE_ENDPOINT": "https://r.openai.azure.com",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 || cfg.LLM.Keys[0].AzureKeyConfig == nil {
		t.Fatalf("expected azure key config in keys[0], got %+v", cfg.LLM.Keys)
	}
	if got := cfg.LLM.Keys[0].AzureKeyConfig.Endpoint.Val; got != "https://r.openai.azure.com" {
		t.Errorf("endpoint: got %q", got)
	}
	if got := cfg.LLM.Keys[0].Value; got.Val != "az-canonical" || got.EnvKey() != "AZURE_OPENAI_API_KEY" ||
		!got.IsFromEnv() {
		t.Errorf("canonical key value: got %+v, want {Val:az-canonical EnvVar:AZURE_OPENAI_API_KEY FromEnv:true}", got)
	}
}

func TestLoad_BedrockRegion_ResolvesFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":       "bedrock",
		"CYNATIVE_LLM_MODEL":          "anthropic.claude-opus-4-v1:0",
		"CYNATIVE_LLM_BEDROCK_REGION": "us-east-1",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 || cfg.LLM.Keys[0].BedrockKeyConfig == nil {
		t.Fatalf("expected bedrock key config in keys[0], got %+v", cfg.LLM.Keys)
	}
	if cfg.LLM.Keys[0].BedrockKeyConfig.Region == nil ||
		cfg.LLM.Keys[0].BedrockKeyConfig.Region.Val != "us-east-1" {
		t.Errorf("region: got %+v", cfg.LLM.Keys[0].BedrockKeyConfig.Region)
	}
}

func TestLoad_VertexConfig_ResolvesFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":          "vertex",
		"CYNATIVE_LLM_MODEL":             "gemini-2.5-pro",
		"CYNATIVE_LLM_VERTEX_PROJECT_ID": "my-proj",
		"CYNATIVE_LLM_VERTEX_REGION":     "us-central1",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LLM.Keys) != 1 || cfg.LLM.Keys[0].VertexKeyConfig == nil {
		t.Fatalf("expected vertex key config in keys[0], got %+v", cfg.LLM.Keys)
	}
	if cfg.LLM.Keys[0].VertexKeyConfig.ProjectID.Val != "my-proj" ||
		cfg.LLM.Keys[0].VertexKeyConfig.Region.Val != "us-central1" {
		t.Errorf("vertex config: got %+v", cfg.LLM.Keys[0].VertexKeyConfig)
	}
}

func TestLoad_VertexAPIKeyWithoutConfig_Errors(t *testing.T) {
	t.Parallel()

	// Load must succeed; LLM validation (including key-config checks) moved to ValidateLLM.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "vertex",
		"CYNATIVE_LLM_MODEL":    "gemini-2.5-pro",
		"CYNATIVE_LLM_API_KEY":  "not-a-vertex-credential",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrKeyConfigRequired) {
		t.Fatalf("ValidateLLM = %v, want ErrKeyConfigRequired", vErr)
	}
}

func TestLoad_AzureKeyWithoutEndpoint_Errors(t *testing.T) {
	t.Parallel()

	// AZURE_OPENAI_API_KEY (the canonical key) forces key synthesis so the guard
	// has a key to inspect; the absent azure_key_config is what must error here.
	// Load must succeed; LLM validation (including key-config checks) moved to ValidateLLM.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "azure",
		"CYNATIVE_LLM_MODEL":    "gpt-4o-prod",
		"AZURE_OPENAI_API_KEY":  "az-canonical",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	if vErr := config.ValidateLLM(&cfg.LLM); !errors.Is(vErr, llm.ErrKeyConfigRequired) {
		t.Fatalf("ValidateLLM = %v, want ErrKeyConfigRequired", vErr)
	}
}

// --- AWS hardening config tests ---

func TestDefaultConfig_populatesAWSDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if got, want := cfg.Connectors.AWS.Policy, "arn:aws:iam::aws:policy/SecurityAudit"; got != want {
		t.Errorf("AWS.Policy = %q, want %q", got, want)
	}
}

func TestDefaultConfig_populatesCacheDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if got, want := cfg.Cache.Dir, "~/.cynative/cache"; got != want {
		t.Errorf("Cache.Dir = %q, want %q", got, want)
	}
	if got, want := cfg.Cache.TTL, 24*time.Hour; got != want {
		t.Errorf("Cache.TTL = %v, want 24h", got)
	}
}

func TestDefaultConfig_populatesGCPDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	// creasty/defaults fills Role from the default tag "roles/viewer"; viper also
	// registers the same value via defaultValueForViper so both paths agree.
	if got := cfg.Connectors.GCP.Role; got != "roles/viewer" {
		t.Errorf("GCP.Role default = %q, want roles/viewer", got)
	}
}

func TestLoad_expandsCacheDirTilde(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	loader := config.NewLoader(envMap(map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"OPENAI_API_KEY":        "sk-test",
	}), config.WithHomeDir(func() (string, error) { return home, nil }))

	cfg, err := loader.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(home, ".cynative", "cache")
	if cfg.Cache.Dir != want {
		t.Errorf("Cache.Dir = %q, want %q", cfg.Cache.Dir, want)
	}
}

func TestLoad_expandsCacheDirTilde_HomeDirError(t *testing.T) {
	t.Parallel()

	// Use an explicit config file (which intentionally omits cache.dir) so Load
	// skips the first homeDir call for config-path resolution. The default
	// cache.dir "~/.cynative/cache" then triggers expandTilde which calls
	// homeDir — and that fails, exercising the cache.dir expansion error branch.
	errHome := errors.New("home unavailable")
	cfgPath := writeConfig(t, `llm:
  provider: openai
  model: gpt-5
  keys:
    - name: k
      value: literal-key
      models: ["*"]
      weight: 1.0
`)
	loader := config.NewLoader(
		envMap(nil),
		config.WithHomeDir(func() (string, error) { return "", errHome }),
	)

	_, err := loader.Load(cfgPath)
	if err == nil {
		t.Fatal("expected error when homeDir fails during cache.dir expansion")
	}
	if !errors.Is(err, errHome) {
		t.Errorf("expected wrapped errHome, got: %v", err)
	}
}

// --- GCP hardening config tests ---

// --- GCP env key tests ---

// --- Azure hardening config tests ---

func TestDefaultConfig_populatesAzureDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	// creasty/defaults fills RoleDefinition from the default tag "Reader"; viper
	// also registers the same value via defaultValueForViper so both paths agree.
	// Pin the element so a tag change is caught immediately.
	if got, want := cfg.Connectors.Azure.RoleDefinition, "Reader"; got != want {
		t.Errorf("Azure.RoleDefinition = %q, want %q", got, want)
	}
}

func TestExpandTilde(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	homeFunc := func() (string, error) { return home, nil }
	errHome := errors.New("no home")
	errHomeFunc := func() (string, error) { return "", errHome }

	tests := []struct {
		name    string
		path    string
		homeDir func() (string, error)
		want    string
		wantErr bool
		errIs   error
	}{
		{
			name:    "empty path returns empty",
			path:    "",
			homeDir: homeFunc,
			want:    "",
		},
		{
			name:    "tilde alone expands to home",
			path:    "~",
			homeDir: homeFunc,
			want:    home,
		},
		{
			name:    "tilde slash expands to home subpath",
			path:    "~/.cynative/cache/aws",
			homeDir: homeFunc,
			want:    filepath.Join(home, ".cynative", "cache", "aws"),
		},
		{
			name:    "tilde-user form is returned unchanged",
			path:    "~user/foo",
			homeDir: homeFunc,
			want:    "~user/foo",
		},
		{
			name:    "absolute path returned unchanged",
			path:    "/absolute/path",
			homeDir: homeFunc,
			want:    "/absolute/path",
		},
		{
			name:    "homeDir error propagates for tilde alone",
			path:    "~",
			homeDir: errHomeFunc,
			wantErr: true,
			errIs:   errHome,
		},
		{
			name:    "homeDir error propagates for tilde-slash",
			path:    "~/foo",
			homeDir: errHomeFunc,
			wantErr: true,
			errIs:   errHome,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := config.ExpandTilde(tc.path, tc.homeDir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got: %v", tc.errIs, err)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoad_appliesCacheConfigFromEnv(t *testing.T) {
	t.Parallel()

	loader := config.NewLoader(envMap(map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"OPENAI_API_KEY":        "sk-test",
		"CYNATIVE_CACHE_DIR":    "/var/cache/cynative",
		"CYNATIVE_CACHE_TTL":    "2h",
	}), config.WithHomeDir(func() (string, error) { return t.TempDir(), nil }))

	cfg, err := loader.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := cfg.Cache.Dir, "/var/cache/cynative"; got != want {
		t.Errorf("Cache.Dir from env = %q, want %q", got, want)
	}
	if got, want := cfg.Cache.TTL, 2*time.Hour; got != want {
		t.Errorf("Cache.TTL from env = %v, want 2h", got)
	}
}

func TestLoad_appliesSandboxMaxConcurrencyFromEnv(t *testing.T) {
	t.Parallel()

	loader := config.NewLoader(envMap(map[string]string{
		"CYNATIVE_LLM_PROVIDER":            "openai",
		"CYNATIVE_LLM_MODEL":               "gpt-5",
		"OPENAI_API_KEY":                   "sk-test",
		"CYNATIVE_SANDBOX_MAX_CONCURRENCY": "33",
	}), config.WithHomeDir(func() (string, error) { return t.TempDir(), nil }))

	cfg, err := loader.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SandboxMaxConcurrency != 33 {
		t.Errorf("SandboxMaxConcurrency from env = %d, want 33", cfg.SandboxMaxConcurrency)
	}
}

// --- GitHub hardening config tests ---

func TestLoad_githubPermissionsDefaultEmpty(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
	}).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Connectors.Github.Permissions) != 0 {
		t.Errorf(
			"default permissions = %v, want empty (baseline applied downstream)",
			cfg.Connectors.Github.Permissions,
		)
	}
}

func TestLoad_githubPermissionsFromYAML(t *testing.T) {
	t.Parallel()

	yaml := validYAML + "connectors:\n  github:\n    permissions:\n      default: read\n      issues: write\n"
	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Connectors.Github.Permissions["issues"] != "write" {
		t.Errorf("issues = %q, want write", cfg.Connectors.Github.Permissions["issues"])
	}
}

func TestLoad_githubPermissionsFromEnv(t *testing.T) {
	t.Parallel()

	// The compact CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS form ("k=v,k2=v2", spaces
	// trimmed) is split into the permissions map by the shared string-map hook.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
		"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": "default=read, issues=write, secret-scanning=none",
	}).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Connectors.Github.Permissions
	if len(p) != 3 || p["default"] != "read" || p["issues"] != "write" || p["secret-scanning"] != "none" {
		t.Errorf("permissions from env = %v, want default=read issues=write secret-scanning=none", p)
	}
}

func TestLoad_githubPermissionsEnvOverridesYAML(t *testing.T) {
	t.Parallel()

	yaml := validYAML + "connectors:\n  github:\n    permissions:\n      default: read\n      issues: read\n"
	cfg, err := config.NewLoader(envMap(map[string]string{
		"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": "issues=write",
	})).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The env value replaces the file map wholesale (it is not merged): only the
	// env-supplied issues:write remains, and the file's default:read is dropped.
	p := cfg.Connectors.Github.Permissions
	if len(p) != 1 || p["issues"] != "write" {
		t.Errorf("permissions = %v, want {issues:write} (env replaces the file map wholesale)", p)
	}
}

func TestLoad_rejectsMalformedGithubPermissionsEnv(t *testing.T) {
	t.Parallel()

	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
		"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": "default=read,nopair",
	}).Load("")
	if err == nil || !strings.Contains(err.Error(), "key=value") {
		t.Fatalf("Load(malformed permissions env) err = %v, want key=value parse error", err)
	}
}

func TestLoad_rejectsBadGithubLevelFromEnv(t *testing.T) {
	t.Parallel()

	// An env value parses structurally but is still validated like the YAML form.
	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
		"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": "issues=admin",
	}).Load("")
	if err == nil || !strings.Contains(err.Error(), "read|write|none") {
		t.Fatalf("Load(bad level from env) err = %v, want level error", err)
	}
}

func TestLoad_blankPermissionsEnvLeavesFileMap(t *testing.T) {
	t.Parallel()

	// An empty or whitespace-only env value is treated as unset, so a configured
	// file map is preserved — a blank env var never silently resets the ceiling.
	yaml := validYAML + "connectors:\n  github:\n    permissions:\n      issues: write\n"
	for _, blank := range []string{"", "   "} {
		cfg, err := config.NewLoader(envMap(map[string]string{
			"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": blank,
		})).Load(writeConfig(t, yaml))
		if err != nil {
			t.Fatalf("Load(blank=%q): %v", blank, err)
		}
		if cfg.Connectors.Github.Permissions["issues"] != "write" {
			t.Errorf("blank env %q wiped the file map: %v", blank, cfg.Connectors.Github.Permissions)
		}
	}
}

func TestLoad_rejectsDuplicatePermissionsEnvKey(t *testing.T) {
	t.Parallel()

	// A duplicate key in the compact env form fails closed rather than silently
	// last-wins (which could widen the ceiling, e.g. issues=none then issues=write).
	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
		"CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS": "issues=none,issues=write",
	}).Load("")
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("Load(duplicate permissions env key) err = %v, want duplicate-key error", err)
	}
}

// mapLeafKeys returns the dotted json-tag paths of every map-kinded leaf reachable
// from t, skipping the top-level llm block (its env keys are resolved separately).
// It independently re-derives the structEnvKeys map surface so the guard test below
// pins exactly which map fields removing the structEnvKeys map-skip exposed to env.
func mapLeafKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for field := range t.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if prefix == "" && name == "llm" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		if field.Type.Kind() == reflect.Struct {
			keys = append(keys, mapLeafKeys(field.Type, key)...)

			continue
		}
		if field.Type.Kind() == reflect.Map {
			keys = append(keys, key)
		}
	}

	return keys
}

func TestEnvBindableMapLeaves_OnlyPermissions(t *testing.T) {
	t.Parallel()

	// Guard: structEnvKeys no longer skips map leaves, so every map[string]string
	// field reachable from a non-llm Config struct is now env-settable via the
	// compact string hook. Today the github and gitlab permissions maps are the only
	// such leaves; pin them so a future map field elsewhere becoming env-widenable is
	// a deliberate, reviewed change (this test must be updated) rather than silent.
	got := mapLeafKeys(reflect.TypeFor[config.Config](), "")
	slices.Sort(got)
	want := []string{"connectors.github.permissions", "connectors.gitlab.permissions"}
	if !slices.Equal(got, want) {
		t.Errorf("env-bindable map leaves = %v, want %v", got, want)
	}
}

// --- GitLab hardening config tests ---

func TestDefaultConfig_populatesGitLabDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if cfg.Connectors.GitLab.Host != "gitlab.com" {
		t.Errorf("GitLab.Host default = %q, want gitlab.com", cfg.Connectors.GitLab.Host)
	}

	if cfg.Connectors.GitLab.AllowPrivateNetwork {
		t.Errorf("GitLab.AllowPrivateNetwork default = true, want false")
	}

	if cfg.Connectors.GitLab.Permissions != nil {
		t.Errorf("GitLab.Permissions default = %+v, want nil (secure baseline)", cfg.Connectors.GitLab.Permissions)
	}
}

func TestLoad_GitLabPermissionsFromYAML(t *testing.T) {
	t.Parallel()

	yaml := validYAML + "connectors:\n  gitlab:\n    permissions:\n      default: read\n      projects: write\n"

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Connectors.GitLab.Permissions["projects"] != "write" {
		t.Errorf("projects = %q, want write", cfg.Connectors.GitLab.Permissions["projects"])
	}
}

func TestLoad_GitLabPermissionsFromEnv(t *testing.T) {
	t.Parallel()

	// The compact CYNATIVE_CONNECTORS_GITLAB_PERMISSIONS form is split into the
	// permissions map by the shared string-map hook, exactly like github's.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai", "CYNATIVE_LLM_MODEL": "gpt-5", "OPENAI_API_KEY": "sk-test",
		"CYNATIVE_CONNECTORS_GITLAB_PERMISSIONS": "default=read, projects=write, ci-variables=none",
	}).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Connectors.GitLab.Permissions
	if len(p) != 3 || p["default"] != "read" || p["projects"] != "write" || p["ci-variables"] != "none" {
		t.Errorf("permissions from env = %v, want default=read projects=write ci-variables=none", p)
	}
}

func TestValidateGitLabHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		field      string
		host       string
		allowEmpty bool
		wantErr    bool
	}{
		{"empty required rejected", "connectors.gitlab.host", "", false, true},
		{"empty optional accepted", "connectors.gitlab.api_host", "", true, false},
		{"valid hostname", "connectors.gitlab.host", "gitlab.com", false, false},
		{"valid self-managed", "connectors.gitlab.host", "gitlab.example.com", false, false},
		{"scheme rejected (https://)", "connectors.gitlab.host", "https://gitlab.com", false, true},
		{"scheme rejected (http://)", "connectors.gitlab.host", "http://x", false, true},
		{"path rejected (slash)", "connectors.gitlab.host", "gitlab.com/foo", false, true},
		{"space rejected", "connectors.gitlab.host", "gitlab.com x", false, true},
		{"host:port accepted", "connectors.gitlab.host", "gitlab.internal:8443", false, false},
		{"host:443 accepted", "connectors.gitlab.host", "gitlab.com:443", false, false},
		{"non-numeric port rejected", "connectors.gitlab.host", "gitlab.internal:abc", false, true},
		{"empty port rejected", "connectors.gitlab.host", "gitlab.internal:", false, true},
		{"zero port rejected", "connectors.gitlab.host", "gitlab.internal:0", false, true},
		{"out-of-range port rejected", "connectors.gitlab.host", "gitlab.internal:99999", false, true},
		{"leading-plus port rejected", "connectors.gitlab.host", "gitlab.internal:+443", false, true},
		{"leading-zero port rejected", "connectors.gitlab.host", "gitlab.internal:08443", false, true},
		{"empty hostname rejected", "connectors.gitlab.host", ":8443", false, true},
		{"multi-colon rejected", "connectors.gitlab.host", "a:b:c", false, true},
		{"non-empty api_host valid", "connectors.gitlab.api_host", "api.gitlab.example.com", true, false},
		{"api_host host:port valid", "connectors.gitlab.api_host", "api.gitlab.internal:8443", true, false},
		{"non-empty bad api_host rejected", "connectors.gitlab.api_host", "https://api.x.com", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := config.ValidateGitLabHost(tc.field, tc.host, tc.allowEmpty)
			if (err != nil) != tc.wantErr {
				t.Fatalf(
					"ValidateGitLabHost(%q, %q, %v) error = %v, wantErr %v",
					tc.field,
					tc.host,
					tc.allowEmpty,
					err,
					tc.wantErr,
				)
			}
		})
	}
}

func TestLoad_GitLabHostSchemeRejected(t *testing.T) {
	t.Parallel()

	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":           "openai",
		"CYNATIVE_LLM_MODEL":              "gpt-5",
		"OPENAI_API_KEY":                  "sk-test",
		"CYNATIVE_CONNECTORS_GITLAB_HOST": "https://gitlab.com/foo",
	}).Load("")
	if err == nil {
		t.Fatal("expected validation error for a host with scheme/path, got nil")
	}

	if !strings.Contains(err.Error(), "connectors.gitlab.host") {
		t.Errorf("error should mention connectors.gitlab.host: %v", err)
	}
}

// --- Kubernetes hardening config tests ---

func TestDefaultConfig_populatesKubernetesDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if cfg.Connectors.Kubernetes.ClusterRole != "view" {
		t.Errorf("Kubernetes.ClusterRole default = %q, want \"view\"", cfg.Connectors.Kubernetes.ClusterRole)
	}
}

func TestLoad_appliesConnectorsAWSPolicyFromNestedYAML(t *testing.T) {
	t.Parallel()

	// The new nested shape binds correctly end-to-end through viper unmarshal.
	yaml := validYAML + "connectors:\n  aws:\n    policy: arn:aws:iam::123456789012:policy/custom\n"

	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := cfg.Connectors.AWS.Policy, "arn:aws:iam::123456789012:policy/custom"; got != want {
		t.Errorf("connectors.aws.policy = %q, want %q", got, want)
	}
}

// TestLoad_ReasoningFromEnv verifies both reasoning keys load from CYNATIVE_*
// env vars, including the string→int coercion for the budget.
func TestLoad_ReasoningFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":             "openai",
		"CYNATIVE_LLM_MODEL":                "gpt-5",
		"CYNATIVE_LLM_REASONING_EFFORT":     "high",
		"CYNATIVE_LLM_REASONING_MAX_TOKENS": "2048",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.ReasoningEffort != "high" || cfg.LLM.ReasoningMaxTokens != 2048 {
		t.Errorf("reasoning = %q/%d, want high/2048", cfg.LLM.ReasoningEffort, cfg.LLM.ReasoningMaxTokens)
	}
}

// TestLoad_ReasoningFromYAML verifies the flat llm: keys unmarshal.
func TestLoad_ReasoningFromYAML(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  reasoning_effort: low
  reasoning_max_tokens: 1024
`
	cfg, err := config.NewLoader(envMap(nil)).Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.ReasoningEffort != "low" || cfg.LLM.ReasoningMaxTokens != 1024 {
		t.Errorf("reasoning = %q/%d, want low/1024", cfg.LLM.ReasoningEffort, cfg.LLM.ReasoningMaxTokens)
	}
}

// TestLoad_ReasoningEnvOverridesFile verifies env precedence over the file.
func TestLoad_ReasoningEnvOverridesFile(t *testing.T) {
	t.Parallel()

	yaml := `llm:
  provider: openai
  model: gpt-5
  reasoning_effort: low
`
	l := config.NewLoader(envMap(map[string]string{"CYNATIVE_LLM_REASONING_EFFORT": "high"}))
	cfg, err := l.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLM.ReasoningEffort != "high" {
		t.Errorf("reasoning_effort = %q, want env override \"high\"", cfg.LLM.ReasoningEffort)
	}
}

// TestLoad_InvalidReasoningEffort verifies ValidateLLM rejects a junk effort level.
func TestLoad_InvalidReasoningEffort(t *testing.T) {
	t.Parallel()

	// Load must succeed; LLM validation (including reasoning checks) moved to ValidateLLM.
	// An API key is required so ValidateKeyPresence does not fire before the
	// reasoning check (ValidateKeyPresence runs before ValidateReasoning).
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":         "openai",
		"CYNATIVE_LLM_MODEL":            "gpt-5",
		"CYNATIVE_LLM_API_KEY":          "sk-placeholder",
		"CYNATIVE_LLM_REASONING_EFFORT": "maximal",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	vErr := config.ValidateLLM(&cfg.LLM)
	if !errors.Is(vErr, llm.ErrInvalidReasoningEffort) {
		t.Errorf("ValidateLLM = %v, want ErrInvalidReasoningEffort", vErr)
	}
	// The operator-facing message must name the key and the valid values.
	if vErr == nil || !strings.Contains(vErr.Error(), "one of: none, minimal, low, medium, high") {
		t.Errorf("expected the valid effort levels in the message, got: %v", vErr)
	}
}

// TestLoad_ReasoningConflict verifies ValidateLLM rejects effort "none" combined
// with an explicit token budget.
func TestLoad_ReasoningConflict(t *testing.T) {
	t.Parallel()

	// Load must succeed; LLM validation (including reasoning checks) moved to ValidateLLM.
	// An API key is required so ValidateKeyPresence does not fire before the
	// reasoning check (ValidateKeyPresence runs before ValidateReasoning).
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":             "openai",
		"CYNATIVE_LLM_MODEL":                "gpt-5",
		"CYNATIVE_LLM_API_KEY":              "sk-placeholder",
		"CYNATIVE_LLM_REASONING_EFFORT":     "none",
		"CYNATIVE_LLM_REASONING_MAX_TOKENS": "1024",
	}).Load("")
	if err != nil {
		t.Fatalf("Load should succeed; LLM validation moved to ValidateLLM: %v", err)
	}

	vErr := config.ValidateLLM(&cfg.LLM)
	if !errors.Is(vErr, llm.ErrReasoningConflict) {
		t.Errorf("ValidateLLM = %v, want ErrReasoningConflict", vErr)
	}
	// The operator-facing message must explain the conflict.
	if vErr == nil || !strings.Contains(vErr.Error(), "conflicts with llm.reasoning_max_tokens") {
		t.Errorf("expected the conflict explanation in the message, got: %v", vErr)
	}
}

func TestLoad_BudgetFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":     "openai",
		"CYNATIVE_LLM_MODEL":        "gpt-5",
		"CYNATIVE_LLM_API_KEY":      "sk",
		"CYNATIVE_MAX_TOTAL_TOKENS": "5000",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MaxTotalTokens != 5000 {
		t.Errorf("max_total_tokens = %d, want 5000", cfg.MaxTotalTokens)
	}
}

func TestLoad_NegativeBudgetRejected(t *testing.T) {
	t.Parallel()

	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":     "openai",
		"CYNATIVE_LLM_MODEL":        "gpt-5",
		"CYNATIVE_LLM_API_KEY":      "sk",
		"CYNATIVE_MAX_TOTAL_TOKENS": "-1",
	}).Load("")
	if err == nil {
		t.Fatal("expected a validation error for negative max_total_tokens")
	}
	if !strings.Contains(err.Error(), "max_total_tokens") {
		t.Errorf("error = %v, want it to mention max_total_tokens", err)
	}
}

func TestLoad_MaxConsecutiveFailures_DefaultAndEnv(t *testing.T) {
	t.Parallel()

	// Default when unset: expect 5.
	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"CYNATIVE_LLM_API_KEY":  "sk",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MaxConsecutiveFailures != 5 {
		t.Errorf("default = %d, want 5", cfg.MaxConsecutiveFailures)
	}

	// Env override.
	cfgEnv, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":             "openai",
		"CYNATIVE_LLM_MODEL":                "gpt-5",
		"CYNATIVE_LLM_API_KEY":              "sk",
		"CYNATIVE_MAX_CONSECUTIVE_FAILURES": "3",
	}).Load("")
	if err != nil {
		t.Fatalf("unexpected error with env override: %v", err)
	}

	if cfgEnv.MaxConsecutiveFailures != 3 {
		t.Errorf("env override = %d, want 3", cfgEnv.MaxConsecutiveFailures)
	}
}

func TestLoad_MaxConsecutiveFailures_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":             "openai",
		"CYNATIVE_LLM_MODEL":                "gpt-5",
		"CYNATIVE_LLM_API_KEY":              "sk",
		"CYNATIVE_MAX_CONSECUTIVE_FAILURES": "-1",
	}).Load("")
	if err == nil {
		t.Fatalf("negative max_consecutive_failures must be rejected")
	}

	if !strings.Contains(err.Error(), "max_consecutive_failures") {
		t.Errorf("error = %v, want it to mention max_consecutive_failures", err)
	}
}

func TestValidateClusterRoleName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"empty rejected", "", true},
		{"builtin view", "view", false},
		{"builtin edit", "edit", false},
		{"builtin admin", "admin", false},
		{"cluster-admin", "cluster-admin", false},
		{"system aggregate", "system:aggregate-to-view", false},
		{"custom dotted", "custom.read-only", false},
		{"slash rejected", "a/b", true},
		{"percent rejected", "a%b", true},
		{"dot rejected", ".", true},
		{"dotdot rejected", "..", true},
		{"space rejected", "a b", true},
		{"tab rejected", "a\tb", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := config.ValidateClusterRoleName("connectors.eks.cluster_role", tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateClusterRoleName(%q) error = %v, wantErr %v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestLoad_appliesK8sClusterRoleFromEnv(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":                       "openai",
		"CYNATIVE_LLM_MODEL":                          "gpt-5",
		"OPENAI_API_KEY":                              "sk-test",
		"CYNATIVE_CONNECTORS_EKS_CLUSTER_ROLE":        "eks-reader",
		"CYNATIVE_CONNECTORS_GKE_CLUSTER_ROLE":        "gke-reader",
		"CYNATIVE_CONNECTORS_AKS_CLUSTER_ROLE":        "aks-reader",
		"CYNATIVE_CONNECTORS_KUBERNETES_CLUSTER_ROLE": "k8s-reader",
	}).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Connectors.EKS.ClusterRole != "eks-reader" ||
		cfg.Connectors.GKE.ClusterRole != "gke-reader" ||
		cfg.Connectors.AKS.ClusterRole != "aks-reader" ||
		cfg.Connectors.Kubernetes.ClusterRole != "k8s-reader" {
		t.Fatalf("cluster_role env not applied: %+v", cfg.Connectors)
	}
}

// --- Consolidated per-connector Load tests (table-driven) ---

// baseLLMEnv is the minimal env that makes Load succeed: an openai provider/model
// plus its canonical API key, with no connector overrides.
func baseLLMEnv() map[string]string {
	return map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"OPENAI_API_KEY":        "sk-test",
	}
}

// TestLoad_ConnectorScalarDefaults pins every per-connector scalar default that a
// bare Load (base LLM env, no connector override) must apply.
func TestLoad_ConnectorScalarDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, baseLLMEnv()).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"aws.policy", cfg.Connectors.AWS.Policy, "arn:aws:iam::aws:policy/SecurityAudit"},
		{"cache.ttl", cfg.Cache.TTL.String(), (24 * time.Hour).String()},
		{"gcp.role", cfg.Connectors.GCP.Role, "roles/viewer"},
		{"azure.cloud", cfg.Connectors.Azure.Cloud, "auto"},
		{"gitlab.host", cfg.Connectors.GitLab.Host, "gitlab.com"},
		{"eks.cluster_role", cfg.Connectors.EKS.ClusterRole, "view"},
		{"gke.cluster_role", cfg.Connectors.GKE.ClusterRole, "view"},
		{"aks.cluster_role", cfg.Connectors.AKS.ClusterRole, "view"},
		{"kubernetes.cluster_role", cfg.Connectors.Kubernetes.ClusterRole, "view"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("%s default = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}

	// Non-scalar GitLab defaults: private network off and a nil (secure-baseline)
	// permissions map when the connector block is omitted.
	if cfg.Connectors.GitLab.AllowPrivateNetwork {
		t.Error("GitLab.AllowPrivateNetwork default = true, want false")
	}
	if cfg.Connectors.GitLab.Permissions != nil {
		t.Errorf("GitLab.Permissions default = %+v, want nil (secure baseline)", cfg.Connectors.GitLab.Permissions)
	}
}

// TestLoad_ConnectorScalarFromEnv pins that each per-connector scalar binds from
// its CYNATIVE_CONNECTORS_* env var (acceptance paths only; rejects live below).
func TestLoad_ConnectorScalarFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		envKey string
		envVal string
		get    func(config.Config) string
		want   string
	}{
		{
			"aws.policy", "CYNATIVE_CONNECTORS_AWS_POLICY", "arn:aws:iam::123456789012:policy/custom",
			func(c config.Config) string { return c.Connectors.AWS.Policy }, "arn:aws:iam::123456789012:policy/custom",
		},
		{
			"gcp.role predefined", "CYNATIVE_CONNECTORS_GCP_ROLE", "roles/iam.securityReviewer",
			func(c config.Config) string { return c.Connectors.GCP.Role }, "roles/iam.securityReviewer",
		},
		{
			// A custom project-scoped role is also accepted (validateGCPRole custom path).
			"gcp.role custom", "CYNATIVE_CONNECTORS_GCP_ROLE", "projects/my-proj/roles/cynativeReadonly",
			func(c config.Config) string { return c.Connectors.GCP.Role }, "projects/my-proj/roles/cynativeReadonly",
		},
		{
			"azure.role_definition", "CYNATIVE_CONNECTORS_AZURE_ROLE_DEFINITION", "Security Reader",
			func(c config.Config) string { return c.Connectors.Azure.RoleDefinition }, "Security Reader",
		},
		{
			"azure.cloud", "CYNATIVE_CONNECTORS_AZURE_CLOUD", "AzureUSGovernment",
			func(c config.Config) string { return c.Connectors.Azure.Cloud }, "AzureUSGovernment",
		},
		{
			"gitlab.host", "CYNATIVE_CONNECTORS_GITLAB_HOST", "gitlab.example.com",
			func(c config.Config) string { return c.Connectors.GitLab.Host }, "gitlab.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := baseLLMEnv()
			env[tc.envKey] = tc.envVal
			cfg, err := loaderEnv(t, env).Load("")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := tc.get(cfg); got != tc.want {
				t.Errorf("%s from env = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestLoad_ConnectorEnvRejects pins that a bad CYNATIVE_CONNECTORS_* value fails
// Load with an error naming the field.
func TestLoad_ConnectorEnvRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		envKey   string
		envVal   string
		wantSubs string
	}{
		{"aws.policy not an ARN", "CYNATIVE_CONNECTORS_AWS_POLICY", "not-an-arn", "connectors.aws.policy"},
		{
			"gcp.role not a role", "CYNATIVE_CONNECTORS_GCP_ROLE", "not-a-role",
			"connectors.gcp.role must be a predefined role",
		},
		{"azure.cloud unknown", "CYNATIVE_CONNECTORS_AZURE_CLOUD", "Mars", "connectors.azure.cloud"},
		{"eks unsafe role", "CYNATIVE_CONNECTORS_EKS_CLUSTER_ROLE", "bad/role", "connectors.eks.cluster_role"},
		{"gke unsafe role", "CYNATIVE_CONNECTORS_GKE_CLUSTER_ROLE", "bad/role", "connectors.gke.cluster_role"},
		{"aks unsafe role", "CYNATIVE_CONNECTORS_AKS_CLUSTER_ROLE", "bad/role", "connectors.aks.cluster_role"},
		{
			"kubernetes unsafe role", "CYNATIVE_CONNECTORS_KUBERNETES_CLUSTER_ROLE", "bad/role",
			"connectors.kubernetes.cluster_role",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := baseLLMEnv()
			env[tc.envKey] = tc.envVal
			_, err := loaderEnv(t, env).Load("")
			if err == nil || !strings.Contains(err.Error(), tc.wantSubs) {
				t.Fatalf("Load(%s=%q) err = %v, want error containing %q", tc.envKey, tc.envVal, err, tc.wantSubs)
			}
		})
	}
}

// TestLoad_ConnectorYAMLRejects pins that a bad connector value in the config file
// fails Load with the field-friendly error. The YAML form (not env) exercises the
// validator/errmsg path: e.g. an explicit empty azure.role_definition overrides the
// default and must surface the `required` errmsg via errMsgFromType, and an empty
// cluster_role is rejected by validateClusterRoleName naming the field.
func TestLoad_ConnectorYAMLRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		yaml     string
		wantSubs string
	}{
		{
			"azure empty role_definition",
			validYAML + "connectors:\n  azure:\n    role_definition: \"\"\n",
			"connectors.azure.role_definition must be an Azure RBAC role name",
		},
		{
			"github bad level",
			validYAML + "connectors:\n  github:\n    permissions:\n      issues: admin\n",
			"read|write|none",
		},
		{
			"github malformed key",
			validYAML + "connectors:\n  github:\n    permissions:\n      \"Bad Key\": read\n",
			"is malformed",
		},
		{
			"gitlab bad level",
			validYAML + "connectors:\n  gitlab:\n    permissions:\n      projects: admin\n",
			"read|write|none",
		},
		{
			"gitlab malformed key",
			validYAML + "connectors:\n  gitlab:\n    permissions:\n      \"Bad Key\": read\n",
			"is malformed",
		},
		{
			"gitlab bad api_host",
			validYAML + "connectors:\n  gitlab:\n    api_host: \"https://api.gitlab.example.com/v4\"\n",
			"connectors.gitlab.api_host",
		},
		{
			"eks empty cluster_role",
			"llm:\n  provider: openai\n  model: gpt-5\nconnectors:\n  eks:\n    cluster_role: \"\"\n",
			"connectors.eks.cluster_role",
		},
		{
			"gke empty cluster_role",
			"llm:\n  provider: openai\n  model: gpt-5\nconnectors:\n  gke:\n    cluster_role: \"\"\n",
			"connectors.gke.cluster_role",
		},
		{
			"aks empty cluster_role",
			"llm:\n  provider: openai\n  model: gpt-5\nconnectors:\n  aks:\n    cluster_role: \"\"\n",
			"connectors.aks.cluster_role",
		},
		{
			"kubernetes empty cluster_role",
			"llm:\n  provider: openai\n  model: gpt-5\nconnectors:\n  kubernetes:\n    cluster_role: \"\"\n",
			"connectors.kubernetes.cluster_role",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := loaderEnv(t, map[string]string{"OPENAI_API_KEY": "sk-test"}).Load(writeConfig(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantSubs) {
				t.Fatalf("Load(%s) err = %v, want error containing %q", tc.name, err, tc.wantSubs)
			}
		})
	}
}
