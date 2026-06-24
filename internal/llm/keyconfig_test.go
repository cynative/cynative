package llm_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// keyWithConfig builds a schemas.Key and applies set (if non-nil). Using a var
// (not a composite literal) keeps exhaustruct quiet without per-field noise.
func keyWithConfig(set func(*schemas.Key)) schemas.Key {
	var k schemas.Key
	if set != nil {
		set(&k)
	}
	return k
}

func TestValidateKeyConfigs(t *testing.T) {
	t.Parallel()

	// Non-nil configs; only presence matters to the guard, so zero values are fine.
	var (
		azureCfg  schemas.AzureKeyConfig
		vertexCfg schemas.VertexKeyConfig
	)

	cases := []struct {
		name     string
		provider string
		keys     []schemas.Key
		wantErr  bool
	}{
		{"azure_missing_config", "azure", []schemas.Key{keyWithConfig(nil)}, true},
		{
			"azure_with_config",
			"azure",
			[]schemas.Key{keyWithConfig(func(k *schemas.Key) { k.AzureKeyConfig = &azureCfg })},
			false,
		},
		{"vertex_missing_config", "vertex", []schemas.Key{keyWithConfig(nil)}, true},
		{
			"vertex_with_config_iam",
			"vertex",
			[]schemas.Key{keyWithConfig(func(k *schemas.Key) { k.VertexKeyConfig = &vertexCfg })},
			false,
		},
		{"bedrock_optional_config_nil_ok", "bedrock", []schemas.Key{keyWithConfig(nil)}, false},
		{"openai_no_config_field", "openai", []schemas.Key{keyWithConfig(nil)}, false},
		{
			"azure_second_key_missing_config",
			"azure",
			[]schemas.Key{
				keyWithConfig(func(k *schemas.Key) { k.AzureKeyConfig = &azureCfg }),
				keyWithConfig(nil),
			},
			true,
		},
		{
			"azure_all_keys_with_config",
			"azure",
			[]schemas.Key{
				keyWithConfig(func(k *schemas.Key) { k.AzureKeyConfig = &azureCfg }),
				keyWithConfig(func(k *schemas.Key) { k.AzureKeyConfig = &azureCfg }),
			},
			false,
		},
		{"required_provider_zero_keys_vertex", "vertex", nil, true},
		{"required_provider_zero_keys_azure", "azure", nil, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			entry := &llm.ProviderEntry{ //nolint:exhaustruct // only Provider and Keys matter here
				Provider: c.provider,
				Keys:     c.keys,
			}
			err := llm.ValidateKeyConfigs(entry)
			if c.wantErr {
				if !errors.Is(err, llm.ErrKeyConfigRequired) {
					t.Errorf("got %v, want ErrKeyConfigRequired", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateKeyConfigs_ErrorMentionsDocs(t *testing.T) {
	t.Parallel()
	entry := &llm.ProviderEntry{ //nolint:exhaustruct // only Provider and Keys matter here
		Provider: "vertex",
		Keys:     []schemas.Key{keyWithConfig(nil)},
	}
	err := llm.ValidateKeyConfigs(entry)
	if err == nil || !strings.Contains(err.Error(), "docs/providers/vertex.md") {
		t.Errorf("want error mentioning docs/providers/vertex.md, got: %v", err)
	}
}

func TestValidateKeyConfigs_NilEntry(t *testing.T) {
	t.Parallel()
	if err := llm.ValidateKeyConfigs(nil); err != nil {
		t.Errorf("nil entry: got %v, want nil", err)
	}
}

func TestValidateKeyPresence(t *testing.T) {
	t.Parallel()

	// baseURLEntry builds a ProviderEntry with the given provider, model, and a
	// non-empty NetworkConfig.BaseURL (a local/proxy endpoint). base_url does NOT
	// exempt the key requirement — FileAccount still needs at least one key entry.
	baseURLEntry := func(provider, model string) *llm.ProviderEntry {
		var e llm.ProviderEntry //nolint:exhaustruct // setting only the fields under test
		e.Provider = provider
		e.Model = model
		e.NetworkConfig.BaseURL = "http://localhost:11434"
		return &e
	}

	tests := []struct {
		name    string
		entry   *llm.ProviderEntry
		wantErr error
	}{
		{
			"openai no key no base_url → ErrNoKeysForProvider",
			&llm.ProviderEntry{Provider: "openai", Model: "gpt-5.5"}, //nolint:exhaustruct // only Provider matters here
			llm.ErrNoKeysForProvider,
		},
		{
			// base_url does NOT exempt the key requirement: FileAccount rejects an
			// empty Keys slice even with a base_url, so a local/proxy user must still
			// provide a (possibly dummy) key.
			"openai base_url but no key entry → ErrNoKeysForProvider",
			baseURLEntry("openai", "gpt-5.5"),
			llm.ErrNoKeysForProvider,
		},
		{
			"openai with a key value → nil",
			&llm.ProviderEntry{ //nolint:exhaustruct // testing key presence
				Provider: "openai",
				Model:    "gpt-5.5",
				Keys: []schemas.Key{keyWithConfig(func(k *schemas.Key) {
					k.Value = schemas.EnvVar{Val: "sk-test", FromEnv: false, EnvVar: ""}
				})},
			},
			nil,
		},
		{
			// A key ENTRY synthesized from a hoisted config block (e.g. an Azure
			// endpoint / service-principal) carries an empty Value but is a VALID
			// credential (bearer-token auth). It must NOT be flagged — only a wholly
			// absent key entry is.
			"azure endpoint key with empty value → nil (service-principal auth)",
			&llm.ProviderEntry{ //nolint:exhaustruct // empty-value key entry path
				Provider: "azure",
				Model:    "gpt-4o-deploy",
				Keys:     []schemas.Key{keyWithConfig(nil)},
			},
			nil,
		},
		{
			// Even keyless providers need a key ENTRY: FileAccount rejects an empty
			// Keys slice for every provider, so ollama/vllm/bedrock with no config
			// (no synthesized key) is unrunnable and must be flagged up front.
			"ollama with no config (no key entry) → ErrNoKeysForProvider",
			&llm.ProviderEntry{Provider: "ollama", Model: "llama3.3"}, //nolint:exhaustruct // no config at all
			llm.ErrNoKeysForProvider,
		},
		{
			"bedrock with a key entry → nil",
			&llm.ProviderEntry{ //nolint:exhaustruct // has a materialized key entry
				Provider: "bedrock",
				Model:    "claude-3",
				Keys:     []schemas.Key{keyWithConfig(nil)},
			},
			nil,
		},
		{
			"nil entry → nil",
			nil,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := llm.ValidateKeyPresence(tt.entry)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateKeyPresence_BaseURLStillNeedsKey verifies that a base_url override
// does NOT exempt the key requirement: FileAccount.GetKeysForProvider rejects an
// empty Keys slice regardless of base_url, so a key-requiring provider with no key
// entry is flagged even when a custom endpoint is set.
func TestValidateKeyPresence_BaseURLStillNeedsKey(t *testing.T) {
	t.Parallel()

	var entry llm.ProviderEntry //nolint:exhaustruct // setting fields individually for clarity
	entry.Provider = "openai"
	entry.Model = "gpt-5.5"
	entry.NetworkConfig.BaseURL = "http://localhost:11434"

	if err := llm.ValidateKeyPresence(&entry); !errors.Is(err, llm.ErrNoKeysForProvider) {
		t.Errorf("base_url with no key entry must still be flagged, got %v", err)
	}
}
