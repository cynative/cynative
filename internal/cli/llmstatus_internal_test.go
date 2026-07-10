package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/ui"
)

func cfgWith(provider, model string) config.Config {
	c := validCfg()
	c.LLM.Provider = provider
	c.LLM.Model = model

	return c
}

func TestLLMConfigStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cfg           config.Config
		err           error
		notConfigured bool
		wantState     ui.ConnectorState
	}{
		{
			"provider missing → onboarding",
			cfgWith("", ""), config.ErrLLMProviderMissing, true, ui.ConnectorError,
		},
		{
			"model missing → fix",
			cfgWith("openai", ""), config.ErrLLMModelMissing, false, ui.ConnectorError,
		},
		{
			"unknown provider → fix",
			cfgWith("nope", "x"), llm.ErrUnknownProvider, false, ui.ConnectorError,
		},
		{
			"key unset → fix",
			cfgWith("openai", "gpt-5.5"), llm.ErrEnvVarUnset, false, ui.ConnectorError,
		},
		{
			"reasoning effort → reasoning fix",
			cfgWith("openai", "gpt-5.5"), llm.ErrInvalidReasoningEffort, false, ui.ConnectorError,
		},
		{
			"reasoning max tokens → reasoning fix",
			cfgWith("openai", "gpt-5.5"), llm.ErrInvalidReasoningMaxTokens, false, ui.ConnectorError,
		},
		{
			"reasoning conflict → reasoning fix",
			cfgWith("openai", "gpt-5.5"), llm.ErrReasoningConflict, false, ui.ConnectorError,
		},
		{
			"no keys for provider → API key not set",
			cfgWith("openai", "gpt-5.5"), llm.ErrNoKeysForProvider, false, ui.ConnectorError,
		},
		{
			"generic default (key config) → generic fix",
			cfgWith("azure", "gpt-5.5"), llm.ErrKeyConfigRequired, false, ui.ConnectorError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := llmConfigStatus(tt.cfg, tt.err)
			if s.NotConfigured != tt.notConfigured {
				t.Errorf("NotConfigured = %v, want %v", s.NotConfigured, tt.notConfigured)
			}
			if tt.notConfigured && len(s.Example) == 0 {
				t.Error("onboarding status must carry the README Example lines")
			}
			if !tt.notConfigured && s.State != tt.wantState {
				t.Errorf("State = %v, want %v", s.State, tt.wantState)
			}
			if !tt.notConfigured && s.Hint == "" {
				t.Error("a structural-fix status must carry a hint")
			}
			// SECURITY: the raw error string must never appear in a rendered hint.
			if strings.Contains(s.Hint, tt.err.Error()) {
				t.Errorf("raw error string leaked into hint: %q", s.Hint)
			}
		})
	}
}

func TestLLMConfigStatus_ReasoningHints(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("openai", "gpt-5.5")
	for _, err := range []error{
		llm.ErrInvalidReasoningEffort,
		llm.ErrInvalidReasoningMaxTokens,
		llm.ErrReasoningConflict,
	} {
		s := llmConfigStatus(cfg, err)
		if s.State != ui.ConnectorError {
			t.Errorf("err=%v: State = %v, want ConnectorError", err, s.State)
		}
		if s.Reason != "invalid reasoning config" {
			t.Errorf("err=%v: Reason = %q, want 'invalid reasoning config'", err, s.Reason)
		}
		if s.Hint == "" {
			t.Errorf("err=%v: Hint must be non-empty", err)
		}
	}
}

func TestLLMConfigStatus_GenericDefault_NoRawError(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("azure", "gpt-5.5")
	s := llmConfigStatus(cfg, llm.ErrKeyConfigRequired)
	if s.State != ui.ConnectorError {
		t.Errorf("State = %v, want ConnectorError", s.State)
	}
	if s.Reason != "invalid LLM configuration" {
		t.Errorf("Reason = %q, want 'invalid LLM configuration'", s.Reason)
	}
	if strings.Contains(s.Hint, llm.ErrKeyConfigRequired.Error()) {
		t.Errorf("raw error string must NOT appear in hint: %q", s.Hint)
	}
	if s.Hint == "" {
		t.Error("generic default must carry a hint")
	}
}

func TestLLMRuntimeStatus(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("anthropic", "claude-opus-4-8")
	const secret = "sk-ant-LEAKED-SECRET-VALUE"

	tests := []struct {
		name    string
		err     error
		wantSub string
	}{
		{
			"401 → invalid credentials",
			&llm.GenerateError{StatusCode: 401, Message: secret}, //nolint:exhaustruct // Code unused.
			"invalid credentials",
		},
		{
			"404 → model not found",
			&llm.GenerateError{StatusCode: 404, Message: secret}, //nolint:exhaustruct // Code unused.
			"model",
		},
		{
			"429 → rate/quota",
			&llm.GenerateError{StatusCode: 429, Message: secret}, //nolint:exhaustruct // Code unused.
			"quota",
		},
		{
			"500 → request failed",
			&llm.GenerateError{StatusCode: 500, Message: secret}, //nolint:exhaustruct // Code unused.
			"request failed",
		},
		{
			// With retries on, Bifrost collapses a permanent per-key 401/402/403
			// into a synthetic 502 typed upstream_credentials_exhausted (the
			// literal wire value, duplicated here on purpose as a drift pin).
			"credentials-exhausted 502 → credential guidance",
			//nolint:exhaustruct // Code unused.
			&llm.GenerateError{StatusCode: 502, Type: "upstream_credentials_exhausted", Message: secret},
			"invalid credentials or billing",
		},
		{
			"plain 502 without the machine type → request failed",
			&llm.GenerateError{StatusCode: 502, Message: secret}, //nolint:exhaustruct // Code/Type unused.
			"request failed",
		},
		{
			"no status → could not reach",
			&llm.GenerateError{StatusCode: 0, Message: secret}, //nolint:exhaustruct // Code unused.
			"could not reach",
		},
		{
			"non-GenerateError (init) → could not reach",
			errors.New("bifrost init: " + secret),
			"could not reach",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := llmRuntimeStatus(cfg, tt.err)
			if s.State != ui.ConnectorError || s.Provider != "anthropic" || s.Model != "claude-opus-4-8" {
				t.Errorf("status header wrong: %#v", s)
			}
			if !strings.Contains(s.Reason, tt.wantSub) {
				t.Errorf("Reason %q should contain %q", s.Reason, tt.wantSub)
			}
			// SECURITY: the raw provider/init message must NEVER reach the status.
			if strings.Contains(s.Reason, "LEAKED") || strings.Contains(s.Hint, "LEAKED") {
				t.Errorf("raw message leaked into status: reason=%q hint=%q", s.Reason, s.Hint)
			}
		})
	}
}

func TestLLMOKStatus(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("openai", "gpt-5")
	s := llmOKStatus(cfg)

	if s.State != ui.ConnectorOK {
		t.Errorf("State = %v, want ConnectorOK", s.State)
	}
	if s.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", s.Provider, "openai")
	}
	if s.Model != "gpt-5" {
		t.Errorf("Model = %q, want %q", s.Model, "gpt-5")
	}
	if s.Reason != "" || s.Hint != "" || s.NotConfigured {
		t.Errorf("OK status must have empty Reason/Hint and NotConfigured=false: %#v", s)
	}
}

// TestLLMConfigStatus_NoKeysForProvider verifies that ErrNoKeysForProvider is
// classified as a Tier-2 "no credentials configured" status whose hint covers both
// the API-key and the provider-config (keyless) setups and references docs.
func TestLLMConfigStatus_NoKeysForProvider(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("openai", "gpt-5.5")
	s := llmConfigStatus(cfg, llm.ErrNoKeysForProvider)

	if s.NotConfigured {
		t.Error("NotConfigured must be false for a no-credentials error")
	}
	if s.State != ui.ConnectorError {
		t.Errorf("State = %v, want ConnectorError", s.State)
	}
	if !strings.Contains(strings.ToLower(s.Reason), "credentials") {
		t.Errorf("Reason must mention missing credentials, got %q", s.Reason)
	}
	if !strings.Contains(strings.ToLower(s.Hint), "api key") {
		t.Errorf("Hint should mention the API-key option, got %q", s.Hint)
	}
	// The hint must also cover the keyless/provider-config setup (e.g. an Ollama URL),
	// not just an API key — ErrNoKeysForProvider now fires for keyless providers too.
	if !strings.Contains(strings.ToLower(s.Hint), "config") {
		t.Errorf("Hint should mention the provider-config option, got %q", s.Hint)
	}
	if !strings.Contains(s.Hint, "docs/providers") {
		t.Errorf("Hint must reference docs/providers, got %q", s.Hint)
	}
	// SECURITY: the raw error string must never appear in the hint.
	if strings.Contains(s.Hint, llm.ErrNoKeysForProvider.Error()) {
		t.Errorf("raw error string must NOT appear in hint: %q", s.Hint)
	}
}

// TestLLMConfigStatus_EnvVarUnset_NamedInHint verifies that when an env var is
// unset the reason is generic ("required env var not set") and the hint names
// the exact variable rather than generic "API key".
func TestLLMConfigStatus_EnvVarUnset_NamedInHint(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("azure", "gpt-5.5")
	err := fmt.Errorf("%w: %s", llm.ErrEnvVarUnset, "AZURE_CLIENT_ID")
	s := llmConfigStatus(cfg, err)

	if s.State != ui.ConnectorError {
		t.Errorf("State = %v, want ConnectorError", s.State)
	}
	if s.Reason != "required env var not set" {
		t.Errorf("Reason = %q, want \"required env var not set\"", s.Reason)
	}
	if !strings.Contains(s.Hint, "AZURE_CLIENT_ID") {
		t.Errorf("Hint must name the specific env var AZURE_CLIENT_ID, got %q", s.Hint)
	}
	// SECURITY: the raw error string must not appear in the hint.
	if strings.Contains(s.Hint, err.Error()) {
		t.Errorf("raw error string must NOT be in hint: %q", s.Hint)
	}
}

// TestLLMConfigStatus_EnvVarUnset_NotAPIKey verifies that the hint does NOT
// say "API key" when the unset var is not an API key (e.g. a client ID).
func TestLLMConfigStatus_EnvVarUnset_NotAPIKey(t *testing.T) {
	t.Parallel()

	cfg := cfgWith("azure", "gpt-5.5")
	err := fmt.Errorf("%w: %s", llm.ErrEnvVarUnset, "AZURE_CLIENT_ID")
	s := llmConfigStatus(cfg, err)

	if strings.Contains(strings.ToLower(s.Reason), "api key") {
		t.Errorf("Reason must not say \"API key\" for a non-key env var, got %q", s.Reason)
	}
	if strings.Contains(strings.ToLower(s.Hint), "api key") {
		t.Errorf("Hint must not say \"API key\" for a non-key env var, got %q", s.Hint)
	}
}
