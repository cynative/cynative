package cli

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	cynative "github.com/cynative/cynative"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/ui"
)

// llmOKStatus is the ✓ "validated" status for the configured provider/model.
func llmOKStatus(cfg config.Config) ui.LLMStatus {
	return ui.LLMStatus{ //nolint:exhaustruct // OK line: no reason/hint/onboarding fields needed.
		State:    ui.ConnectorOK,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
	}
}

// llmConfigStatus maps a config.ValidateLLM error to a Tier-1 onboarding block
// (no provider) or a Tier-2 ✗ fix line (provider set but otherwise invalid).
func llmConfigStatus(cfg config.Config, err error) ui.LLMStatus {
	if errors.Is(err, config.ErrLLMProviderMissing) {
		return ui.LLMStatus{ //nolint:exhaustruct // onboarding block: State/Provider/Model/Reason/Hint unused.
			NotConfigured: true,
			Example:       cynative.QuickstartExample(),
		}
	}

	s := ui.LLMStatus{ //nolint:exhaustruct // Reason/Hint/NotConfigured/Example set per branch below.
		State:    ui.ConnectorError,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
	}
	switch {
	case errors.Is(err, config.ErrLLMModelMissing):
		s.Model = ""
		s.Reason = "model not set"
		s.Hint = "Set CYNATIVE_LLM_MODEL (or 'llm.model' in ~/.cynative/config.yaml)."
	case errors.Is(err, llm.ErrUnknownProvider):
		s.Reason = "unknown provider"
		s.Hint = "Not a supported provider. See docs/providers/README.md."
	case errors.Is(err, llm.ErrNoKeysForProvider):
		s.Reason = "no credentials configured"
		s.Hint = "Set this provider's API key (CYNATIVE_LLM_API_KEY / llm.api_key) or its required " +
			"config (e.g. CYNATIVE_LLM_OLLAMA_URL for local providers). See docs/providers/README.md."
	case errors.Is(err, llm.ErrEnvVarUnset):
		s.Reason = "required env var not set"
		// Extract the variable name from the wrapped error message. If the error
		// carries no suffix (bare sentinel, e.g. from tests), fall back to the
		// generic docs pointer rather than leaking the sentinel text.
		if name, ok := strings.CutPrefix(err.Error(), llm.ErrEnvVarUnset.Error()+": "); ok {
			s.Hint = "Set " + name + " (see docs/providers/README.md for this provider's setup)."
		} else {
			s.Hint = "Set the required env var (see docs/providers/README.md for this provider's setup)."
		}
	case errors.Is(err, llm.ErrInvalidReasoningEffort),
		errors.Is(err, llm.ErrInvalidReasoningMaxTokens),
		errors.Is(err, llm.ErrReasoningConflict):
		s.Reason = "invalid reasoning config"
		s.Hint = "Check llm.reasoning_effort / llm.reasoning_max_tokens. See docs/providers/README.md."
	default:
		s.Reason = "invalid LLM configuration"
		s.Hint = "Check your llm.* settings. See docs/providers/README.md."
	}

	return s
}

// llmRuntimeStatus maps a first-interaction failure to a Tier-3 ✗ status. The
// reason/hint are built ONLY from the GenerateError's StatusCode plus an
// equality match on its machine Type, NEVER the raw provider/init message,
// which can echo a credential AND (for a chat-model-init error) has not passed
// through RedactingChatModel. The message survives only in err.Error() for
// -v / the turn-≥2 %v path, where it is redacted at the RedactingChatModel
// boundary. Every first-interaction failure aborts regardless, so the label is
// a generic, NON-per-provider bucket.
func llmRuntimeStatus(cfg config.Config, err error) ui.LLMStatus {
	s := ui.LLMStatus{ //nolint:exhaustruct // Reason/Hint/NotConfigured/Example set per branch below.
		State:    ui.ConnectorError,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
	}

	status := 0
	if ge, ok := errors.AsType[*llm.GenerateError](err); ok {
		status = ge.StatusCode
		// With retries enabled (max_retries defaults to 3), Bifrost collapses a
		// permanent per-key 401/402/403 into a synthetic 502 once every
		// configured key is dead, so the status code alone would render the
		// generic "request failed" bucket for a plain bad key or billing
		// failure. Restore the credential guidance from the machine Type.
		if ge.CredentialsExhausted() {
			s.Reason = "invalid credentials or billing"
			s.Hint = "The provider rejected the credentials (HTTP 401/402/403). Check your API key / auth " +
				"and the account's billing; behind a gateway, this can be the gateway's own upstream keys."

			return s
		}
	}

	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		s.Reason = httpReason("invalid credentials", status)
		s.Hint = "The provider rejected the credentials. Check your API key / auth."
	case http.StatusNotFound:
		s.Reason = httpReason("model not found / no access", status)
		s.Hint = "Check llm.model is correct and your account can access it."
	case http.StatusPaymentRequired, http.StatusTooManyRequests:
		s.Reason = httpReason("rate limited / out of quota", status)
		s.Hint = "Check the provider account's billing/quota, then retry."
	case 0:
		s.Reason = "could not reach the provider"
		s.Hint = "Check connectivity and llm.base_url; run with -v for details."
	default:
		s.Reason = httpReason("request failed", status)
		s.Hint = "Run with -v for the (redacted) provider error."
	}

	return s
}

// httpReason appends "(HTTP nnn)" — only ever called with status > 0.
func httpReason(label string, status int) string {
	return label + " (HTTP " + strconv.Itoa(status) + ")"
}
