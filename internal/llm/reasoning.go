package llm

import (
	"errors"
	"fmt"
)

// Sentinel errors raised at startup when the llm reasoning config is invalid.
var (
	// ErrInvalidReasoningEffort is returned when llm.reasoning_effort is not
	// one of the levels Bifrost accepts.
	ErrInvalidReasoningEffort = errors.New("invalid llm.reasoning_effort")
	// ErrInvalidReasoningMaxTokens is returned when llm.reasoning_max_tokens
	// is negative.
	ErrInvalidReasoningMaxTokens = errors.New("invalid llm.reasoning_max_tokens")
	// ErrReasoningConflict is returned when llm.reasoning_effort "none" is
	// combined with an explicit llm.reasoning_max_tokens budget: Bifrost's
	// Anthropic-style converters give the budget priority over the effort, so
	// the combination would silently enable the thinking the operator
	// disabled.
	ErrReasoningConflict = errors.New("conflicting llm reasoning configuration")
)

// ValidateReasoning rejects an invalid llm.reasoning_effort /
// llm.reasoning_max_tokens configuration at load time, before the request
// path could send it. A nil entry is treated as nothing to validate.
func ValidateReasoning(entry *ProviderEntry) error {
	if entry == nil {
		return nil
	}

	switch entry.ReasoningEffort {
	case "", "none", "minimal", "low", "medium", "high":
	default:
		return fmt.Errorf(
			"%w: %q — set llm.reasoning_effort (or CYNATIVE_LLM_REASONING_EFFORT) to one of: none, minimal, low, medium, high",
			ErrInvalidReasoningEffort,
			entry.ReasoningEffort,
		)
	}

	if entry.ReasoningMaxTokens < 0 {
		return fmt.Errorf(
			"%w: %d — llm.reasoning_max_tokens (CYNATIVE_LLM_REASONING_MAX_TOKENS) must be a positive token budget",
			ErrInvalidReasoningMaxTokens, entry.ReasoningMaxTokens,
		)
	}

	if entry.ReasoningEffort == "none" && entry.ReasoningMaxTokens > 0 {
		return fmt.Errorf(
			"%w: llm.reasoning_effort %q conflicts with llm.reasoning_max_tokens — an explicit token budget enables"+
				" reasoning on Anthropic-style providers; unset one of them"+
				" (CYNATIVE_LLM_REASONING_EFFORT / CYNATIVE_LLM_REASONING_MAX_TOKENS)",
			ErrReasoningConflict, entry.ReasoningEffort,
		)
	}

	return nil
}
