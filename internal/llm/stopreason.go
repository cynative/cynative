package llm

import "github.com/cynative/cynative/internal/schema"

// geminiUnspecifiedReason is Gemini's "no reason given" sentinel. Bifrost has no
// mapping for it, so it arrives verbatim; it means the same thing as an absent
// finish_reason, and classifying it as a terminal reason would abandon a run over
// a value that reports nothing.
const geminiUnspecifiedReason = "FINISH_REASON_UNSPECIFIED"

// stopReasonFrom normalizes the finish reason on a Bifrost choice, returning the
// classification and the backend string verbatim.
//
// Bifrost does not guarantee the OpenAI vocabulary. Each provider converts
// through a lookup map and returns its input unchanged on a miss, and the
// OpenAI-shaped providers do no conversion at all, so values like
// "guardrail_intervened" and "refusal" reach us as-is. Matching is therefore on
// exact strings: an unverified value is classified StopOther rather than
// coerced, because promoting it to a canonical reason would be a guess about
// behavior we would then act on.
func stopReasonFrom(raw *string) (schema.StopReason, string) {
	if raw == nil || *raw == "" {
		return schema.StopUnspecified, ""
	}

	switch *raw {
	case string(schema.StopNormal):
		return schema.StopNormal, *raw
	case string(schema.StopLength):
		return schema.StopLength, *raw
	case string(schema.StopContentFilter):
		return schema.StopContentFilter, *raw
	case string(schema.StopToolCalls):
		return schema.StopToolCalls, *raw
	case geminiUnspecifiedReason:
		return schema.StopUnspecified, *raw
	default:
		return schema.StopOther, *raw
	}
}
