package llm

import (
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

func TestStopReasonFrom(t *testing.T) {
	t.Parallel()

	ptr := func(s string) *string { return &s }

	for _, tc := range []struct {
		name     string
		in       *string
		wantStop schema.StopReason
		wantRaw  string
	}{
		// Absent is spelled two ways: anthropic/cohere/openai-passthrough leave
		// the pointer nil; gemini and bedrock always allocate, so an empty native
		// reason arrives as a pointer to "".
		{"nil pointer", nil, schema.StopUnspecified, ""},
		{"empty string", ptr(""), schema.StopUnspecified, ""},
		// Gemini's own "no reason given" sentinel is unmapped by Bifrost and
		// arrives verbatim. It must not be mistaken for a terminal classification.
		{"gemini unspecified", ptr("FINISH_REASON_UNSPECIFIED"), schema.StopUnspecified, "FINISH_REASON_UNSPECIFIED"},
		{"stop", ptr("stop"), schema.StopNormal, "stop"},
		{"length", ptr("length"), schema.StopLength, "length"},
		{"content filter", ptr("content_filter"), schema.StopContentFilter, "content_filter"},
		{"tool calls", ptr("tool_calls"), schema.StopToolCalls, "tool_calls"},
		// Reachable unmapped values that Bifrost passes through verbatim.
		{"bedrock guardrail", ptr("guardrail_intervened"), schema.StopOther, "guardrail_intervened"},
		{"anthropic refusal", ptr("refusal"), schema.StopOther, "refusal"},
		{"anthropic compaction", ptr("compaction"), schema.StopOther, "compaction"},
		{
			"anthropic context window",
			ptr("model_context_window_exceeded"), schema.StopOther, "model_context_window_exceeded",
		},
		{"replicate error", ptr("error"), schema.StopOther, "error"},
		// No fuzzy matching: an unverified value is never promoted to canonical.
		{"wrong case", ptr("LENGTH"), schema.StopOther, "LENGTH"},
		{"literal other", ptr("other"), schema.StopOther, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotStop, gotRaw := stopReasonFrom(tc.in)
			if gotStop != tc.wantStop {
				t.Errorf("stop reason = %q, want %q", gotStop, tc.wantStop)
			}
			if gotRaw != tc.wantRaw {
				t.Errorf("raw reason = %q, want %q", gotRaw, tc.wantRaw)
			}
		})
	}
}
