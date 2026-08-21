package schema_test

import (
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

func TestGeneration_ZeroValueMeansNothingReported(t *testing.T) {
	t.Parallel()

	var g schema.Generation
	if g.Message != nil {
		t.Errorf("zero Generation.Message = %v, want nil", g.Message)
	}
	if g.StopReason != schema.StopUnspecified {
		t.Errorf("zero Generation.StopReason = %q, want %q", g.StopReason, schema.StopUnspecified)
	}
	if g.RawReason != "" {
		t.Errorf("zero Generation.RawReason = %q, want empty", g.RawReason)
	}
}

func TestStopReason_WireSpellings(t *testing.T) {
	t.Parallel()

	// The constants ARE the wire spellings the normalizer matches on, so a typo
	// here would silently reclassify every response of that kind as StopOther.
	for _, tc := range []struct {
		reason schema.StopReason
		want   string
	}{
		{schema.StopUnspecified, ""},
		{schema.StopNormal, "stop"},
		{schema.StopLength, "length"},
		{schema.StopContentFilter, "content_filter"},
		{schema.StopToolCalls, "tool_calls"},
		{schema.StopOther, "other"},
	} {
		if got := string(tc.reason); got != tc.want {
			t.Errorf("StopReason = %q, want %q", got, tc.want)
		}
	}
}

func TestGeneration_CarriesMessageAndReason(t *testing.T) {
	t.Parallel()

	g := schema.Generation{
		Message:    schema.AssistantMessage("hi", nil),
		StopReason: schema.StopLength,
		RawReason:  "length",
	}
	if got := g.Message.Text(); got != "hi" {
		t.Errorf("Message.Text() = %q, want %q", got, "hi")
	}
	if g.StopReason != schema.StopLength {
		t.Errorf("StopReason = %q, want %q", g.StopReason, schema.StopLength)
	}
	if g.RawReason != "length" {
		t.Errorf("RawReason = %q, want %q", g.RawReason, "length")
	}
}
