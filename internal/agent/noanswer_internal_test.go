package agent

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// TestRun_FutileStopsReturnErrNoAnswer pins the exit-code contract (#281): a run
// that ends without a final answer renders its operator notice and returns
// ErrNoAnswer wrapping the specific cause, so a scripted one-shot can exit
// non-zero while the interactive loop keeps treating the turn as non-fatal.
// History stays untouched: no partial answer is recorded.
func TestRun_FutileStopsReturnErrNoAnswer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		cfg   func() Config
		cause error
	}{
		{
			name: "iteration limit",
			cfg: func() Config {
				cfg := baseConfig()
				cfg.Cfg.MaxIterations = 1
				cfg.Model = &scriptedModel{msgs: []*schema.Message{toolCall("c1", "echo", "{}")}}
				cfg.Tools = []schema.InvokableTool{&echoTool{ran: nil}}

				return cfg
			},
			cause: errIterationLimit,
		},
		{
			name: "empty responses",
			cfg: func() Config {
				cfg := baseConfig()
				cfg.Model = &transcriptModel{msgs: []*schema.Message{
					schema.AssistantMessage("", nil),
					schema.AssistantMessage("", nil),
					schema.AssistantMessage("", nil),
				}}

				return cfg
			},
			cause: errEmptyResponses,
		},
		{
			name: "budget exceeded",
			cfg: func() Config {
				acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
				cfg := baseConfig()
				cfg.Model = &budgetLoopModel{acc: acc, usage: schema.Usage{TotalTokens: 50}, calls: 0}
				cfg.Metrics = acc
				cfg.Tools = []schema.InvokableTool{&echoTool{ran: nil}}

				return cfg
			},
			cause: errBudgetExceeded,
		},
		{
			name: "output limit",
			cfg: func() Config {
				cfg := baseConfig()
				cfg.Model = &blankReasonModel{reason: schema.StopLength, raw: "", calls: 0}

				return cfg
			},
			cause: errOutputLimit,
		},
		{
			name: "content filter",
			cfg: func() Config {
				cfg := baseConfig()
				cfg.Model = &blankReasonModel{reason: schema.StopContentFilter, raw: "", calls: 0}

				return cfg
			},
			cause: errContentFiltered,
		},
		{
			name: "stopped early",
			cfg: func() Config {
				cfg := baseConfig()
				cfg.Model = &blankReasonModel{reason: schema.StopOther, raw: "guardrail", calls: 0}

				return cfg
			},
			cause: errStoppedEarly,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := New(context.Background(), tc.cfg())

			var buf bytes.Buffer
			err := a.Run(context.Background(), "q", &buf)
			if !errors.Is(err, ErrNoAnswer) {
				t.Fatalf("Run = %v, want ErrNoAnswer", err)
			}
			if !errors.Is(err, tc.cause) {
				t.Fatalf("Run = %v, want the cause %v preserved for errors.Is", err, tc.cause)
			}
			if buf.Len() == 0 {
				t.Error("the operator notice must still render before the sentinel returns")
			}
			if len(a.history) != 0 {
				t.Errorf("history length = %d, want 0 (no partial answer recorded)", len(a.history))
			}
		})
	}
}

// TestRun_StoppedEarlyKeepsRawReasonThroughTheWrap pins that the umbrella wrap
// preserves the concrete *stoppedEarlyError, not just the bare sentinel: the
// raw backend reason must stay reachable via errors.As for diagnostics.
func TestRun_StoppedEarlyKeepsRawReasonThroughTheWrap(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &blankReasonModel{reason: schema.StopOther, raw: "guardrail_x", calls: 0}
	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	stoppedEarly, ok := errors.AsType[*stoppedEarlyError](err)
	if !ok {
		t.Fatalf("Run = %v, want the concrete *stoppedEarlyError preserved through the wrap", err)
	}
	if stoppedEarly.raw != "guardrail_x" {
		t.Errorf("raw = %q, want the backend reason preserved", stoppedEarly.raw)
	}
}
