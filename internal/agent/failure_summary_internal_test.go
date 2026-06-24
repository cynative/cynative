package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// budgetSummaryModel records over-budget usage into acc on Generate, modeling the
// summary turn being the call that crosses the per-session ceiling.
type budgetSummaryModel struct {
	acc   *metrics.Accumulator
	usage schema.Usage
}

var _ schema.ChatModel = (*budgetSummaryModel)(nil)

func (m *budgetSummaryModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.acc.AddUsage(m.usage)

	return schema.AssistantMessage("summary text", nil), nil
}

// answerOnceModel returns a scriptedModel producing one assistant text message.
func answerOnceModel(text string) *scriptedModel {
	return &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage(text, nil)}}
}

// errModel (in agent_internal_test.go) always errors — used here for Generate-error fallback.

func TestFailureSummary_RendersAndReturnsModelText(t *testing.T) {
	t.Parallel()

	a := newTestAgent(answerOnceModel("Need a GCP project id; reply with it to continue."),
		map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 3
	a.renderer = echoRenderer
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	buf := rs.out.(*bytes.Buffer)

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if err != nil {
		t.Fatalf("failureSummary error: %v", err)
	}
	if !strings.Contains(buf.String(), "Stopped after 3 consecutive failures") {
		t.Errorf("missing halt header: %q", buf.String())
	}
	if !strings.Contains(got, "project id") {
		t.Errorf("summary answer should be the model text, got %q", got)
	}
}

func TestFailureSummary_BlankCompletionFallsBack(t *testing.T) {
	t.Parallel()

	a := newTestAgent(answerOnceModel("   "), map[string]schema.InvokableTool{}) // whitespace-only completion.
	a.maxConsecutiveFailures = 2
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != deterministicFailureNotice {
		t.Errorf("blank completion must fall back to the deterministic notice, got %q", got)
	}
	if !strings.Contains(rs.out.(*bytes.Buffer).String(), deterministicFailureNotice) {
		t.Errorf("the deterministic notice must be rendered to the user")
	}
}

func TestFailureSummary_GenerateErrorFallsBack(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&errModel{}, map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if err != nil || got != deterministicFailureNotice {
		t.Errorf("Generate error must fall back: got=(%q,%v)", got, err)
	}
}

func TestFailureSummary_InterruptPreCheck(t *testing.T) {
	t.Parallel()

	a := newTestAgent(answerOnceModel("irrelevant"), map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	a.interrupter = &fakeInterrupter{tripped: true} //nolint:exhaustruct // began/ended unused.
	rs := &runState{                                //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, errInterrupted) {
		t.Errorf("pre-check interrupt: got=(%q, %v), want errInterrupted", got, err)
	}
	// The halt header must NOT have been printed (interrupted before rendering).
	if strings.Contains(rs.out.(*bytes.Buffer).String(), "Stopped after") {
		t.Errorf("halt header must not be rendered when interrupted before it: %q",
			rs.out.(*bytes.Buffer).String())
	}
}

func TestFailureSummary_InterruptPostGenerate(t *testing.T) {
	t.Parallel()

	// The interrupter trips only after Generate (second Interrupted() call).
	// Call 0: pre-check (false → passes). Call 1: post-Generate check (true → halt).
	ci := &countInterrupter{target: 1}

	a := newTestAgent(answerOnceModel("summary text"), map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	a.interrupter = ci
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, errInterrupted) {
		t.Errorf("post-Generate interrupt: got=(%q, %v), want errInterrupted", got, err)
	}
}

func TestFailureSummary_InterruptDuringSummaryRenderDenies(t *testing.T) {
	t.Parallel()

	// Call 0 = pre-check (false). Call 1 = post-Generate check (false). Call 2 = the
	// new post-render re-check (true → halt before recording the rendered summary).
	ci := &countInterrupter{target: 2}
	a := newTestAgent(answerOnceModel("the wall summary"), map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	a.interrupter = ci
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, errInterrupted) {
		t.Errorf("post-render interrupt: got=(%q, %v), want errInterrupted", got, err)
	}
	if got != "" {
		t.Errorf("an interrupted summary must return empty, got %q", got)
	}
}

func TestFailureSummary_CanceledContextPropagates(t *testing.T) {
	t.Parallel()

	// A context canceled before/during the summary Generate must propagate the
	// cancellation, NOT degrade into a successful deterministic notice (C4).
	a := newTestAgent(answerOnceModel("would-be summary"), map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := a.failureSummary(ctx, rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled context: got=(%q, %v), want context.Canceled", got, err)
	}
	if got == deterministicFailureNotice {
		t.Errorf("cancellation must not degrade to the deterministic notice")
	}
}

func TestFailureSummary_BudgetCrossReturnsSentinel(t *testing.T) {
	t.Parallel()

	// The summary Generate's usage crosses the per-session budget; failureSummary
	// must return the same sentinel the main loop uses so Run renders the notice (C2).
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	acc.StartTurn()

	a := newTestAgent(&budgetSummaryModel{acc: acc, usage: schema.Usage{TotalTokens: 50}},
		map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	a.metrics = acc
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("budget cross: got=(%q, %v), want errBudgetExceeded", got, err)
	}
	if got != "" {
		t.Errorf("budget halt must return empty answer, got %q", got)
	}
}

func TestCompletePendingToolResults_PairsUnansweredCalls(t *testing.T) {
	t.Parallel()

	// A halt mid-batch: the assistant emitted two tool calls but only the first was dispatched.
	turn := []*schema.Message{
		schema.UserMessage("q"),
		schema.AssistantMessage("", []schema.ToolCallBlock{
			{ID: "a", Name: "http_request", Arguments: "{}"},
			{ID: "b", Name: "http_request", Arguments: "{}"},
		}),
		schema.ToolMessage("done", "a"),
	}

	got := completePendingToolResults(turn)

	answered := map[string]string{}
	for _, m := range got {
		for _, tr := range m.ToolResults() {
			answered[tr.ToolCallID] = tr.Content
		}
	}
	if answered["a"] != "done" {
		t.Errorf("the real result for a must be preserved, got %q", answered["a"])
	}
	if answered["b"] != syntheticHaltResult {
		t.Errorf("unanswered call b got %q, want the synthetic halt result", answered["b"])
	}
	if len(got) != 4 {
		t.Errorf("exactly one synthetic message must be appended, got len=%d", len(got))
	}
}

func TestCompletePendingToolResults_LeavesCompleteTranscript(t *testing.T) {
	t.Parallel()

	turn := []*schema.Message{
		schema.AssistantMessage("", []schema.ToolCallBlock{{ID: "a", Name: "t", Arguments: "{}"}}),
		schema.ToolMessage("done", "a"),
	}
	if got := completePendingToolResults(turn); len(got) != len(turn) {
		t.Errorf("a fully-answered transcript must be unchanged, got len=%d want %d", len(got), len(turn))
	}
}

func TestCompletePendingToolResults_NoToolCallsUnchanged(t *testing.T) {
	t.Parallel()

	turn := []*schema.Message{schema.UserMessage("q"), schema.AssistantMessage("hi", nil)}
	if got := completePendingToolResults(turn); len(got) != len(turn) {
		t.Errorf("a turn with no tool calls must be unchanged, got len=%d", len(got))
	}
}

func TestFailureSummary_CompletesPendingToolCallsBeforeGenerate(t *testing.T) {
	t.Parallel()

	// The summary Generate must receive a valid transcript: every assistant tool call
	// paired with a tool result, even after a mid-batch halt left one undispatched.
	cm := &capturingModel{ret: schema.AssistantMessage("here's the wall", nil)} //nolint:exhaustruct // seen/calls zero.
	a := newTestAgent(cm, map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	turn := []*schema.Message{
		schema.UserMessage("q"),
		schema.AssistantMessage("", []schema.ToolCallBlock{
			{ID: "a", Name: "http_request", Arguments: "{}"},
			{ID: "b", Name: "http_request", Arguments: "{}"},
		}),
		schema.ToolMessage("403", "a"),
	}

	if _, err := a.failureSummary(context.Background(), rs, turn); err != nil {
		t.Fatalf("failureSummary error: %v", err)
	}

	calls, results := map[string]bool{}, map[string]bool{}
	for _, m := range cm.seen {
		for _, tc := range m.ToolCalls() {
			calls[tc.ID] = true
		}
		for _, tr := range m.ToolResults() {
			results[tr.ToolCallID] = true
		}
	}
	if len(calls) == 0 {
		t.Fatal("the captured transcript had no tool calls; test setup is wrong")
	}
	for id := range calls {
		if !results[id] {
			t.Errorf("tool call %q reached Generate without a matching result", id)
		}
	}
	if !results["b"] {
		t.Errorf("the undispatched call b was not completed before Generate")
	}
}

func TestFailureSummary_CancelsHungSummaryOnInterrupt(t *testing.T) {
	t.Parallel()

	// Pre-check (call 0) false → the summary Generate starts; the cancel poll's tick
	// (call 1) trips and cancels the hung summary; the post-Generate check (call 2) halts.
	ci := &countInterrupter{target: 1}
	a := newTestAgent(ctxWaitModel{}, map[string]schema.InvokableTool{})
	a.maxConsecutiveFailures = 2
	a.interrupter = ci
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   &bytes.Buffer{},
		todos: nil,
		runID: "r",
	}

	got, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")})
	if !errors.Is(err, errInterrupted) {
		t.Errorf("hung summary + interrupt: got (%q, %v), want errInterrupted", got, err)
	}
}
