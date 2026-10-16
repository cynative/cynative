package agent

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

// signedReasoning builds a reasoning block with aggregate text and one signed
// detail, the shape a replayable backend returns.
func signedReasoning(text string) *schema.ReasoningBlock {
	sig := "sig"

	return &schema.ReasoningBlock{
		Text:    &text,
		Details: []schema.ReasoningDetail{{Index: 0, Type: "reasoning.text", Text: &text, Signature: &sig}},
	}
}

func TestHistoryAnswer_KeepsReasoningTextOnly(t *testing.T) {
	t.Parallel()

	r := signedReasoning("thought")
	msg := historyAnswer("answer", r)

	if msg.Role != schema.Assistant || msg.Text() != "answer" || len(msg.ToolCalls()) != 0 {
		t.Fatalf("message = %+v, want an assistant turn carrying only the answer text", msg)
	}
	got := msg.Reasoning()
	if got == nil || got.Text != r.Text || got.Details != nil {
		t.Errorf("reasoning = %#v, want the aggregate text and no details", got)
	}
}

func TestHistoryAnswer_NoReasoningText(t *testing.T) {
	t.Parallel()

	detailsOnly := signedReasoning("x")
	detailsOnly.Text = nil
	for name, r := range map[string]*schema.ReasoningBlock{"nil": nil, "details only": detailsOnly} {
		if got := historyAnswer("answer", r).Reasoning(); got != nil {
			t.Errorf("%s: reasoning = %#v, want none", name, got)
		}
	}
}

func TestRun_HistoryCarriesTheAnswersReasoningText(t *testing.T) {
	t.Parallel()

	first := schema.AssistantMessage("one", nil)
	first.Content = append([]schema.Block{*signedReasoning("why one")}, first.Content...)
	m := &genScriptModel{gens: []schema.Generation{plainTurn(first), plainTurn(schema.AssistantMessage("two", nil))}}
	cfg := baseConfig()
	cfg.Model = m
	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q1", &bytes.Buffer{}); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	if err := a.Run(context.Background(), "q2", &bytes.Buffer{}); err != nil {
		t.Fatalf("Run 2: %v", err)
	}

	var prior *schema.Message
	for _, msg := range m.seen[1] {
		if msg.Role == schema.Assistant {
			prior = msg
		}
	}
	r := prior.Reasoning()
	if prior.Text() != "one" || r == nil || r.Text == nil || *r.Text != "why one" || r.Details != nil {
		t.Errorf("history turn = %+v (reasoning %#v), want answer one with its reasoning text only", prior, r)
	}
}

func TestWelcome_HistoryCarriesTheGreetingsReasoningText(t *testing.T) {
	t.Parallel()

	greeting := schema.AssistantMessage("hello", nil)
	greeting.Content = append([]schema.Block{*signedReasoning("greet")}, greeting.Content...)
	a, _ := welcomeAgent(t, &scriptedModel{msgs: []*schema.Message{greeting}})

	if _, err := a.Welcome(context.Background()); err != nil {
		t.Fatalf("Welcome: %v", err)
	}
	r := a.history[1].Reasoning()
	if r == nil || r.Text == nil || *r.Text != "greet" || r.Details != nil {
		t.Errorf("greeting reasoning = %#v, want its text only", r)
	}
}

func TestFailureSummary_RecordsTheSummarysReasoning(t *testing.T) {
	t.Parallel()

	summary := schema.AssistantMessage("stuck on X", nil)
	r := signedReasoning("summarizing")
	summary.Content = append([]schema.Block{*r}, summary.Content...)
	a := newTestAgent(&scriptedModel{msgs: []*schema.Message{summary}}, map[string]schema.InvokableTool{})
	rs := &runState{depth: 0, out: &bytes.Buffer{}, runID: "r"}

	if _, err := a.failureSummary(context.Background(), rs, []*schema.Message{schema.UserMessage("q")}); err != nil {
		t.Fatalf("failureSummary: %v", err)
	}
	if rs.answerReasoning == nil || rs.answerReasoning.Text != r.Text {
		t.Errorf("answerReasoning = %#v, want the summary turn's reasoning", rs.answerReasoning)
	}
}

func TestRun_HostWrittenFailureNoticeStaysOutOfHistory(t *testing.T) {
	t.Parallel()

	// Three failing calls trip the halt; the scripted model is then exhausted, so
	// the summary Generate errors and the run answers with the host-written notice.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "fail_tool", "{}"),
		toolCall("c2", "fail_tool", "{}"),
		toolCall("c3", "fail_tool", "{}"),
	}}
	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 3
	cfg.Tools = []schema.InvokableTool{&failingTool{name: "fail_tool"}}
	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "scan", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(deterministicFailureNotice)) {
		t.Fatalf("output %q lacks the host notice; the test did not reach the fallback", buf.String())
	}
	if len(a.history) != 0 {
		t.Errorf("history = %+v, want the host-written notice kept out of it", a.history)
	}
	if !slices.Equal(a.unanswered, []string{"scan"}) {
		t.Errorf("unanswered = %q, want the failed question queued for the next one", a.unanswered)
	}
}

func TestWithUnanswered_JoinsEveryQueuedQuestion(t *testing.T) {
	t.Parallel()

	got := withUnanswered([]string{"a", "b"}, "c")
	want := unansweredPrefix + "a\n\n" + unansweredPrefix + "b\n\nc"
	if got != want {
		t.Errorf("withUnanswered = %q, want %q", got, want)
	}
}

func TestRun_FailedQuestionCarriesIntoTheNextQuestion(t *testing.T) {
	t.Parallel()

	// Run 1: three failing calls, then the summary Generate errors (scriptErr), so
	// the run ends with the host notice. Run 2: the model answers directly.
	model := &genScriptModel{gens: []schema.Generation{
		plainTurn(toolCall("c1", "fail_tool", "{}")),
		plainTurn(toolCall("c2", "fail_tool", "{}")),
		plainTurn(toolCall("c3", "fail_tool", "{}")),
		{Message: nil},
		plainTurn(schema.AssistantMessage("found it", nil)),
	}}
	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 3
	cfg.Tools = []schema.InvokableTool{&failingTool{name: "fail_tool"}}
	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "scan the bucket", &bytes.Buffer{}); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	if err := a.Run(context.Background(), "use project X", &bytes.Buffer{}); err != nil {
		t.Fatalf("Run 2: %v", err)
	}

	req := model.seen[len(model.seen)-1]
	last := req[len(req)-1]
	want := "Earlier question, which ended without an answer: scan the bucket\n\nuse project X"
	if last.Role != schema.User || last.Text() != want {
		t.Errorf("question sent = %q, want %q", last.Text(), want)
	}
	if n := len(a.history); n != 2 || a.history[0].Text() != want || a.history[1].Text() != "found it" {
		t.Errorf("history = %+v, want the combined question and its answer", a.history)
	}
	if len(a.unanswered) != 0 {
		t.Errorf("unanswered = %q, want it cleared once a question is answered", a.unanswered)
	}
}
