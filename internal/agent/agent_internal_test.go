package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// --- shared test doubles (reused by loop, todos, and task tests) ---

// scriptedModel returns its messages in order from Generate; once exhausted it
// errors.
type scriptedModel struct {
	msgs  []*schema.Message
	calls int
}

var _ schema.ChatModel = (*scriptedModel)(nil)

func (m *scriptedModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	if m.calls >= len(m.msgs) {
		return nil, errors.New("scriptedModel: out of scripted messages")
	}
	msg := m.msgs[m.calls]
	m.calls++

	return msg, nil
}

// capturingModel records the messages passed to its most recent Generate call
// (so a multi-turn test sees the latest Run's seed) and returns ret.
type capturingModel struct {
	seen  []*schema.Message
	ret   *schema.Message
	calls int
}

var _ schema.ChatModel = (*capturingModel)(nil)

func (m *capturingModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.seen = msgs
	m.calls++
	if m.ret == nil {
		return nil, errors.New("capturingModel: no return scripted")
	}

	return m.ret, nil
}

// errModel always errors from Generate.
type errModel struct{}

var _ schema.ChatModel = (*errModel)(nil)

func (*errModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	return nil, errors.New("generate boom")
}

// echoTool records whether it ran and returns "echoed".
type echoTool struct {
	ran *bool
}

var _ schema.InvokableTool = (*echoTool)(nil)

func (*echoTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "echo", Desc: "echo tool", Params: nil}
}

func (t *echoTool) Run(context.Context, string) (string, error) {
	if t.ran != nil {
		*t.ran = true
	}

	return "echoed", nil
}

// errTool always returns a Go error from Run.
type errTool struct{}

var _ schema.InvokableTool = (*errTool)(nil)

func (*errTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "boom", Desc: "boom tool", Params: nil}
}

func (*errTool) Run(context.Context, string) (string, error) {
	return "", errors.New("tool boom")
}

// toolCall builds an assistant message carrying a single tool call.
func toolCall(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCallBlock{{ID: id, Name: name, Arguments: args}})
}

// --- loop tests ---

func TestRun_NoToolCallReturnsFinalAnswer(t *testing.T) {
	t.Parallel()

	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("done", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "done" {
		t.Errorf("answer = %q, want %q", answer, "done")
	}
}

func TestRun_DispatchesToolThenAnswers(t *testing.T) {
	t.Parallel()

	var ran bool

	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("final", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: &ran}})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "final" {
		t.Errorf("answer = %q, want %q", answer, "final")
	}
	if !ran {
		t.Error("echo tool did not run")
	}
}

func TestRun_IterationGuardExhausts(t *testing.T) {
	t.Parallel()

	// Every turn is a tool call, so the loop never reaches a final answer and
	// exhausts maxIter, returning "".
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		toolCall("c2", "echo", "{}"),
		toolCall("c3", "echo", "{}"),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "" {
		t.Errorf("answer = %q, want empty (iteration limit)", answer)
	}
}

func TestRun_ZeroIterations(t *testing.T) {
	t.Parallel()

	// maxIter <= 0: the loop body never runs and the model is never called.
	model := &scriptedModel{msgs: nil}
	a := newTestAgent(model, map[string]schema.InvokableTool{})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "" {
		t.Errorf("answer = %q, want empty", answer)
	}
	if model.calls != 0 {
		t.Errorf("model called %d times, want 0", model.calls)
	}
}

func TestRun_UnknownToolRecovers(t *testing.T) {
	t.Parallel()

	// The first turn calls a tool not in the toolset; dispatch returns an
	// error-result string and the loop continues to a final answer.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "nope", "{}"),
		schema.AssistantMessage("recovered", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "recovered" {
		t.Errorf("answer = %q, want %q", answer, "recovered")
	}
}

func TestRun_ModelGenerateErrorPropagates(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&errModel{}, map[string]schema.InvokableTool{})

	_, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err == nil || !strings.Contains(err.Error(), "model generate") {
		t.Fatalf("expected wrapped generate error, got: %v", err)
	}
}

func TestRun_ToolRunErrorRecovers(t *testing.T) {
	t.Parallel()

	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "boom", "{}"),
		schema.AssistantMessage("after error", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"boom": &errTool{}})

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "after error" {
		t.Errorf("answer = %q, want %q", answer, "after error")
	}
}

func TestDispatch_UnknownTool(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})

	rs := &runState{depth: 0, out: io.Discard}
	out, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{ID: "x", Name: "ghost", Arguments: "{}"})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}
	if !strings.Contains(out, "unknown tool") {
		t.Errorf("dispatch = %q, want unknown-tool message", out)
	}
}

func TestDispatch_ToolError(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{"boom": &errTool{}})

	rs := &runState{depth: 0, out: io.Discard}
	out, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{ID: "x", Name: "boom", Arguments: "{}"})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}
	if !strings.Contains(out, "Error executing tool") {
		t.Errorf("dispatch = %q, want tool-error message", out)
	}
}

func TestDispatch_Success(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})

	rs := &runState{depth: 0, out: io.Discard}
	out, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{ID: "x", Name: "echo", Arguments: "{}"})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}
	// echo is an I/O (plain Run) tool, so dispatch fences its result as untrusted.
	if !strings.Contains(out, "echoed") {
		t.Errorf("dispatch = %q, want to contain %q", out, "echoed")
	}
}

// --- New / Run / buildToolset tests ---

// echoRenderer writes the message's text into w.
func echoRenderer(msg *schema.Message, _ string, w io.Writer) {
	_, _ = io.WriteString(w, msg.Text())
}

// baseConfig builds a Config with the echo renderer and the current config
// field names.
func baseConfig() Config {
	return Config{ //nolint:exhaustruct // Tools/VerboseWriter set per test
		Cfg: config.Config{ //nolint:exhaustruct // only render/iteration fields matter
			RenderStyle:           "notty",
			MaxIterations:         5,
			MaxSubagentIterations: 3,
		},
		Providers: nil,
		Renderer:  echoRenderer,
	}
}

func TestNew_Success(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{}

	a := New(context.Background(), cfg)
	if a.maxIter != 5 || a.maxSubagentIter != 3 {
		t.Errorf("budgets = (%d,%d), want (5,3)", a.maxIter, a.maxSubagentIter)
	}
	// write_todos and task must be registered.
	if _, ok := a.tools.tools["write_todos"]; !ok {
		t.Error("write_todos not registered")
	}
	if _, ok := a.tools.tools["task"]; !ok {
		t.Error("task not registered")
	}
}

func TestNew_AppliesOptions(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{}

	a := New(context.Background(), cfg, withSystemPrompt("OVERRIDDEN"))
	if a.systemPrompt != "OVERRIDDEN" {
		t.Errorf("systemPrompt = %q, want option-applied value", a.systemPrompt)
	}
}

func TestNew_RegistersOrchestrationToolsUnwrapped(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{}

	a := New(context.Background(), cfg)

	// The concrete types prove New registers them bare: surfaced, not gated.
	if _, ok := a.tools.tools["write_todos"].(*writeTodosTool); !ok {
		t.Errorf("write_todos registered as %T, want *writeTodosTool (unwrapped)", a.tools.tools["write_todos"])
	}
	if _, ok := a.tools.tools["task"].(*taskTool); !ok {
		t.Errorf("task registered as %T, want *taskTool (unwrapped)", a.tools.tools["task"])
	}
}

func TestNew_RegistersVerifierAlways(t *testing.T) {
	t.Parallel()

	cfg := baseConfig() // No panel size to set: verification is unconditional.
	cfg.Model = &scriptedModel{}

	a := New(context.Background(), cfg)
	if _, ok := a.tools.tools["verify_findings"].(*verifyFindingsTool); !ok {
		t.Errorf("verify_findings registered as %T, want *verifyFindingsTool", a.tools.tools["verify_findings"])
	}
	if !strings.Contains(a.systemPrompt, "verify_findings") {
		t.Error("system prompt does not teach verify_findings")
	}
}

func TestRun_RecordsQAHistory(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("the answer", nil)}}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "the question", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(buf.String(), "the answer") {
		t.Errorf("output = %q, want rendered answer", buf.String())
	}
	// History holds only the user question and the final answer.
	if len(a.history) != 2 {
		t.Fatalf("history length = %d, want 2", len(a.history))
	}
	if a.history[0].Role != schema.User || a.history[0].Text() != "the question" {
		t.Errorf("history[0] = %+v, want user question", a.history[0])
	}
	if a.history[1].Role != schema.Assistant || a.history[1].Text() != "the answer" {
		t.Errorf("history[1] = %+v, want assistant answer", a.history[1])
	}
}

func TestRun_SeedsSystemThenHistoryThenQuestion(t *testing.T) {
	t.Parallel()

	model := &capturingModel{ret: schema.AssistantMessage("a1", nil)} //nolint:exhaustruct // seen/calls start zero

	cfg := baseConfig()
	cfg.Model = model
	cfg.Providers = []auth.Provider{}

	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q1", io.Discard); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// First turn seeds [system, user].
	if len(model.seen) != 2 {
		t.Fatalf("seed length = %d, want 2", len(model.seen))
	}
	if model.seen[0].Role != schema.System {
		t.Errorf("seed[0] role = %q, want system", model.seen[0].Role)
	}
	if model.seen[1].Role != schema.User || model.seen[1].Text() != "q1" {
		t.Errorf("seed[1] = %+v, want user q1", model.seen[1])
	}
}

func TestRun_SecondTurnReplaysHistory(t *testing.T) {
	t.Parallel()

	// First turn records a Q&A pair; the second turn's seed must include it
	// between the system message and the new question.
	model := &capturingModel{ret: schema.AssistantMessage("a1", nil)} //nolint:exhaustruct // seen/calls start zero

	cfg := baseConfig()
	cfg.Model = model

	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q1", io.Discard); err != nil {
		t.Fatalf("Run #1: %v", err)
	}
	if err := a.Run(context.Background(), "q2", io.Discard); err != nil {
		t.Fatalf("Run #2: %v", err)
	}

	// Second seed: [system, user q1, assistant a1, user q2].
	if len(model.seen) != 4 {
		t.Fatalf("second seed length = %d, want 4", len(model.seen))
	}
	if model.seen[1].Text() != "q1" || model.seen[2].Text() != "a1" || model.seen[3].Text() != "q2" {
		t.Errorf("second seed = %v", []string{
			model.seen[1].Text(), model.seen[2].Text(), model.seen[3].Text(),
		})
	}
}

func TestRun_IterationLimitNotice(t *testing.T) {
	t.Parallel()

	// The model always calls a tool, so run exhausts maxIter and returns "":
	// Run prints the notice and records nothing.
	cfg := baseConfig()
	cfg.Cfg.MaxIterations = 1
	cfg.Model = &scriptedModel{msgs: []*schema.Message{toolCall("c1", "echo", "{}")}}
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: nil}}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "q", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(buf.String(), "Reached the iteration limit") {
		t.Errorf("output = %q, want iteration-limit notice", buf.String())
	}
	if len(a.history) != 0 {
		t.Errorf("history length = %d, want 0", len(a.history))
	}
}

func TestRun_PropagatesModelError(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &errModel{}

	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q", io.Discard); err == nil {
		t.Fatal("expected error from Run")
	}
}

// --- render tests ---

func TestRenderTurn_Prose(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.renderer = echoRenderer

	a.renderTurn(schema.AssistantMessage("hello", nil), &buf)
	if buf.String() != "hello" {
		t.Errorf("output = %q, want %q", buf.String(), "hello")
	}
}

func TestRenderTurn_ToolCallVerbose(t *testing.T) {
	t.Parallel()

	var verbose bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.verbose = &verbose

	msg := toolCall("c1", "http_request", `{"url":"x"}`)
	a.renderTurn(msg, io.Discard)

	out := verbose.String()
	if !strings.Contains(out, "http_request") || !strings.Contains(out, `{"url":"x"}`) {
		t.Errorf("verbose = %q, want tool-call notice", out)
	}
}

func TestRenderTurn_NilVerboseNoPanic(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	// a.verbose is nil; rendering a tool call must not panic.
	a.renderTurn(toolCall("c1", "echo", "{}"), io.Discard)
}

func TestRenderTurn_EmptyTextSkipsRenderer(t *testing.T) {
	t.Parallel()

	called := false
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.renderer = func(*schema.Message, string, io.Writer) { called = true }

	// Tool-call-only message has empty text; the renderer must not be called.
	a.renderTurn(toolCall("c1", "echo", "{}"), io.Discard)
	if called {
		t.Error("renderer called for empty-text turn")
	}
}

func TestRenderTodos_AllStatuses(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.renderer = echoRenderer

	a.renderTodos([]todo{
		{Content: "done step", Status: todoCompleted},
		{Content: "doing step", Status: todoInProgress},
		{Content: "todo step", Status: todoPending},
		{Content: "bogus step", Status: todoStatus("weird")},
	}, &buf)

	out := buf.String()
	for _, want := range []string{
		"Investigation plan",
		"- [x] done step",
		"- [~] doing step",
		"- [ ] todo step",
		"- [ ] bogus step",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("todos output missing %q; got %q", want, out)
		}
	}
}

func TestCheckMark(t *testing.T) {
	t.Parallel()

	cases := map[todoStatus]string{
		todoCompleted:       "x",
		todoInProgress:      "~",
		todoPending:         " ",
		todoStatus("other"): " ",
	}
	for status, want := range cases {
		if got := checkMark(status); got != want {
			t.Errorf("checkMark(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestRenderTaskStart(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.renderer = echoRenderer

	a.renderTaskStart("investigate X", &buf)
	if got := buf.String(); got != "▶ Delegating sub-task: investigate X" {
		t.Errorf("output = %q, want start notice", got)
	}
}

func TestRenderTaskEnd(t *testing.T) {
	t.Parallel()

	cases := map[bool]string{true: "■ Sub-task complete", false: "■ Sub-task failed"}
	for ok, want := range cases {
		var buf bytes.Buffer
		a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
		a.renderer = echoRenderer

		a.renderTaskEnd(ok, &buf)
		if got := buf.String(); got != want {
			t.Errorf("renderTaskEnd(%v) = %q, want %q", ok, got, want)
		}
	}
}

// --- verboseWriter tests ---

func TestVerboseWriter_Set(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.verbose = &buf

	if a.verboseWriter() != &buf {
		t.Error("verboseWriter did not return the set verbose writer")
	}
}

func TestVerboseWriter_NilDiscards(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	// a.verbose is nil.
	if a.verboseWriter() != io.Discard {
		t.Error("verboseWriter did not fall back to io.Discard")
	}
}

func TestRun_RecordsRoundTripsAndToolCalls(t *testing.T) {
	t.Parallel()

	// Turn 1: tool call (echo) → final answer. Expect 2 round-trips, 1 tool call.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("final", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})
	a.metrics = metrics.NewAccumulator("p", "m")
	a.metrics.StartTurn() // run() is the inner loop; only the public Run() calls StartTurn.

	if _, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5); err != nil {
		t.Fatalf("run: %v", err)
	}

	s := a.metrics.Snapshot()
	if s.RoundTrips != 2 || s.ToolCalls != 1 {
		t.Errorf("metrics = %+v, want rt=2 tc=1", s)
	}
}

func TestRun_RecordsResponses(t *testing.T) {
	t.Parallel()

	// A successful turn (tool call → final answer) must record two responses:
	// one for the tool-call Generate and one for the final-answer Generate.
	// A failed Generate must NOT increment Responses.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("final", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})
	a.metrics = metrics.NewAccumulator("p", "m")
	a.metrics.StartTurn()

	if _, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5); err != nil {
		t.Fatalf("run: %v", err)
	}

	s := a.metrics.Snapshot()
	// Two successful Generates (tool-call turn + final-answer turn) → Responses=2.
	if s.Responses != 2 {
		t.Errorf("Responses = %d, want 2 (one per successful Generate)", s.Responses)
	}
	// A failed Generate does not increment Responses; RoundTrips still counts it.
	aErr := newTestAgent(&errModel{}, map[string]schema.InvokableTool{})
	aErr.metrics = metrics.NewAccumulator("p", "m")
	aErr.metrics.StartTurn()

	_, _ = aErr.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)

	if got := aErr.metrics.Snapshot().Responses; got != 0 {
		t.Errorf("failed Generate must not increment Responses, got %d", got)
	}
	if got := aErr.metrics.Snapshot().RoundTrips; got != 1 {
		t.Errorf("failed Generate must still increment RoundTrips, got %d", got)
	}
}

func TestTaskTool_CountsSubagent(t *testing.T) {
	t.Parallel()

	// The sub-agent's model returns a final answer immediately.
	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("sub done", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.metrics = metrics.NewAccumulator("p", "m")
	a.metrics.StartTurn() // run() is the inner loop; only the public Run() calls StartTurn.
	a.maxSubagentIter = 5

	tool := newTaskTool(a)
	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"do a thing"}`)
	if err != nil {
		t.Fatalf("task Run: %v", err)
	}
	// task fences its summary as untrusted, so the content rides inside the fence.
	if !strings.Contains(out, "sub done") {
		t.Errorf("task result = %q, want to contain %q", out, "sub done")
	}

	// The sub-run's single Generate is also counted as a round-trip.
	s := a.metrics.Snapshot()
	if s.Subagents != 1 {
		t.Errorf("subagents = %d, want 1", s.Subagents)
	}
	if s.RoundTrips != 1 {
		t.Errorf("round-trips = %d, want 1 (sub-agent generate)", s.RoundTrips)
	}
}

// concurrentScriptModel is a stateless ChatModel (race-free by construction)
// that scripts a full task delegation from the shape of the transcript: a
// top-level question delegates, the sub-run plans with write_todos, then both
// answer.
type concurrentScriptModel struct{}

var _ schema.ChatModel = concurrentScriptModel{}

func (concurrentScriptModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	last := msgs[len(msgs)-1]
	switch {
	case last.Role == schema.User && last.Text() == "sub job":
		return toolCall("s1", "write_todos", `{"todos":[{"content":"sub step","status":"pending"}]}`), nil
	case last.Role == schema.User:
		return toolCall("p1", "task", `{"description":"sub job"}`), nil
	default:
		return schema.AssistantMessage("done", nil), nil
	}
}

func TestRun_ConcurrentRunsShareNoMutableState(t *testing.T) {
	t.Parallel()

	// Concurrent runs over ONE shared *Agent, each with its own runState.
	// Each run delegates a sub-task whose sub-run writes todos — exercising
	// depth, todos, and rendering concurrently. The -race suite is the assertion;
	// the answers prove all runs completed the full delegation script.
	a := newTestAgent(concurrentScriptModel{}, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 5
	a.metrics = metrics.NewAccumulator("p", "m")
	a.metrics.StartTurn()
	a.tools.tools["task"] = newTaskTool(a)
	a.tools.tools["write_todos"] = newWriteTodosTool(a)

	const runs = 4

	var wg sync.WaitGroup
	answers := make([]string, runs)
	errs := make([]error, runs)
	for i := range runs {
		wg.Go(func() {
			rs := &runState{depth: 0, out: io.Discard}
			seed := []*schema.Message{schema.SystemMessage("SYS"), schema.UserMessage("question")}
			answers[i], errs[i] = a.run(context.Background(), rs, seed, 5)
		})
	}
	wg.Wait()

	for i := range runs {
		if errs[i] != nil {
			t.Fatalf("run %d: %v", i, errs[i])
		}
		if answers[i] != "done" {
			t.Errorf("run %d answer = %q, want done", i, answers[i])
		}
	}

	if got := a.metrics.Snapshot().Subagents; got != runs {
		t.Errorf("subagents = %d, want %d (every run must have delegated)", got, runs)
	}
}

func TestRun_CountersAccumulateAcrossTurns(t *testing.T) {
	t.Parallel()

	model := &capturingModel{ret: schema.AssistantMessage("a1", nil)} //nolint:exhaustruct // seen/calls zero.
	cfg := baseConfig()
	cfg.Model = model
	cfg.Metrics = metrics.NewAccumulator("p", "m")

	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q1", io.Discard); err != nil {
		t.Fatalf("Run #1: %v", err)
	}
	if s := cfg.Metrics.Snapshot(); s.RoundTrips != 1 {
		t.Errorf("round-trips after turn 1 = %d, want 1", s.RoundTrips)
	}
	if err := a.Run(context.Background(), "q2", io.Discard); err != nil {
		t.Fatalf("Run #2: %v", err)
	}

	// Counters are session-cumulative: turn 2's Generate adds to turn 1's.
	if s := cfg.Metrics.Snapshot(); s.RoundTrips != 2 {
		t.Errorf("round-trips after turn 2 = %d, want 2 (cumulative)", s.RoundTrips)
	}
}

func TestRun_ClosesTurnForActiveTime(t *testing.T) {
	t.Parallel()

	// EndTurn (deferred in Run) closes the active window, so after Run the turn is
	// not open: repeated Snapshots report a stable Elapsed. With the window left
	// open (EndTurn missing) an injected advancing clock would grow it each read.
	advancing := func() func() time.Time {
		cur := time.Unix(0, 0)
		return func() time.Time {
			t := cur
			cur = cur.Add(time.Second)
			return t
		}
	}()

	model := &capturingModel{ret: schema.AssistantMessage("a1", nil)} //nolint:exhaustruct // seen/calls zero.
	cfg := baseConfig()
	cfg.Model = model
	cfg.Metrics = metrics.NewAccumulator("p", "m", metrics.WithClock(advancing))

	a := New(context.Background(), cfg)
	if err := a.Run(context.Background(), "q1", io.Discard); err != nil {
		t.Fatalf("Run: %v", err)
	}

	e1 := cfg.Metrics.Snapshot().Elapsed
	e2 := cfg.Metrics.Snapshot().Elapsed
	if e1 != e2 {
		t.Errorf("turn left open: Elapsed grew %v → %v (EndTurn not wired)", e1, e2)
	}
}

// budgetLoopModel records usage on every Generate (simulating the production
// usage sink) and always returns a tool call, so the loop only stops when the
// budget halts it.
type budgetLoopModel struct {
	acc   *metrics.Accumulator
	usage schema.Usage
	calls int
}

var _ schema.ChatModel = (*budgetLoopModel)(nil)

func (m *budgetLoopModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.acc.AddUsage(m.usage)
	m.calls++

	return toolCall("c1", "echo", "{}"), nil
}

func TestRun_BudgetHaltsTurnWithNotice(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	model := &budgetLoopModel{acc: acc, usage: schema.Usage{TotalTokens: 50}, calls: 0}

	cfg := baseConfig()
	cfg.Model = model
	cfg.Metrics = acc
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: nil}}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "q", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if model.calls != 1 {
		t.Errorf("model calls = %d, want 1 (one Generate, then halt at the next top-check)", model.calls)
	}
	out := buf.String()
	if !strings.Contains(out, "Budget reached") || !strings.Contains(out, "token budget reached: 50 / 10 tokens") {
		t.Errorf("notice missing from output: %q", out)
	}
	if len(a.history) != 0 {
		t.Errorf("history len = %d, want 0 (no partial answer recorded on a budget halt)", len(a.history))
	}
}

// budgetAnswerModel records usage then returns a final answer (no tool calls),
// modeling a single Generate that both crosses the budget and finishes the turn.
type budgetAnswerModel struct {
	acc   *metrics.Accumulator
	usage schema.Usage
	calls int
}

var _ schema.ChatModel = (*budgetAnswerModel)(nil)

func (m *budgetAnswerModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.acc.AddUsage(m.usage)
	m.calls++

	return schema.AssistantMessage("THE-ANSWER", nil), nil
}

func TestRun_BudgetHaltsOnOverBudgetFinalAnswer(t *testing.T) {
	t.Parallel()

	// A single Generate that crosses the budget AND returns a final answer must
	// halt this turn (not silently complete and only stop on the next one).
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	model := &budgetAnswerModel{acc: acc, usage: schema.Usage{TotalTokens: 50}, calls: 0}

	cfg := baseConfig()
	cfg.Model = model
	cfg.Metrics = acc

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "q", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if model.calls != 1 {
		t.Errorf("model calls = %d, want 1", model.calls)
	}
	out := buf.String()
	if !strings.Contains(out, "Budget reached") {
		t.Errorf("want budget notice, got %q", out)
	}
	if strings.Contains(out, "THE-ANSWER") {
		t.Errorf("over-budget final answer must be suppressed, got %q", out)
	}
	if len(a.history) != 0 {
		t.Errorf("history len = %d, want 0 (over-budget answer not recorded)", len(a.history))
	}
}

// multiToolBudgetModel returns a top-level assistant message with two tool calls
// (a task delegation then an echo); the task sub-run records over-budget usage.
// It models a single message whose first tool call exhausts the budget.
type multiToolBudgetModel struct {
	acc *metrics.Accumulator
}

var _ schema.ChatModel = (*multiToolBudgetModel)(nil)

func (m *multiToolBudgetModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	last := msgs[len(msgs)-1]
	if last.Role == schema.User && last.Text() == "sub" {
		m.acc.AddUsage(schema.Usage{TotalTokens: 50}) // sub-run crosses the budget.

		return schema.AssistantMessage("sub done", nil), nil
	}

	return schema.AssistantMessage("", []schema.ToolCallBlock{
		{ID: "t1", Name: "task", Arguments: `{"description":"sub"}`},
		{ID: "e1", Name: "echo", Arguments: "{}"},
	}), nil
}

func TestRun_BudgetHaltsBeforeRemainingToolCalls(t *testing.T) {
	t.Parallel()

	// First tool call (a task sub-run) exhausts the budget; the second tool call
	// in the same message (echo) must not be dispatched.
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	ran := false

	cfg := baseConfig()
	cfg.Model = &multiToolBudgetModel{acc: acc}
	cfg.Metrics = acc
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: &ran}}

	a := New(context.Background(), cfg)
	a.maxSubagentIter = 3

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "go", &buf); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if ran {
		t.Error("echo (second tool call) must not run after the first exhausts the budget")
	}
	if !strings.Contains(buf.String(), "Budget reached") {
		t.Errorf("want budget notice, got %q", buf.String())
	}
}

func TestTaskTool_RespectsSharedBudget(t *testing.T) {
	t.Parallel()

	// Budget already exhausted when the sub-run starts: its first top-check halts
	// it and runScoped propagates the sentinel — the bound is cumulative across
	// task sub-runs.
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 20}) // over budget.

	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("unreached", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.metrics = acc
	a.maxSubagentIter = 5

	tool := newTaskTool(a)
	_, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"do a thing"}`)
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("err = %v, want errBudgetExceeded", err)
	}
	if model.calls != 0 {
		t.Errorf("sub-run model calls = %d, want 0 (halted before any Generate)", model.calls)
	}
}

// --- Interrupter seam tests ---

// fakeInterrupter is a test double for the Interrupter interface, reused across tasks.
type fakeInterrupter struct{ tripped, began, ended bool }

func (f *fakeInterrupter) Interrupted() bool { return f.tripped }
func (f *fakeInterrupter) BeginTurn()        { f.began = true }
func (f *fakeInterrupter) EndTurn()          { f.ended = true }

func TestAgent_InterruptHelpers_NilSafe(t *testing.T) {
	t.Parallel()

	a := &Agent{}        //nolint:exhaustruct // only the nil interrupter is under test.
	a.beginTurn()        // must not panic with a nil interrupter.
	a.endTurn()          // must not panic.
	if a.interrupted() { // nil interrupter never interrupts.
		t.Errorf("nil interrupter must report not-interrupted")
	}
}

func TestAgent_Run_BracketsInterrupterTurn(t *testing.T) {
	t.Parallel()

	fi := &fakeInterrupter{} //nolint:exhaustruct // tripped starts false.
	cfg := baseConfig()
	cfg.Model = &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("done", nil)}}
	cfg.Interrupter = fi
	cfg.Metrics = metrics.NewAccumulator("p", "m")

	a := New(context.Background(), cfg)

	if err := a.Run(context.Background(), "q", io.Discard); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !fi.began || !fi.ended {
		t.Errorf("Run must BeginTurn and EndTurn (began=%v ended=%v)", fi.began, fi.ended)
	}
}

// countInterrupter trips Interrupted() after exactly N calls (0-indexed: call N
// returns true, calls 0..N-1 return false). Used for timing-sensitive tests that
// need the interrupt to fire at a specific checkpoint rather than the top of the
// loop.
type countInterrupter struct {
	target int // the Nth Interrupted() call (0-based) that should return true.
	calls  int // counts Interrupted() invocations.
}

func (c *countInterrupter) Interrupted() bool {
	v := c.calls >= c.target
	c.calls++

	return v
}
func (c *countInterrupter) BeginTurn() {}
func (c *countInterrupter) EndTurn()   {}

// --- Interrupt checkpoint tests (C6) ---

// TestRun_InterruptAtTopOfLoop verifies that an already-tripped interrupter halts the
// turn immediately at the top of the first iteration: Run returns ErrInterrupted, the
// writer receives the terse notice, and nothing is appended to history.
func TestRun_InterruptAtTopOfLoop(t *testing.T) {
	t.Parallel()

	fi := &fakeInterrupter{tripped: true} //nolint:exhaustruct // began/ended zero.
	cfg := baseConfig()
	// The model would answer if called — but the interrupt must fire before Generate.
	cfg.Model = &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("should not appear", nil)}}
	cfg.Interrupter = fi

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt at top of loop: got err %v, want ErrInterrupted", err)
	}
	if !strings.Contains(buf.String(), "Stopped") {
		t.Errorf("terse notice missing from output: %q", buf.String())
	}
	if len(a.history) != 0 {
		t.Errorf("interrupted turn must record nothing to history, got %d entries", len(a.history))
	}
}

// TestRun_InterruptAfterGenerate verifies the post-Generate checkpoint: the model
// returns a tool call but the interrupter trips immediately after AddRoundTrip,
// before any tool is dispatched or the answer is rendered.
func TestRun_InterruptAfterGenerate(t *testing.T) {
	t.Parallel()

	// Call 0 = top-of-loop haltErr (false so we reach Generate).
	// Call 1 = post-Generate haltErr (true → fires the post-Generate checkpoint).
	ci := &countInterrupter{target: 1}

	var ran bool
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("should not appear", nil),
	}}
	cfg := baseConfig()
	cfg.Model = model
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: &ran}}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt post-Generate: got err %v, want ErrInterrupted", err)
	}
	if ran {
		t.Error("echo tool must not run when interrupt fires after Generate")
	}
	if !strings.Contains(buf.String(), "Stopped") {
		t.Errorf("terse notice missing from output: %q", buf.String())
	}
	if len(a.history) != 0 {
		t.Errorf("interrupted turn must record nothing to history, got %d entries", len(a.history))
	}
}

// TestRun_InterruptDuringGenerateWinsOverModelError verifies that a graceful stop
// requested while Generate is in flight surfaces ErrInterrupted even when that
// Generate also returns an error, instead of the generic model-failure error.
func TestRun_InterruptDuringGenerateWinsOverModelError(t *testing.T) {
	t.Parallel()

	// Call 0 = top-of-loop haltErr (false → reach Generate).
	// Call 1 = post-Generate haltErr, now ahead of the error return (true → wins).
	ci := &countInterrupter{target: 1}
	cfg := baseConfig()
	cfg.Model = &errModel{} // Generate always errors.
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt + model error: got %v, want ErrInterrupted", err)
	}
	if strings.Contains(err.Error(), "model generate") {
		t.Errorf("the interrupt must win over the model error, got %v", err)
	}
	if len(a.history) != 0 {
		t.Errorf("interrupted turn must record nothing to history, got %d entries", len(a.history))
	}
}

// TestRun_InterruptDuringFinalAnswerRenderDenies verifies the post-render checkpoint:
// a stop that lands while a tool-free final answer is being rendered still surfaces
// ErrInterrupted (exit 130) instead of recording the answer and exiting 0.
func TestRun_InterruptDuringFinalAnswerRenderDenies(t *testing.T) {
	t.Parallel()

	// Call 0 = top-of-loop (false). Call 1 = post-Generate (false). Call 2 = the
	// post-render final-answer re-check (true → halt before accepting the answer).
	ci := &countInterrupter{target: 2}
	cfg := baseConfig()
	cfg.Model = &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("the final answer", nil)}}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt during final-answer render: got %v, want ErrInterrupted", err)
	}
	if len(a.history) != 0 {
		t.Errorf("an interrupted final answer must not be recorded, got %d history entries", len(a.history))
	}
}

// TestRun_InterruptPostDispatch verifies the post-dispatch checkpoint: the model
// requests a tool call, it executes, and then the post-dispatch interrupt check
// fires before a second tool call (or the next iteration) would run.
func TestRun_InterruptPostDispatch(t *testing.T) {
	t.Parallel()

	// Call 0 = top-of-loop haltErr (false).
	// Call 1 = post-Generate haltErr (false).
	// Call 2 = invokeIO guard (direct interrupted() call, false → tool runs).
	// Call 3 = post-dispatch haltErr (true → halt).
	ci := &countInterrupter{target: 3}

	var ran bool
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("should not appear", nil),
	}}
	cfg := baseConfig()
	cfg.Model = model
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: &ran}}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt post-dispatch: got err %v, want ErrInterrupted", err)
	}
	// The echo tool ran before the post-dispatch check.
	if !ran {
		t.Error("echo tool must have run before the post-dispatch interrupt check")
	}
	if !strings.Contains(buf.String(), "Stopped") {
		t.Errorf("terse notice missing from output: %q", buf.String())
	}
	if len(a.history) != 0 {
		t.Errorf("interrupted turn must record nothing to history, got %d entries", len(a.history))
	}
}

// TestRun_InvokeIOGuard verifies the fail-closed guard inside invokeIO: when the
// interrupter is already tripped before invokeIO runs, the tool's Run must not
// be called. This exercises D5 of the task brief.
func TestRun_InvokeIOGuard(t *testing.T) {
	t.Parallel()

	// We test the invokeIO guard directly via the dispatch path.
	// Call 0 = top-of-loop haltErr (false) so we enter the iteration.
	// Call 1 = post-Generate haltErr (false) so we proceed past the model response.
	// Call 2 = invokeIO guard (direct interrupted() call, true → must skip t.Run).
	// The post-dispatch check (call 3) then returns true as well, surfacing errInterrupted.
	ci := &countInterrupter{target: 2}

	var ran bool
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
	}}
	cfg := baseConfig()
	cfg.Model = model
	cfg.Tools = []schema.InvokableTool{&echoTool{ran: &ran}}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("invokeIO guard: got err %v, want ErrInterrupted", err)
	}
	if ran {
		t.Error("echo tool must NOT run when invokeIO guard fires (D5 fail-closed)")
	}
}

// ctxWaitTool blocks in Run until its context is canceled, then records that it
// observed the cancellation — used to prove invokeIO cancels a running tool on a stop.
type ctxWaitTool struct{ canceled *bool }

var _ schema.InvokableTool = ctxWaitTool{}

func (ctxWaitTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "waiter", Desc: "", Params: nil}
}

func (w ctxWaitTool) Run(ctx context.Context, _ string) (string, error) {
	<-ctx.Done()
	*w.canceled = true

	return "canceled", nil
}

// TestInvokeIO_CancelsRunningToolOnInterrupt verifies that a graceful stop arriving
// while an approved tool runs cancels the dispatch context, so a long-running
// code_execution script stops promptly instead of running to its own timeout.
func TestInvokeIO_CancelsRunningToolOnInterrupt(t *testing.T) {
	t.Parallel()

	// Guard call (0) is false so t.Run starts; the poll's first tick (call 1) trips
	// and cancels the dispatch context, unblocking the waiting tool.
	ci := &countInterrupter{target: 1}
	var canceled bool
	tool := ctxWaitTool{canceled: &canceled}
	a := newTestAgent(answerOnceModel("x"), map[string]schema.InvokableTool{"waiter": tool})
	a.interrupter = ci
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   io.Discard,
		runID: "r",
	}

	out, _, err := a.invokeIO(context.Background(), rs, tool, dispatchTC("waiter", "{}"))
	if err != nil {
		t.Fatalf("invokeIO error: %v", err)
	}
	if !canceled {
		t.Error("the running tool's context was not canceled on a graceful stop")
	}
	if out == "" {
		t.Error("expected the tool's result to be returned")
	}
}

// ctxWaitModel blocks in Generate until its context is canceled, then returns the
// cancellation error — used to prove the loop cancels a hung model call on a stop.
type ctxWaitModel struct{}

var _ schema.ChatModel = ctxWaitModel{}

func (ctxWaitModel) Generate(ctx context.Context, _ []*schema.Message, _ []*schema.ToolInfo) (*schema.Message, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}

// TestRun_CancelsHungModelCallOnInterrupt verifies that the first graceful stop cancels
// an in-flight model call, so a one-shot is not stuck for the provider timeout.
func TestRun_CancelsHungModelCallOnInterrupt(t *testing.T) {
	t.Parallel()

	// Call 0 = top-of-loop (false) so Generate starts; the model poll's tick (call 1)
	// trips and cancels the model context, unblocking the hung Generate.
	ci := &countInterrupter{target: 1}
	cfg := baseConfig()
	cfg.Model = ctxWaitModel{}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "q", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("hung model + interrupt: got %v, want ErrInterrupted", err)
	}
	if len(a.history) != 0 {
		t.Errorf("interrupted turn must record nothing, got %d", len(a.history))
	}
}

// --- Consecutive-failure counter tests ---

// failingTool is a plain I/O tool that marks audit failure (not a Go error), so
// the loop treats it as a no-progress call and the result rides in the transcript.
type failingTool struct{ name string }

var _ schema.InvokableTool = (*failingTool)(nil)

func (f *failingTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: f.name, Desc: "", Params: nil}
}

func (f *failingTool) Run(ctx context.Context, _ string) (string, error) {
	audit.MarkFailed(ctx)

	return "Error: tool failed.", nil
}

// succeedingTool is a plain I/O tool that returns success (no audit failure).
type succeedingTool struct{ name string }

var _ schema.InvokableTool = (*succeedingTool)(nil)

func (s *succeedingTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: s.name, Desc: "", Params: nil}
}

func (s *succeedingTool) Run(context.Context, string) (string, error) {
	return "ok", nil
}

// haltBaseConfig builds a Config suitable for consecutive-failure tests: echo renderer,
// maxIterations = 10, maxSubagentIterations = 3.
func haltBaseConfig() Config {
	return Config{ //nolint:exhaustruct // Tools/Model/Metrics set per test
		Cfg: config.Config{ //nolint:exhaustruct // only the fields below matter
			RenderStyle:           "notty",
			MaxIterations:         10,
			MaxSubagentIterations: 3,
		},
		Providers: nil,
		Renderer:  echoRenderer,
	}
}

func TestRun_HaltsAfterNConsecutiveFailures(t *testing.T) {
	t.Parallel()

	// The scripted model calls "fail_tool" three times, then (when failureSummary calls
	// Generate without tools) answers with a summary. N = 3.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "fail_tool", "{}"),
		toolCall("c2", "fail_tool", "{}"),
		toolCall("c3", "fail_tool", "{}"),
		schema.AssistantMessage("I'm stuck: need a project id.", nil),
	}}

	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 3
	cfg.Tools = []schema.InvokableTool{&failingTool{name: "fail_tool"}}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "scan", &buf); err != nil {
		t.Fatalf("failure halt must not error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Stopped after 3 consecutive failures") {
		t.Errorf("expected the failure halt header, got %q", out)
	}
	if !strings.Contains(out, "project id") {
		t.Errorf("expected summary text in output, got %q", out)
	}
	// The summary is recorded to history so follow-up turns have context.
	if len(a.history) != 2 {
		t.Errorf("history length = %d, want 2 (question + summary answer)", len(a.history))
	}
}

func TestRun_SuccessResetsFailureStreak(t *testing.T) {
	t.Parallel()

	// Pattern: fail, fail, succeed, fail, fail → streak is 2 everywhere → no halt with N=3.
	// The final model turn returns a text answer (no tool call).
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "fail_tool", "{}"),
		toolCall("c2", "fail_tool", "{}"),
		toolCall("c3", "good_tool", "{}"),
		toolCall("c4", "fail_tool", "{}"),
		toolCall("c5", "fail_tool", "{}"),
		schema.AssistantMessage("done without halt", nil),
	}}

	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 3
	cfg.Tools = []schema.InvokableTool{
		&failingTool{name: "fail_tool"},
		&succeedingTool{name: "good_tool"},
	}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "scan", &buf); err != nil {
		t.Fatalf("no halt expected: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Stopped after") {
		t.Errorf("success must reset the streak, no halt expected; got %q", out)
	}
	if !strings.Contains(out, "done without halt") {
		t.Errorf("expected final answer, got %q", out)
	}
}

func TestRun_MaxConsecutiveFailuresZeroDisables(t *testing.T) {
	t.Parallel()

	// With MaxConsecutiveFailures = 0 the feature is disabled; even an all-failing run
	// hits the iteration limit, NOT the failure halt header.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "fail_tool", "{}"),
		toolCall("c2", "fail_tool", "{}"),
	}}

	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 0
	cfg.Cfg.MaxIterations = 2 // exhaust after 2 iterations.
	cfg.Tools = []schema.InvokableTool{&failingTool{name: "fail_tool"}}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "scan", &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Stopped after") {
		t.Errorf("zero disables the halt; got %q", out)
	}
	if !strings.Contains(out, "Reached the iteration limit") {
		t.Errorf("expected iteration-limit notice; got %q", out)
	}
}

func TestRun_DenialCountsAsFailure(t *testing.T) {
	t.Parallel()

	// A denial (approval-denied call) must increment consecutiveFailures.
	// We use a tool whose Run returns the deniedResult sentinel string; after N=2
	// denials the halt fires.
	const denyMsg = "DENIED"
	denyingTool := funcTool{name: "http_request", run: func(ctx context.Context, _ string) (string, error) {
		audit.RecordDecision(ctx, false)

		return denyMsg, nil
	}}

	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "http_request", "{}"),
		toolCall("c2", "http_request", "{}"),
		schema.AssistantMessage("I was denied twice — need a credential.", nil),
	}}

	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 2
	cfg.DeniedToolResult = denyMsg
	cfg.Tools = []schema.InvokableTool{denyingTool}

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	if err := a.Run(context.Background(), "scan", &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Stopped after 2 consecutive failures") {
		t.Errorf("denial must count as failure; got %q", buf.String())
	}
}

func TestFailuresExhausted_ZeroDisables(t *testing.T) {
	t.Parallel()

	a := &Agent{maxConsecutiveFailures: 0} //nolint:exhaustruct // only field under test.
	rs := &runState{consecutiveFailures: 999}

	if a.failuresExhausted(rs) {
		t.Error("zero ceiling must disable the trigger even with high consecutiveFailures")
	}
}

func TestFailuresExhausted_PositiveCeiling(t *testing.T) {
	t.Parallel()

	a := &Agent{maxConsecutiveFailures: 3} //nolint:exhaustruct // only field under test.

	if a.failuresExhausted(&runState{consecutiveFailures: 2}) {
		t.Error("2 < 3, should not be exhausted")
	}
	if !a.failuresExhausted(&runState{consecutiveFailures: 3}) {
		t.Error("3 >= 3, should be exhausted")
	}
	if !a.failuresExhausted(&runState{consecutiveFailures: 5}) {
		t.Error("5 >= 3, should be exhausted")
	}
}

func TestRun_FailureSummaryInterruptPropagates(t *testing.T) {
	t.Parallel()

	// Verify the line-144 path: failuresExhausted triggers but failureSummary
	// itself returns errInterrupted (interrupt fires between the haltErr check in
	// dispatchAndTrack and the pre-check inside failureSummary).
	//
	// Call sequence with maxConsecutiveFailures=1 and one failing tool:
	//   0: top-of-loop haltErr → Interrupted() (false, enter iteration)
	//   1: post-Generate haltErr → Interrupted() (false, proceed to dispatch)
	//   2: invokeIO guard → Interrupted() (false, tool runs and fails)
	//   3: dispatchAndTrack's haltErr → Interrupted() (false, pass)
	//   4: failureSummary pre-check → Interrupted() (true → errInterrupted)
	ci := &countInterrupter{target: 4}

	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "fail_tool", "{}"),
	}}

	cfg := haltBaseConfig()
	cfg.Model = model
	cfg.Cfg.MaxConsecutiveFailures = 1
	cfg.Tools = []schema.InvokableTool{&failingTool{name: "fail_tool"}}
	cfg.Interrupter = ci

	a := New(context.Background(), cfg)

	var buf bytes.Buffer
	err := a.Run(context.Background(), "scan", &buf)
	if !errors.Is(err, ErrInterrupted) {
		t.Errorf("failureSummary errInterrupted must propagate through Run: got %v", err)
	}
}

func TestCreditedFailures(t *testing.T) {
	t.Parallel()

	oc := func(outcome string, failures, progress int) callOutcome {
		return callOutcome{decision: "", outcome: outcome, result: "", failures: failures, progress: progress}
	}
	for name, tc := range map[string]struct {
		oc   callOutcome
		want int
	}{
		"explicit inner count":        {oc(audit.OutcomeError, 3, 0), 3},
		"denial floors to one":        {oc(audit.OutcomeDenied, 0, 0), 1},
		"go error floors to one":      {oc(audit.OutcomeError, 0, 0), 1},
		"ok is zero":                  {oc(audit.OutcomeOK, 0, 0), 0},
		"progress overrides failures": {oc(audit.OutcomeError, 5, 2), 0}, // mixed fan-out → not stuck.
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := creditedFailures(tc.oc); got != tc.want {
				t.Errorf("creditedFailures = %d, want %d", got, tc.want)
			}
		})
	}
}

// multiFailTool marks the failure recorder n times, simulating a code_execution
// script whose n inner http_request calls each returned >=400.
type multiFailTool struct{ n int }

func (multiFailTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "multifail", Desc: "", Params: nil}
}

func (m multiFailTool) Run(ctx context.Context, _ string) (string, error) {
	for range m.n {
		audit.MarkFailed(ctx)
	}

	return "done", nil
}

// TestDispatch_CountsEachInnerFailure verifies a batched call's inner failures each
// credit the consecutive-failure counter instead of collapsing into a single +1.
func TestDispatch_CountsEachInnerFailure(t *testing.T) {
	t.Parallel()

	a := newTestAgent(answerOnceModel("x"), map[string]schema.InvokableTool{"multifail": multiFailTool{n: 3}})
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   io.Discard,
		runID: "r",
	}

	_, failures, err := a.dispatch(context.Background(), rs, dispatchTC("multifail", "{}"))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if failures != 3 {
		t.Errorf("dispatch failures = %d, want 3 (one per inner mark)", failures)
	}
}

// mixedOutcomeTool marks both failures and progress, simulating a code_execution
// fan-out that got some 4xx responses and some useful 2xx ones.
type mixedOutcomeTool struct{}

func (mixedOutcomeTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "mixed", Desc: "", Params: nil}
}

func (mixedOutcomeTool) Run(ctx context.Context, _ string) (string, error) {
	audit.MarkFailed(ctx)
	audit.MarkFailed(ctx)
	audit.MarkProgress(ctx)

	return "ok", nil
}

// TestDispatch_MixedOutcomeCreditsZero verifies a fan-out that made progress does not
// add to the consecutive-failure streak even though some inner calls failed.
func TestDispatch_MixedOutcomeCreditsZero(t *testing.T) {
	t.Parallel()

	a := newTestAgent(answerOnceModel("x"), map[string]schema.InvokableTool{"mixed": mixedOutcomeTool{}})
	rs := &runState{ //nolint:exhaustruct // consecutiveFailures zero-init is correct.
		depth: 0,
		out:   io.Discard,
		runID: "r",
	}

	_, credited, err := a.dispatch(context.Background(), rs, dispatchTC("mixed", "{}"))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if credited != 0 {
		t.Errorf("a mixed-success call must credit 0 failures (made progress), got %d", credited)
	}
}

func TestNew_WiresAbout(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{}
	cfg.About = "PRODUCT BLURB"

	a := New(context.Background(), cfg)
	if !strings.Contains(a.systemPrompt, "About cynative:") || !strings.Contains(a.systemPrompt, "PRODUCT BLURB") {
		t.Errorf("New did not weave Config.About into the system prompt: %q", a.systemPrompt)
	}
}

// --- OnFirstResponse hook tests ---

func TestNew_WiresOnFirstResponse(t *testing.T) {
	t.Parallel()

	called := false
	hook := func() { called = true }

	cfg := baseConfig()
	cfg.Model = &scriptedModel{}
	cfg.OnFirstResponse = hook

	a := New(context.Background(), cfg)

	// The field must be set to the same func value (pointer equality).
	if a.onFirstResponse == nil {
		t.Fatal("New did not wire Config.OnFirstResponse onto the agent")
	}
	// Invoke via the agent's copy to confirm it is the same func.
	a.onFirstResponse()
	if !called {
		t.Error("agent.onFirstResponse is not the Config.OnFirstResponse func")
	}
}

func TestRun_FiresOnFirstResponseAtDepthZeroBeforeRender(t *testing.T) {
	t.Parallel()

	var order []string
	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("done", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.renderer = func(*schema.Message, string, io.Writer) { order = append(order, "render") }
	a.onFirstResponse = func() { order = append(order, "hook") }

	if _, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(order) != 2 || order[0] != "hook" || order[1] != "render" {
		t.Fatalf("order = %v, want [hook render]", order)
	}
}

func TestRun_FiresOnFirstResponseOncePerRun(t *testing.T) {
	t.Parallel()

	calls := 0
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "echo", "{}"),
		schema.AssistantMessage("final", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})
	a.onFirstResponse = func() { calls++ }

	if _, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("hook fired %d times, want 1", calls)
	}
}

func TestRun_DoesNotFireOnFirstResponseAtDepthGtZero(t *testing.T) {
	t.Parallel()

	calls := 0
	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("sub done", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.onFirstResponse = func() { calls++ }

	if _, err := a.run(context.Background(), &runState{depth: 1, out: io.Discard}, nil, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 0 {
		t.Errorf("hook fired %d times at depth 1, want 0", calls)
	}
}

func TestRun_NilOnFirstResponseIsSafe(t *testing.T) {
	t.Parallel()

	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("done", nil)}}
	a := newTestAgent(model, map[string]schema.InvokableTool{}) // onFirstResponse is nil.

	answer, err := a.run(context.Background(), &runState{depth: 0, out: io.Discard}, nil, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if answer != "done" {
		t.Errorf("answer = %q, want %q", answer, "done")
	}
}
