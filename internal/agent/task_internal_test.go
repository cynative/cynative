package agent

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

// rootState returns a fresh top-level runState writing to w.
func rootState(w io.Writer) *runState {
	return &runState{depth: 0, out: w, todos: nil}
}

func TestNewTaskTool_Info(t *testing.T) {
	t.Parallel()

	tool := newTaskTool(newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{}))

	info, err := tool.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "task" {
		t.Errorf("name = %q, want task", info.Name)
	}
	if info.Params == nil {
		t.Error("expected non-nil params schema")
	}
}

func TestTaskTool_RunUnparseable(t *testing.T) {
	t.Parallel()

	tool := newTaskTool(newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{}))

	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `@@@`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "non-empty 'description'") {
		t.Errorf("out = %q, want description prompt", out)
	}
}

func TestTaskTool_RunEmptyDescription(t *testing.T) {
	t.Parallel()

	tool := newTaskTool(newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{}))

	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":""}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "non-empty 'description'") {
		t.Errorf("out = %q, want description prompt", out)
	}
}

func TestTaskTool_RunFreshSeedAndSummary(t *testing.T) {
	t.Parallel()

	// The sub-agent seed must be exactly [system, user(description)] — fresh, not
	// the parent transcript — and the sub-run's final answer is returned verbatim.
	model := &capturingModel{ret: schema.AssistantMessage("sub summary", nil)} //nolint:exhaustruct // seen/calls zero
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.systemPrompt = "SYS"
	a.maxSubagentIter = 5

	tool := newTaskTool(a)

	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"investigate X"}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// task fences its summary as untrusted, so the answer rides inside the fence.
	if !strings.Contains(out, "sub summary") {
		t.Errorf("out = %q, want to contain sub summary", out)
	}
	if len(model.seen) != 2 {
		t.Fatalf("sub seed length = %d, want 2", len(model.seen))
	}
	if model.seen[0].Role != schema.System || model.seen[0].Text() != "SYS" {
		t.Errorf("sub seed[0] = %+v, want system SYS", model.seen[0])
	}
	if model.seen[1].Role != schema.User || model.seen[1].Text() != "investigate X" {
		t.Errorf("sub seed[1] = %+v, want user description", model.seen[1])
	}
}

func TestTaskTool_RunIterationLimit(t *testing.T) {
	t.Parallel()

	// The sub-agent always calls a tool, so its run exhausts maxSubagentIter and
	// returns ""; the task tool reports the limit message.
	model := &scriptedModel{msgs: []*schema.Message{toolCall("c1", "echo", "{}")}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})
	a.maxSubagentIter = 1

	tool := newTaskTool(a)

	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"loop forever"}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "reached its iteration limit") {
		t.Errorf("out = %q, want iteration-limit message", out)
	}
}

func TestTaskTool_RunSubModelError(t *testing.T) {
	t.Parallel()

	// A sub-run model error propagates as a Go error from the task tool.
	a := newTestAgent(&errModel{}, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 3

	tool := newTaskTool(a)

	_, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"go"}`)
	if err == nil {
		t.Fatal("expected propagated sub-run error")
	}
}

func TestTaskTool_RunDepthGuardRefuses(t *testing.T) {
	t.Parallel()

	// A sub-agent already at the max nesting depth must refuse to delegate: it
	// returns the guidance string and never starts a sub-run (model untouched).
	model := &capturingModel{ret: schema.AssistantMessage("unreached", nil)} //nolint:exhaustruct // seen/calls zero
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 3

	tool := newTaskTool(a)

	rs := &runState{depth: maxTaskDepth, out: io.Discard, todos: nil} // Simulate being inside a sub-run.
	out, err := tool.runScoped(context.Background(), rs, `{"description":"go deeper"}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "cannot themselves delegate") {
		t.Errorf("out = %q, want delegation-refusal guidance", out)
	}
	if model.calls != 0 {
		t.Errorf("model called %d times, want 0 (sub-run must not start)", model.calls)
	}
}

func TestTaskTool_SubRunDelegationRefused(t *testing.T) {
	t.Parallel()

	// The sub-run's first turn tries to delegate again. The nested task call must
	// be refused via the sub-run's elevated rs.depth WITHOUT consuming a model
	// turn: exactly two Generate calls happen (sub-run turn 1 and turn 2). If the
	// nested call started a sub-sub-run, it would consume the second scripted
	// message as its answer and the outer sub-run would error out of script.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("n1", "task", `{"description":"nested"}`),
		schema.AssistantMessage("sub done", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 5

	tool := newTaskTool(a)
	a.tools.tools["task"] = tool

	out, err := tool.runScoped(context.Background(), rootState(io.Discard), `{"description":"outer"}`)
	if err != nil {
		t.Fatalf("runScoped: %v", err)
	}
	// The outer task fences its summary as untrusted; the content rides inside.
	if !strings.Contains(out, "sub done") {
		t.Errorf("out = %q, want to contain %q", out, "sub done")
	}
	if model.calls != 2 {
		t.Errorf("model calls = %d, want 2 (nested task must not start a run)", model.calls)
	}
}

func TestTaskTool_RunBracketsSubRun(t *testing.T) {
	t.Parallel()

	// The bracket notices surround the sub-run on the main output: a start notice
	// with the description, and a completion close on the answered path.
	model := &capturingModel{ret: schema.AssistantMessage("sub summary", nil)} //nolint:exhaustruct // seen/calls zero
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 3
	a.renderer = echoRenderer

	var buf bytes.Buffer

	if _, err := newTaskTool(a).runScoped(
		context.Background(), rootState(&buf), `{"description":"investigate X"}`,
	); err != nil {
		t.Fatalf("Run: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "▶ Delegating sub-task: investigate X") {
		t.Errorf("out = %q, want start notice", out)
	}
	if !strings.Contains(out, "■ Sub-task complete") {
		t.Errorf("out = %q, want completion notice", out)
	}
	// The sub-agent's own prose routes to the verbose writer, never the main
	// output — only the bracket notices may appear there.
	if strings.Contains(out, "sub summary") {
		t.Errorf("out = %q, sub-agent summary leaked onto the main output", out)
	}
}

func TestTaskTool_RunBracketsIterationLimit(t *testing.T) {
	t.Parallel()

	// The iteration-limit path also closes the bracket with the completion notice.
	model := &scriptedModel{msgs: []*schema.Message{toolCall("c1", "echo", "{}")}}
	a := newTestAgent(model, map[string]schema.InvokableTool{"echo": &echoTool{ran: nil}})
	a.maxSubagentIter = 1
	a.renderer = echoRenderer

	var buf bytes.Buffer

	out, err := newTaskTool(a).runScoped(context.Background(), rootState(&buf), `{"description":"loop forever"}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "reached its iteration limit") {
		t.Errorf("out = %q, want iteration-limit message", out)
	}
	if !strings.Contains(buf.String(), "■ Sub-task complete") {
		t.Errorf("rendered = %q, want completion notice", buf.String())
	}
}

func TestTaskTool_RunBracketsFailureOnSubModelError(t *testing.T) {
	t.Parallel()

	// A sub-run Go error must still close the bracket: dispatch stringifies the
	// error and the parent loop continues, so a dangling open bracket would be
	// visible to the human.
	a := newTestAgent(&errModel{}, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 3
	a.renderer = echoRenderer

	var buf bytes.Buffer

	if _, err := newTaskTool(a).runScoped(context.Background(), rootState(&buf), `{"description":"go"}`); err == nil {
		t.Fatal("expected propagated sub-run error")
	}

	out := buf.String()
	if !strings.Contains(out, "▶ Delegating sub-task: go") {
		t.Errorf("out = %q, want start notice", out)
	}
	if !strings.Contains(out, "■ Sub-task failed") {
		t.Errorf("out = %q, want failure notice", out)
	}
}

func TestTaskTool_RunNoBracketOnRefusedCalls(t *testing.T) {
	t.Parallel()

	// Bad args and the depth guard return guidance without starting a sub-run, so
	// no bracket notices may appear.
	model := &capturingModel{ret: schema.AssistantMessage("unreached", nil)} //nolint:exhaustruct // seen/calls zero
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 3
	a.renderer = echoRenderer

	var buf bytes.Buffer

	tool := newTaskTool(a)
	if _, err := tool.runScoped(context.Background(), rootState(&buf), `@@@`); err != nil {
		t.Fatalf("Run bad args: %v", err)
	}

	atDepth := &runState{depth: maxTaskDepth, out: &buf, todos: nil}
	if _, err := tool.runScoped(context.Background(), atDepth, `{"description":"go deeper"}`); err != nil {
		t.Fatalf("Run at depth: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("rendered = %q, want no bracket notices", buf.String())
	}
}
