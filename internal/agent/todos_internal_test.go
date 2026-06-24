package agent

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

func TestNewWriteTodosTool_Info(t *testing.T) {
	t.Parallel()

	tool := newWriteTodosTool(newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{}))

	info, err := tool.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "write_todos" {
		t.Errorf("name = %q, want write_todos", info.Name)
	}
	if info.Params == nil {
		t.Error("expected non-nil params schema")
	}

	for _, want := range []string{"genuinely multi-step", "single objective", "tick boxes"} {
		if !strings.Contains(info.Desc, want) {
			t.Errorf("write_todos desc missing %q; got: %s", want, info.Desc)
		}
	}
	if strings.Contains(info.Desc, "Call this first") {
		t.Errorf("write_todos desc still says 'Call this first': %s", info.Desc)
	}
}

func TestWriteTodosTool_RunSuccess(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	a.renderer = echoRenderer

	tool := newWriteTodosTool(a)
	rs := &runState{depth: 0, out: &buf, todos: nil}

	const args = `{"todos":[{"content":"enumerate buckets","status":"in_progress"},` +
		`{"content":"check policy","status":"pending"}]}`

	out, err := tool.runScoped(context.Background(), rs, args)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "Recorded 2 todo(s)") {
		t.Errorf("out = %q, want recorded count", out)
	}
	if len(rs.todos) != 2 {
		t.Fatalf("run todos length = %d, want 2", len(rs.todos))
	}
	// renderTodos was called against the run's output writer.
	if !strings.Contains(buf.String(), "enumerate buckets") {
		t.Errorf("render output = %q, want rendered todos", buf.String())
	}
}

func TestWriteTodosTool_RunParseFail(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})
	tool := newWriteTodosTool(a)
	rs := &runState{depth: 0, out: &buf, todos: nil}

	out, err := tool.runScoped(context.Background(), rs, `not json at all`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "Could not parse todos") {
		t.Errorf("out = %q, want parse-failure message", out)
	}
	if rs.todos != nil {
		t.Errorf("run todos = %v, want unchanged (nil)", rs.todos)
	}
}

func TestParseTodos_Strict(t *testing.T) {
	t.Parallel()

	got, ok := parseTodos(`{"todos":[{"content":"a","status":"completed"}]}`)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := []todo{{Content: "a", Status: todoCompleted}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTodos_StringEncoded(t *testing.T) {
	t.Parallel()

	// Some models double-encode the array as a JSON string.
	got, ok := parseTodos(`{"todos":"[{\"content\":\"a\",\"status\":\"pending\"}]"}`)
	if !ok {
		t.Fatal("expected ok=true for string-encoded todos")
	}
	if len(got) != 1 || got[0].Content != "a" {
		t.Errorf("got %v, want single todo a", got)
	}
}

func TestParseTodos_Malformed(t *testing.T) {
	t.Parallel()

	if _, ok := parseTodos(`@@@`); ok {
		t.Error("expected ok=false for unparseable payload")
	}
}

func TestParseTodos_StringEncodedInnerMalformed(t *testing.T) {
	t.Parallel()

	// The outer wrapper parses (todos is a string), but the inner string is not
	// a valid todos array.
	if _, ok := parseTodos(`{"todos":"not-an-array"}`); ok {
		t.Error("expected ok=false when the inner string is not a todos array")
	}
}

func TestNormalizeStatuses_DefaultsUnknown(t *testing.T) {
	t.Parallel()

	got := normalizeStatuses([]todo{
		{Content: "a", Status: todoStatus("")},
		{Content: "b", Status: todoStatus("bogus")},
		{Content: "c", Status: todoInProgress},
	})
	if got[0].Status != todoPending || got[1].Status != todoPending {
		t.Errorf("unknown statuses not defaulted to pending: %v", got)
	}
	if got[2].Status != todoInProgress {
		t.Errorf("valid status mutated: %v", got[2])
	}
}

func TestOrchestrationTools_PublicRunReturnsGuidance(t *testing.T) {
	t.Parallel()

	a := newTestAgent(&scriptedModel{}, map[string]schema.InvokableTool{})

	for name, tool := range map[string]schema.InvokableTool{
		"write_todos": newWriteTodosTool(a),
		"task":        newTaskTool(a),
	} {
		out, err := tool.Run(context.Background(), `{}`)
		if err != nil {
			t.Fatalf("%s Run: %v", name, err)
		}
		if out != orchestrationOutsideLoop {
			t.Errorf("%s Run = %q, want the outside-loop guidance", name, out)
		}
	}
}

func TestWriteTodos_SubRunDoesNotTouchParentState(t *testing.T) {
	t.Parallel()

	// A write_todos call inside a task sub-run renders to the sub-run's writer
	// (the verbose writer) and leaves the parent run's plan and output untouched.
	model := &scriptedModel{msgs: []*schema.Message{
		toolCall("c1", "write_todos", `{"todos":[{"content":"sub step","status":"pending"}]}`),
		schema.AssistantMessage("sub done", nil),
	}}
	a := newTestAgent(model, map[string]schema.InvokableTool{})
	a.maxSubagentIter = 5
	a.renderer = echoRenderer

	var verbose bytes.Buffer
	a.verbose = &verbose

	todosTool := newWriteTodosTool(a)
	a.tools.tools["write_todos"] = todosTool

	var parentOut bytes.Buffer
	parent := &runState{depth: 0, out: &parentOut, todos: nil}

	taskT := newTaskTool(a)
	if _, err := taskT.runScoped(context.Background(), parent, `{"description":"sub job"}`); err != nil {
		t.Fatalf("runScoped: %v", err)
	}

	if parent.todos != nil {
		t.Errorf("parent todos = %v, want untouched nil", parent.todos)
	}
	if strings.Contains(parentOut.String(), "sub step") {
		t.Errorf("parent output %q contains the sub-run checklist", parentOut.String())
	}
	if !strings.Contains(verbose.String(), "sub step") {
		t.Errorf("verbose output %q missing the sub-run checklist", verbose.String())
	}
}
