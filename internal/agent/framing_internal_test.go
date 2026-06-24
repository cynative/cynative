package agent

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

// fakeIOTool is a plain (non-runScoped) tool whose Run returns fixed content.
type fakeIOTool struct{ out string }

func (f fakeIOTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "http_request"}, nil
}
func (f fakeIOTool) Run(context.Context, string) (string, error) { return f.out, nil }

// errScopedTool is a runScoped (orchestration) tool whose runScoped returns a
// Go error, exercising dispatch's orchestration-error branch.
type errScopedTool struct{}

var _ runScopedTool = errScopedTool{}

func (errScopedTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "write_todos"}, nil
}

func (errScopedTool) Run(context.Context, string) (string, error) {
	return orchestrationOutsideLoop, nil
}

func (errScopedTool) runScoped(context.Context, *runState, string) (string, error) {
	return "", errors.New("scoped boom")
}

func TestDispatch_FramesIOToolResult(t *testing.T) {
	t.Parallel()

	a := newTestAgent(nil, map[string]schema.InvokableTool{
		"http_request": fakeIOTool{out: "EXTERNAL BODY"},
	})
	rs := &runState{depth: 0, out: io.Discard}

	got, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{
		ID: "1", Name: "http_request", Arguments: "{}",
	})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}

	if !strings.HasPrefix(got, `<tool_output tool="http_request">`) {
		t.Errorf("I/O result not framed: %q", got)
	}
	if !strings.Contains(got, "EXTERNAL BODY") {
		t.Errorf("content missing: %q", got)
	}
}

func TestDispatch_DoesNotFrameOrchestrationResult(t *testing.T) {
	t.Parallel()

	a := newTestAgent(nil, nil)
	a.tools = toolset{tools: map[string]schema.InvokableTool{"write_todos": newWriteTodosTool(a)}}
	rs := &runState{depth: 0, out: io.Discard}

	got, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{
		ID: "1", Name: "write_todos", Arguments: `{"todos":[{"content":"x","status":"pending"}]}`,
	})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}

	if strings.Contains(got, "<tool_output") {
		t.Errorf("orchestration result must not be framed: %q", got)
	}
}

func TestDispatch_OrchestrationError(t *testing.T) {
	t.Parallel()

	a := newTestAgent(nil, map[string]schema.InvokableTool{"write_todos": errScopedTool{}})
	rs := &runState{depth: 0, out: io.Discard}

	got, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{
		ID: "1", Name: "write_todos", Arguments: "{}",
	})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}

	// An orchestration tool's Go error becomes an unframed error-result string.
	if !strings.Contains(got, "Error executing tool") {
		t.Errorf("dispatch = %q, want tool-error message", got)
	}
	if strings.Contains(got, "<tool_output") {
		t.Errorf("orchestration error must not be framed: %q", got)
	}
}

// fakeDenyTool is a plain (non-runScoped) tool that returns a fixed denial string.
type fakeDenyTool struct{ msg string }

func (f fakeDenyTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "http_request"}, nil
}
func (f fakeDenyTool) Run(context.Context, string) (string, error) { return f.msg, nil }

func TestDispatch_DoesNotFrameApprovalDenial(t *testing.T) {
	t.Parallel()

	const denied = "User denied execution of this tool call."
	a := newTestAgent(nil, map[string]schema.InvokableTool{
		"http_request": fakeDenyTool{msg: denied},
	})
	a.deniedResult = denied
	rs := &runState{depth: 0, out: io.Discard}

	got, _, derr := a.dispatch(context.Background(), rs, schema.ToolCallBlock{
		ID: "1", Name: "http_request", Arguments: "{}",
	})
	if derr != nil {
		t.Fatalf("dispatch: %v", derr)
	}
	if got != denied {
		t.Errorf("approval denial must be returned unframed; got %q", got)
	}
	if strings.Contains(got, "<tool_output") {
		t.Errorf("denial must not be framed: %q", got)
	}
}
