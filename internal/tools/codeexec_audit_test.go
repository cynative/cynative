package tools_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/sandbox"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// captureSink records audit Records; may fail on a chosen phase.
type captureSink struct {
	recs    []audit.Record
	failOn  string
	failErr error
}

func (s *captureSink) Log(rec audit.Record) error {
	s.recs = append(s.recs, rec)
	if s.failOn != "" && rec.Phase == s.failOn {
		return s.failErr
	}

	return nil
}

// echoTool is a tiny inner primitive the sandbox can call.
type echoTool struct {
	err error
}

func (echoTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "http_request", Desc: "echo", Params: nil}, nil
}

func (e echoTool) Run(_ context.Context, args string) (string, error) {
	if e.err != nil {
		return "", e.err
	}

	return args, nil
}

// fakeRunner is a codeRunner that invokes a registered tool func directly,
// simulating a script that makes one inner call. It pulls the func map via the
// sandbox factory seam.
//
// NOTE: implement this by injecting WithCodeSandboxFactory so the returned
// codeRunner, on Run, looks up funcs["http_request"] and calls it with the ctx
// it received (preserving audit.Scope/Fatal). See Step 4 for the exact seam.

func newCodeToolWithFakeSandbox(
	t *testing.T,
	sink audit.Sink,
	inner schema.InvokableTool,
	call func(context.Context, map[string]sandbox.ToolFunc) (string, error),
) schema.InvokableTool {
	t.Helper()

	tool, err := tools.NewCodeExecutionToolWithSink(
		[]schema.InvokableTool{inner},
		io.Discard,
		4,
		sink,
		tools.WithCodeIDFunc(func() string { return "INNER" }),
		tools.WithCodeSandboxFactory(
			func(funcs map[string]sandbox.ToolFunc, _ io.Writer, _ int) (tools.CodeRunner, error) {
				return tools.RunnerFunc(func(ctx context.Context, _ string, _ time.Duration) (string, error) {
					return call(ctx, funcs)
				}), nil
			},
		),
	)
	if err != nil {
		t.Fatalf("build code tool: %v", err)
	}

	return tool
}

func TestCodeExec_InnerCall_AuditsAttemptAndResult(t *testing.T) {
	t.Parallel()

	sink := &captureSink{} //nolint:exhaustruct // failOn/failErr zero-value means never fail.
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{"url":"https://x"}`)
		})

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.recs) != 2 {
		t.Fatalf("want 2 inner records, got %d", len(sink.recs))
	}
	if sink.recs[0].Phase != audit.PhaseAttempt || sink.recs[1].Phase != audit.PhaseResult {
		t.Errorf("phases: %q %q", sink.recs[0].Phase, sink.recs[1].Phase)
	}
	r := sink.recs[1]
	if r.Via != audit.ViaCodeExecution || r.Tool != "http_request" || r.Decision != audit.DecisionApproved {
		t.Errorf("inner result: %+v", r)
	}
	if r.SessionID != "S" || r.RunID != "R" || r.CallID != "INNER" {
		t.Errorf("inner correlation: %+v", r)
	}
}

func TestCodeExec_InnerAttemptWriteFails_AbortsRun(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // recs zero-value is fine.
	sink := &captureSink{failOn: audit.PhaseAttempt, failErr: audit.ErrLog}
	ran := false
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			out, err := funcs["http_request"](ctx, `{}`)
			ran = err == nil

			return out, err
		})

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	_, err := tool.Run(ctx, `{"code":"x"}`)
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want ErrLog abort, got %v", err)
	}
	if ran {
		t.Error("inner action ran despite attempt-write failure")
	}
}

func TestCodeExec_InnerError_RecordsErrorResult(t *testing.T) {
	t.Parallel()

	sink := &captureSink{} //nolint:exhaustruct // failOn/failErr zero-value means never fail.
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: errors.New("boom")},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			_, _ = funcs["http_request"](ctx, `{}`)

			return "done", nil
		})

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}
	r := sink.recs[1]
	if r.Outcome != audit.OutcomeError || r.Result != "boom" {
		t.Errorf("inner error result: %+v", r)
	}
}

func TestCodeExec_NilSink_NoInnerRecords(t *testing.T) {
	t.Parallel()

	tool := newCodeToolWithFakeSandbox(t, nil, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{}`)
		})
	if _, err := tool.Run(context.Background(), `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestCodeExec_InnerResultWriteFails_AbortsRun(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // recs zero-value is fine.
	sink := &captureSink{failOn: audit.PhaseResult, failErr: audit.ErrLog}
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{}`)
		})

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want ErrLog on result-write failure, got %v", err)
	}
}

func TestCodeExec_PreLatchedFatal_ShortCircuits(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // recs zero-value is fine.
	sink := &captureSink{failOn: audit.PhaseAttempt, failErr: audit.ErrLog}
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			// First inner call latches fatal on its attempt-write; the script
			// ignores the error and calls again — the second call must short-circuit
			// (no second attempt record is written).
			_, _ = funcs["http_request"](ctx, `{"n":1}`)
			_, _ = funcs["http_request"](ctx, `{"n":2}`)

			return "done", nil
		})

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	_, err := tool.Run(ctx, `{"code":"x"}`)
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want ErrLog, got %v", err)
	}
	if len(sink.recs) != 1 {
		t.Errorf("second inner call should short-circuit before logging; got %d records", len(sink.recs))
	}
}

func TestCodeExec_InnerCall_SessionApproved_StampsApprovedSession(t *testing.T) {
	t.Parallel()

	sink := &captureSink{} //nolint:exhaustruct // failOn/failErr zero-value means never fail.
	tool := newCodeToolWithFakeSandbox(t, sink, echoTool{err: nil},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{"url":"https://x"}`)
		})

	// Simulate the outer approval decorator having recorded a session-grant approval.
	ctx, _ := audit.WithDecision(context.Background())
	audit.RecordSessionApproval(ctx)
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: "S", RunID: "R", Depth: 0})

	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.recs) != 2 {
		t.Fatalf("want 2 inner records, got %d", len(sink.recs))
	}
	if got := sink.recs[1].Decision; got != audit.DecisionApprovedSession {
		t.Errorf("inner result decision = %q, want %q", got, audit.DecisionApprovedSession)
	}
}

func TestCodeExec_ScriptFailure_ReturnsOutputAndMarksFailed(t *testing.T) {
	t.Parallel()

	ctx, fail := audit.WithFailure(context.Background())
	tool, err := tools.NewCodeExecutionToolWithOpts(
		nil, io.Discard, 4,
		tools.WithCodeSandboxFactory(func(map[string]sandbox.ToolFunc, io.Writer, int) (tools.CodeRunner, error) {
			return tools.RunnerFunc(func(context.Context, string, time.Duration) (string, error) {
				return "partial\n[error] boom", sandbox.ErrScript
			}), nil
		}),
	)
	if err != nil {
		t.Fatalf("build code tool: %v", err)
	}

	out, rerr := tool.Run(ctx, `{"code":"x"}`)
	if rerr != nil {
		t.Fatalf("Run: %v", rerr)
	}
	// A script failure returns the rich diagnostic to the model, not a generic message.
	if !strings.Contains(out, "boom") {
		t.Errorf("script failure should return the rich output, got %q", out)
	}
	if !fail.Failed() {
		t.Error("script failure should MarkFailed so the audit outcome is not ok")
	}
}

// markFailTool simulates an inner http_request that gets a 4xx: it records a failure
// on the context but returns the response body with no Go error.
type markFailTool struct{}

func (markFailTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "http_request", Desc: "", Params: nil}, nil
}

func (markFailTool) Run(ctx context.Context, _ string) (string, error) {
	audit.MarkFailed(ctx)

	return "403 body", nil
}

func TestCodeExec_InnerMarkedFailure_RecordsErrorAndPropagates(t *testing.T) {
	t.Parallel()

	sink := &captureSink{} //nolint:exhaustruct // failOn/failErr zero-value means never fail.
	tool := newCodeToolWithFakeSandbox(t, sink, markFailTool{},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{}`)
		})

	ctx, outerFail := audit.WithFailure(context.Background())
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}

	r := sink.recs[1] // [0]=attempt, [1]=result.
	if r.Outcome != audit.OutcomeError {
		t.Errorf("a 4xx inner call must record OutcomeError, got %q (result %q)", r.Outcome, r.Result)
	}
	if r.Result != "403 body" {
		t.Errorf("the rejected response body must still be the inner result, got %q", r.Result)
	}
	if !outerFail.Failed() {
		t.Error("the inner failure must propagate to the outer code_execution recorder")
	}
}

// markProgressTool simulates an inner http_request that gets a sub-4xx response.
type markProgressTool struct{}

func (markProgressTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "http_request", Desc: "", Params: nil}, nil
}

func (markProgressTool) Run(ctx context.Context, _ string) (string, error) {
	audit.MarkProgress(ctx)

	return "200 body", nil
}

func TestCodeExec_InnerProgress_PropagatesToOuter(t *testing.T) {
	t.Parallel()

	sink := &captureSink{} //nolint:exhaustruct // failOn/failErr zero-value means never fail.
	tool := newCodeToolWithFakeSandbox(t, sink, markProgressTool{},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			return funcs["http_request"](ctx, `{}`)
		})

	ctx, outerFail := audit.WithFailure(context.Background())
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if outerFail.Progress() == 0 {
		t.Error("inner progress must propagate to the outer code_execution recorder")
	}
	if sink.recs[1].Outcome != audit.OutcomeOK {
		t.Errorf("a progress-only inner call must record OK, got %q", sink.recs[1].Outcome)
	}
}

func TestCodeExec_ScriptError_AfterInnerFailure_CountsOnce(t *testing.T) {
	t.Parallel()

	// An inner http_request fails (propagated to the outer recorder) and the script then
	// throws; the wrapper must NOT add a second failure for the same uncaught error.
	tool := newCodeToolWithFakeSandbox(t, &captureSink{}, markFailTool{},
		func(ctx context.Context, funcs map[string]sandbox.ToolFunc) (string, error) {
			_, _ = funcs["http_request"](ctx, `{}`)

			return "partial\n[error] boom", sandbox.ErrScript
		})

	ctx, fail := audit.WithFailure(context.Background())
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: "S", RunID: "R", Depth: 0})
	if _, err := tool.Run(ctx, `{"code":"x"}`); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fail.Count() != 1 {
		t.Errorf("an uncaught inner failure + script error must count once, got %d", fail.Count())
	}
}
