package agent

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// recordingSink captures every Record; optionally fails on a chosen phase.
type recordingSink struct {
	recs    []audit.Record
	failOn  string // "" never fails; otherwise the Phase to fail on.
	failErr error
}

func (s *recordingSink) Log(rec audit.Record) error {
	s.recs = append(s.recs, rec)
	if s.failOn != "" && rec.Phase == s.failOn {
		return s.failErr
	}

	return nil
}

// stubTool is a minimal InvokableTool returning a fixed output/error.
type stubTool struct {
	name string
	out  string
	err  error
}

func (s stubTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: s.name, Desc: "", Params: nil}
}
func (s stubTool) Run(context.Context, string) (string, error) { return s.out, s.err }

func auditAgent(sink audit.Sink, tools map[string]schema.InvokableTool) *Agent {
	infos := make([]*schema.ToolInfo, 0, len(tools))
	for _, tl := range tools {
		info := tl.Info()
		infos = append(infos, info)
	}

	return &Agent{ //nolint:exhaustruct // dispatch tests need these fields only.
		tools:        toolset{tools: tools, infos: infos},
		renderer:     func(*schema.Message, string, io.Writer) {},
		style:        "notty",
		audit:        sink,
		sessionID:    "S",
		newID:        seqIDs("C1", "C2", "C3"),
		deniedResult: "DENIED",
	}
}

func dispatchTC(name, args string) schema.ToolCallBlock {
	return schema.ToolCallBlock{ID: "id", Name: name, Arguments: args}
}

func TestDispatch_ApprovedIO_WritesAttemptAndResult(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	// approvalStub records an approval on the context (mimics the decorator).
	approvalStub := approvalFn(stubTool{name: "http_request", out: "BODY", err: nil}, true)
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": approvalStub})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	ret, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{"u":1}`))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if ret != WrapUntrustedForTest("http_request", "BODY") {
		t.Errorf("ret not framed: %q", ret)
	}
	if len(sink.recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(sink.recs))
	}
	if sink.recs[0].Phase != audit.PhaseAttempt || sink.recs[1].Phase != audit.PhaseResult {
		t.Errorf("phases: %q %q", sink.recs[0].Phase, sink.recs[1].Phase)
	}
	r := sink.recs[1]
	if r.Decision != audit.DecisionApproved || r.Outcome != audit.OutcomeOK || r.Result != "BODY" {
		t.Errorf("result record: %+v", r)
	}
	if r.SessionID != "S" || r.RunID != "R" || r.CallID != sink.recs[0].CallID {
		t.Errorf("correlation: %+v", r)
	}
}

func TestDispatch_DeniedIO_LabelsDenied(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	approvalStub := approvalFn(stubTool{name: "http_request", out: "DENIED", err: nil}, false)
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": approvalStub})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	ret, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if ret != "DENIED" {
		t.Errorf("denied result should be unframed, got %q", ret)
	}
	r := sink.recs[1]
	if r.Decision != audit.DecisionDenied || r.Outcome != audit.OutcomeDenied {
		t.Errorf("denied record: %+v", r)
	}
}

func TestDispatch_AttemptWriteFails_AbortsBeforeExec(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{ //nolint:exhaustruct // recs zero-init.
		failOn: audit.PhaseAttempt, failErr: errors.New("boom"),
	}
	ran := false
	tool := funcTool{name: "http_request", run: func(context.Context, string) (string, error) {
		ran = true

		return "x", nil
	}}
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": tool})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	_, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`))
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
	if ran {
		t.Error("tool ran despite attempt-write failure")
	}
}

func TestDispatch_FatalFromTool_Aborts(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	tool := funcTool{name: "code_execution", run: func(context.Context, string) (string, error) {
		return "", audit.ErrLog
	}}
	a := auditAgent(sink, map[string]schema.InvokableTool{"code_execution": tool})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	_, _, err := a.dispatch(context.Background(), rs, dispatchTC("code_execution", `{}`))
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want ErrLog abort, got %v", err)
	}
}

func TestDispatch_ResultWriteFails_Aborts(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{ //nolint:exhaustruct // recs zero-init.
		failOn: audit.PhaseResult, failErr: errors.New("disk full"),
	}
	a := auditAgent(sink, map[string]schema.InvokableTool{
		"http_request": approvalFn(stubTool{name: "http_request", out: "B", err: nil}, true),
	})
	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	_, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`))
	if err == nil {
		t.Fatal("expected fail-closed error on result-write failure")
	}
}

func TestDispatch_NilSink_NoOp(t *testing.T) {
	t.Parallel()

	a := auditAgent(nil, map[string]schema.InvokableTool{
		"http_request": approvalFn(stubTool{name: "http_request", out: "B", err: nil}, true),
	})
	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	if _, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`)); err != nil {
		t.Fatalf("nil sink should be a no-op: %v", err)
	}
}

// funcTool is an InvokableTool whose Run is a closure.
type funcTool struct {
	name string
	run  func(context.Context, string) (string, error)
}

func (f funcTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: f.name, Desc: "", Params: nil}
}
func (f funcTool) Run(ctx context.Context, args string) (string, error) { return f.run(ctx, args) }

// approvalFn wraps inner so Run records the decision on the context (like the
// real approval decorator) and returns inner's output when approved, "DENIED"
// (matching the test agent's deniedResult) when not.
func approvalFn(inner schema.InvokableTool, approve bool) schema.InvokableTool {
	return funcTool{name: mustName(inner), run: func(ctx context.Context, args string) (string, error) {
		audit.RecordDecision(ctx, approve)
		if !approve {
			return "DENIED", nil
		}

		return inner.Run(ctx, args)
	}}
}

func mustName(t schema.InvokableTool) string {
	info := t.Info()

	return info.Name
}

// fakeScoped is a minimal runScopedTool for orchestration-path dispatch tests.
type fakeScoped struct {
	name string
	out  string
	err  error
}

func (f fakeScoped) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: f.name, Desc: "", Params: nil}
}
func (fakeScoped) Run(context.Context, string) (string, error) { return "", nil }
func (f fakeScoped) runScoped(context.Context, *runState, string) (string, error) {
	return f.out, f.err
}

func TestDispatch_IOFailure_LabelsErrorOutcome(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	// An approved I/O tool that reports failure as a result string + audit.MarkFailed.
	inner := funcTool{name: "http_request", run: func(ctx context.Context, _ string) (string, error) {
		audit.MarkFailed(ctx)

		return "Error executing tool: blocked", nil
	}}
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": approvalFn(inner, true)})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	if _, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	r := sink.recs[1]
	if r.Decision != audit.DecisionApproved || r.Outcome != audit.OutcomeError {
		t.Errorf("nil-error tool failure should be approved+error: %+v", r)
	}
}

func TestDispatch_ScopedFatal_Aborts(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	a := auditAgent(sink, map[string]schema.InvokableTool{
		"task": fakeScoped{name: "task", out: "", err: audit.ErrLog},
	})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	_, _, err := a.dispatch(context.Background(), rs, dispatchTC("task", `{}`))
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("sub-agent ErrLog should abort the parent run, got %v", err)
	}
}

func TestDispatch_OrchestrationRedactsArgs(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	a := auditAgent(sink, map[string]schema.InvokableTool{
		"write_todos": fakeScoped{name: "write_todos", out: "ok", err: nil},
	})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	if _, _, err := a.dispatch(context.Background(), rs, dispatchTC("write_todos", `{"todos":[]}`)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	for _, r := range sink.recs {
		if !r.RedactArgs {
			t.Errorf("ungated orchestration record must set RedactArgs: %+v", r)
		}
	}
	if got := sink.recs[1].Decision; got != audit.DecisionUngated {
		t.Errorf("orchestration decision: got %q want ungated", got)
	}
}

func TestDecisionLabel_AllStates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		dec  audit.Decision
		want string
	}{
		{"denied", audit.Decision{Decided: true, Approved: false, Session: false}, audit.DecisionDenied},
		{"approved", audit.Decision{Decided: true, Approved: true, Session: false}, audit.DecisionApproved},
		{"session", audit.Decision{Decided: true, Approved: true, Session: true}, audit.DecisionApprovedSession},
		{"undecided-defaults-approved", audit.Decision{Decided: false, Approved: false, Session: false}, audit.DecisionApproved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := tc.dec
			if got := decisionLabel(&d); got != tc.want {
				t.Errorf("decisionLabel(%+v) = %q, want %q", d, got, tc.want)
			}
		})
	}
}

func TestDispatch_SessionGrant_PersistsAndLabelsApprovedSession(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.

	var grantedSeen []bool
	prompter := func(_, _, _ string, alreadyGranted bool) tools.Decision {
		grantedSeen = append(grantedSeen, alreadyGranted)

		return tools.ApproveSession
	}
	gated := tools.NewApprovalTool(stubTool{name: "http_request", out: "BODY", err: nil}, prompter, "notty")
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": gated})

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	for range 2 {
		if _, _, err := a.dispatch(context.Background(), rs, dispatchTC("http_request", `{}`)); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
	}

	// The decorator latches after the first ApproveSession, so the prompter sees
	// alreadyGranted false then true — the grant persists across dispatches.
	if len(grantedSeen) != 2 || grantedSeen[0] || !grantedSeen[1] {
		t.Fatalf("grantedSeen = %v, want [false true]", grantedSeen)
	}

	var decisions []string
	for _, r := range sink.recs {
		if r.Phase == audit.PhaseResult {
			decisions = append(decisions, r.Decision)
		}
	}
	if len(decisions) != 2 ||
		decisions[0] != audit.DecisionApproved ||
		decisions[1] != audit.DecisionApprovedSession {
		t.Fatalf("result decisions = %v, want [approved approved_session]", decisions)
	}
}

func TestRun_AbortsWhenAuditAttemptFails(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{failOn: audit.PhaseAttempt, failErr: audit.ErrLog} //nolint:exhaustruct // recs zero-init.
	// scriptedModel (defined in agent_internal_test.go) errors when out of msgs;
	// the run-level test only needs one turn: a tool call. The model returns the
	// scripted call, then dispatch fails before the tool runs, so Generate is
	// called exactly once.
	model := &scriptedModel{msgs: []*schema.Message{
		schema.AssistantMessage("", []schema.ToolCallBlock{{ID: "1", Name: "http_request", Arguments: "{}"}}),
	}}
	tool := funcTool{name: "http_request", run: func(context.Context, string) (string, error) { return "x", nil }}
	a := auditAgent(sink, map[string]schema.InvokableTool{"http_request": tool})
	a.model = model

	rs := &runState{depth: 0, out: io.Discard, runID: "R"}
	_, err := a.run(context.Background(), rs, []*schema.Message{schema.UserMessage("q")}, 3)
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("run should abort fail-closed with ErrLog, got %v", err)
	}
}
