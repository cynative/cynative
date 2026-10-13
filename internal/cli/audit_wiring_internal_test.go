package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/schema"
)

func TestRunResearch_AuditOpenError_Aborts(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newAuditSink = func(config.Config, *audit.AgentProvenance) (audit.Sink, func() error, error) {
		return nil, nil, errors.New("bad audit path")
	}

	err := d.runResearch(
		context.Background(),
		taskReq("task"),
		validCfg(),
		researchFlags{},
	) //nolint:exhaustruct // defaults
	if err == nil {
		t.Fatal("expected the command to abort on audit-open error")
	}
}

func TestRunResearch_AuditSinkClosed(t *testing.T) {
	t.Parallel()

	closed := false
	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("done")},
		}, nil
	}
	d.newAuditSink = func(config.Config, *audit.AgentProvenance) (audit.Sink, func() error, error) {
		return nil, func() error { closed = true; return nil }, nil
	}
	d.out = io.Discard

	if err := d.runResearch(
		context.Background(),
		taskReq("task"),
		validCfg(),
		researchFlags{}, //nolint:exhaustruct // defaults
	); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	if !closed {
		t.Error("audit sink close func was not called")
	}
}

func TestRunResearch_AuditCloseError_FailsClosed(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("done")},
		}, nil
	}
	d.newAuditSink = func(config.Config, *audit.AgentProvenance) (audit.Sink, func() error, error) {
		return nil, func() error { return errors.New("flush failed") }, nil
	}
	d.out = io.Discard

	err := d.runResearch(
		context.Background(),
		taskReq("task"),
		validCfg(),
		researchFlags{}, //nolint:exhaustruct // defaults
	)
	if err == nil || !strings.Contains(err.Error(), "audit log close") {
		t.Fatalf("expected fail-closed close error, got %v", err)
	}
}

func TestInteractiveLoop_TerminatesOnErrLog(t *testing.T) {
	t.Parallel()

	// A run that fails with an ErrLog-wrapped error must end the session.
	err := classifyTurnError(audit.ErrLog)
	if !err {
		t.Error("ErrLog turn error should terminate the interactive loop")
	}
	if classifyTurnError(errors.New("transient")) {
		t.Error("non-audit error should not terminate the loop")
	}
}

// lateWriteModel stands for a bootstrap call that outlives its lookup: while the run is still going, a record is
// written from outside the loop and its write fails. The model then answers, so no later record of the loop's own
// can notice the failure.
type lateWriteModel struct {
	w *switchWriter
	l *audit.Logger
}

func (m *lateWriteModel) Generate(context.Context, []*schema.Message, []*schema.ToolInfo) (schema.Generation, error) {
	m.w.fail = true
	_ = m.l.Log(audit.Record{Tool: audit.ToolLookupRead}) //nolint:exhaustruct // Logger stamps the rest.

	return schema.Generation{Message: assistantMsg("done")}, nil
}

func (m *lateWriteModel) Shutdown() {}

type switchWriter struct{ fail bool }

func (w *switchWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, errors.New("disk full")
	}

	return len(p), nil
}

// TestRunResearch_ALateFailedAuditWriteFailsTheRun pins that a failed audit write no later record reports still
// ends the run with an error, through the Logger's closer, so it exits nonzero.
func TestRunResearch_ALateFailedAuditWriteFailsTheRun(t *testing.T) {
	t.Parallel()

	w := &switchWriter{}
	l := audit.New(w)
	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &lateWriteModel{w: w, l: l}, nil
	}
	d.newAuditSink = func(config.Config, *audit.AgentProvenance) (audit.Sink, func() error, error) {
		return l, l.Closer(func() error { return nil }), nil
	}
	d.out = io.Discard

	err := d.runResearch(
		context.Background(),
		taskReq("task"),
		validCfg(),
		researchFlags{}, //nolint:exhaustruct // defaults
	)
	if !errors.Is(err, audit.ErrLog) || ExitCodeFor(err) != 1 {
		t.Fatalf("runResearch = %v (exit %d), want the latched audit error and exit 1", err, ExitCodeFor(err))
	}
}
