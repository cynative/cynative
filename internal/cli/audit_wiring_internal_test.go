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
	d.newAuditSink = func(config.Config) (audit.Sink, func() error, error) {
		return nil, nil, errors.New("bad audit path")
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
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
	d.newAuditSink = func(config.Config) (audit.Sink, func() error, error) {
		return nil, func() error { closed = true; return nil }, nil
	}
	d.out = io.Discard

	if err := d.runResearch(
		context.Background(),
		"task",
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
	d.newAuditSink = func(config.Config) (audit.Sink, func() error, error) {
		return nil, func() error { return errors.New("flush failed") }, nil
	}
	d.out = io.Discard

	err := d.runResearch(
		context.Background(),
		"task",
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
