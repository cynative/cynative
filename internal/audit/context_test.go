package audit_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/audit"
)

func TestFailure_MarkAndNoRecorder(t *testing.T) {
	t.Parallel()

	ctx, f := audit.WithFailure(context.Background())
	if f.Failed() {
		t.Fatal("fresh Failure should be false")
	}
	audit.MarkFailed(ctx)
	if !f.Failed() {
		t.Error("MarkFailed did not record")
	}

	// No recorder installed: MarkFailed is a safe no-op.
	audit.MarkFailed(context.Background())
}

func TestScope_RoundTripAndMiss(t *testing.T) {
	t.Parallel()

	ctx := audit.WithScope(context.Background(), audit.Scope{SessionID: "S", RunID: "R", Depth: 2})
	got, ok := audit.ScopeFrom(ctx)
	if !ok || got.SessionID != "S" || got.RunID != "R" || got.Depth != 2 {
		t.Fatalf("ScopeFrom: %+v ok=%v", got, ok)
	}
	if _, found := audit.ScopeFrom(context.Background()); found {
		t.Error("ScopeFrom on bare ctx should be ok=false")
	}
}

func TestDecision_RecordAndNoRecorder(t *testing.T) {
	t.Parallel()

	ctx, dec := audit.WithDecision(context.Background())
	audit.RecordDecision(ctx, true)
	if !dec.Decided || !dec.Approved {
		t.Fatalf("decision not recorded: %+v", dec)
	}

	// No recorder installed: RecordDecision is a safe no-op.
	audit.RecordDecision(context.Background(), false)
}

func TestFatal_FirstWriteWinsAndMiss(t *testing.T) {
	t.Parallel()

	ctx, f := audit.WithFatal(context.Background())
	if f.Err() != nil {
		t.Fatal("fresh Fatal should be nil")
	}
	first := errors.New("first")
	f.Set(first)
	f.Set(errors.New("second"))
	if !errors.Is(f.Err(), first) {
		t.Errorf("first-write-wins violated: %v", f.Err())
	}

	got, ok := audit.FatalFrom(ctx)
	if !ok || got != f {
		t.Error("FatalFrom mismatch")
	}
	if _, found := audit.FatalFrom(context.Background()); found {
		t.Error("FatalFrom on bare ctx should be ok=false")
	}
}

func TestFatal_ConcurrentSet(t *testing.T) {
	t.Parallel()

	_, f := audit.WithFatal(context.Background())
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { f.Set(errors.New("e")) })
	}
	wg.Wait()
	if f.Err() == nil {
		t.Error("expected an error latched")
	}
}

func TestSessionApproval_RecordAndNoRecorder(t *testing.T) {
	t.Parallel()

	ctx, dec := audit.WithDecision(context.Background())
	audit.RecordSessionApproval(ctx)
	if !dec.Decided || !dec.Approved || !dec.Session {
		t.Errorf("recorder = %+v, want all true", dec)
	}
	if !audit.SessionApproved(ctx) {
		t.Error("SessionApproved should report true after RecordSessionApproval")
	}

	// No recorder installed: both are safe and report false.
	bare := context.Background()
	audit.RecordSessionApproval(bare) // must not panic
	if audit.SessionApproved(bare) {
		t.Error("SessionApproved on a recorder-less context must be false")
	}
}

func TestSessionApproved_PlainApprovalIsNotSession(t *testing.T) {
	t.Parallel()

	ctx, _ := audit.WithDecision(context.Background())
	audit.RecordDecision(ctx, true)
	if audit.SessionApproved(ctx) {
		t.Error("a plain RecordDecision(true) must not look like a session approval")
	}
}

func TestFailure_CountsEachMark(t *testing.T) {
	t.Parallel()

	ctx, f := audit.WithFailure(context.Background())
	if f.Count() != 0 {
		t.Errorf("fresh Count = %d, want 0", f.Count())
	}
	audit.MarkFailed(ctx)
	audit.MarkFailed(ctx)
	if f.Count() != 2 {
		t.Errorf("Count after two marks = %d, want 2", f.Count())
	}
	if !f.Failed() {
		t.Error("Failed() must be true after marks")
	}
}

func TestFailure_CountsProgress(t *testing.T) {
	t.Parallel()

	ctx, f := audit.WithFailure(context.Background())
	if f.Progress() != 0 {
		t.Errorf("fresh Progress = %d, want 0", f.Progress())
	}
	audit.MarkProgress(ctx)
	audit.MarkProgress(ctx)
	if f.Progress() != 2 {
		t.Errorf("Progress after two marks = %d, want 2", f.Progress())
	}

	// No recorder installed: MarkProgress is a safe no-op.
	audit.MarkProgress(context.Background())
}

func TestFailureFrom(t *testing.T) {
	t.Parallel()

	if _, ok := audit.FailureFrom(context.Background()); ok {
		t.Error("FailureFrom on a bare context must report absent")
	}
	ctx, f := audit.WithFailure(context.Background())
	got, ok := audit.FailureFrom(ctx)
	if !ok || got != f {
		t.Errorf("FailureFrom must return the installed recorder, got ok=%v", ok)
	}
}
