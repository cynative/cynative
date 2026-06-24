package ui

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/tools"
)

// fakeController is a scripted ui.Controller for the single-key approval tests. It
// reports a fixed Interrupted() and, on BeginApproval, returns the channels the
// caller selects on. The test seeds dec/intr before calling.
type fakeController struct {
	interrupted    bool
	tripOnBegin    bool // when set, BeginApproval flips interrupted true (a stop racing the keystroke).
	closeIntrAsync bool // when set, BeginApproval closes intr from a goroutine (interrupt arrives mid-wait).
	tripAtCall     int  // when >0, Interrupted() returns true from this 1-based call onward (a stop racing the print).
	intrCalls      int  // counts Interrupted() invocations (drives tripAtCall).
	dec            chan tools.Decision
	intr           chan struct{}
	cleanups       int
}

func (f *fakeController) Interrupted() bool {
	f.intrCalls++
	if f.tripAtCall > 0 && f.intrCalls >= f.tripAtCall {
		return true
	}

	return f.interrupted
}

func (f *fakeController) BeginApproval() (<-chan tools.Decision, <-chan struct{}, func()) {
	if f.tripOnBegin {
		f.interrupted = true
	}
	if f.closeIntrAsync {
		// Yield first so the caller clears the non-blocking entry guard and parks in
		// the blocking wait before the interrupt lands — so the wait-select denies.
		go func() { runtime.Gosched(); close(f.intr) }()
	}

	return f.dec, f.intr, func() { f.cleanups++ }
}

// newControllerUI builds a UI wired to a fake Controller, capturing prompt output.
func newControllerUI(t *testing.T, c Controller) (*UI, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	u := &UI{ //nolint:exhaustruct // isDark/detectOnce/detectDark zero-valued.
		render:     func(text, _ string) (string, error) { return text, nil },
		in:         nil,
		promptW:    buf,
		errW:       buf,
		controller: c,
	}

	return u, buf
}

func TestApproveSingleKey_Decision(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]tools.Decision{
		"yes once":    tools.ApproveOnce,
		"all session": tools.ApproveSession,
		"deny":        tools.Deny,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dec := make(chan tools.Decision, 1)
			dec <- want
			c := &fakeController{interrupted: false, dec: dec, intr: make(chan struct{}), cleanups: 0}
			u, _ := newControllerUI(t, c)

			if got := u.PromptToolApproval("t", "{}", "dark", false); got != want {
				t.Errorf("got %v, want %v", got, want)
			}
			if c.cleanups != 1 {
				t.Errorf("cleanup called %d times, want 1", c.cleanups)
			}
		})
	}
}

func TestApproveSingleKey_InterruptedDuringPromptDenies(t *testing.T) {
	t.Parallel()

	intr := make(chan struct{})
	close(intr) // interrupt already signalled.
	c := &fakeController{interrupted: false, dec: make(chan tools.Decision), intr: intr, cleanups: 0}
	u, _ := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("interrupt during prompt got %v, want Deny", got)
	}
	if c.cleanups != 1 {
		t.Errorf("cleanup called %d times, want 1", c.cleanups)
	}
}

func TestApproveSingleKey_InterruptArrivesWhileWaitingDenies(t *testing.T) {
	t.Parallel()

	// intr is open at the entry guard (no buffered decision), so the wait commits;
	// the interrupt then arrives while we block and the second select denies. dec is
	// an open, never-fed channel so the only way out of the wait is the intr close.
	intr := make(chan struct{})
	c := &fakeController{
		interrupted: false, closeIntrAsync: true,
		dec: make(chan tools.Decision), intr: intr, cleanups: 0,
	}
	u, _ := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("interrupt arriving mid-wait got %v, want Deny", got)
	}
	if c.cleanups != 1 {
		t.Errorf("cleanup called %d times, want 1", c.cleanups)
	}
}

func TestApproveSingleKey_BufferedDecisionLosesToRacedInterrupt(t *testing.T) {
	t.Parallel()

	// The race FIX 1 closes: the watcher buffered a y/a/n decision AND tripped the
	// shared interrupt state (then closes intr). With intr still open here, the
	// second select can pick the decision — but the post-select Interrupted() re-check
	// must still deny, so a stop that raced in with the keystroke wins.
	dec := make(chan tools.Decision, 1)
	dec <- tools.ApproveSession // a real approval is sitting in the buffer.
	// interrupted is false at the entry fast-path; tripOnBegin flips it true during
	// the window, so only the post-select re-check can catch this race.
	c := &fakeController{interrupted: false, tripOnBegin: true, dec: dec, intr: make(chan struct{}), cleanups: 0}
	u, _ := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("buffered decision raced by interrupt got %v, want Deny", got)
	}
	if c.cleanups != 1 {
		t.Errorf("cleanup called %d times, want 1", c.cleanups)
	}
}

func TestApproveSingleKey_AlreadyInterruptedDeniesWithoutReading(t *testing.T) {
	t.Parallel()

	// dec/intr are nil: any read would block forever, proving no BeginApproval happens.
	c := &fakeController{interrupted: true, dec: nil, intr: nil, cleanups: 0}
	u, buf := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("already-interrupted got %v, want Deny", got)
	}
	if c.cleanups != 0 {
		t.Errorf("cleanup called %d times, want 0 (no approval started)", c.cleanups)
	}
	if buf.Len() != 0 {
		t.Errorf("already-interrupted printed %q, want nothing", buf.String())
	}
}

func TestApproveSingleKey_AlreadyInterruptedDeniesEvenWhenGranted(t *testing.T) {
	t.Parallel()

	c := &fakeController{interrupted: true, dec: nil, intr: nil, cleanups: 0}
	u, _ := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", true); got != tools.Deny {
		t.Errorf("already-interrupted granted got %v, want Deny", got)
	}
}

func TestApproveSingleKey_GrantedAutoApproves(t *testing.T) {
	t.Parallel()

	c := &fakeController{interrupted: false, dec: nil, intr: nil, cleanups: 0}
	u, buf := newControllerUI(t, c)

	if got := u.PromptToolApproval("code_execution", `{"code":"x"}`, "dark", true); got != tools.ApproveOnce {
		t.Errorf("granted got %v, want ApproveOnce", got)
	}
	if !strings.Contains(buf.String(), "Auto-approved (session)") {
		t.Errorf("granted output = %q, want session note", buf.String())
	}
	if c.cleanups != 0 {
		t.Errorf("cleanup called %d times, want 0 (granted fast-path)", c.cleanups)
	}
}

func TestApproveSingleKey_GrantedInterruptedAfterPrintDenies(t *testing.T) {
	t.Parallel()

	// The entry fast-path check (call 1) sees no interrupt, so the granted call prints;
	// a stop then races in and the post-print re-check (call 2) must deny it. dec/intr are
	// nil to prove BeginApproval is never reached on the granted path.
	c := &fakeController{tripAtCall: 2, dec: nil, intr: nil, cleanups: 0}
	u, buf := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", true); got != tools.Deny {
		t.Errorf("granted but interrupted-after-print got %v, want Deny", got)
	}
	if strings.Contains(buf.String(), "Auto-approved (session)") {
		t.Errorf("must not print the auto-approve note when a raced interrupt denies: %q", buf.String())
	}
	if c.cleanups != 0 {
		t.Errorf("cleanup called %d times, want 0 (granted path, no BeginApproval)", c.cleanups)
	}
}

func TestApproveSingleKey_PrintsPromptBeforeReading(t *testing.T) {
	t.Parallel()

	dec := make(chan tools.Decision, 1)
	dec <- tools.ApproveOnce
	c := &fakeController{interrupted: false, dec: dec, intr: make(chan struct{}), cleanups: 0}
	u, buf := newControllerUI(t, c)

	u.PromptToolApproval("my_tool", "{}", "dark", false)
	if !strings.Contains(buf.String(), "Execute?") {
		t.Errorf("expected 'Execute?' in prompt, got %q", buf.String())
	}
}

func TestWithController_Sets(t *testing.T) {
	t.Parallel()

	c := &fakeController{interrupted: false, dec: nil, intr: nil, cleanups: 0}
	u := assemble(&UI{ //nolint:exhaustruct // only the controller field under test.
		render:  func(text, _ string) (string, error) { return text, nil },
		promptW: &bytes.Buffer{},
	}, WithController(c))

	if u.controller != c {
		t.Errorf("WithController did not set the controller field")
	}
}

func TestApproveSingleKey_DecisionEndsPromptLine(t *testing.T) {
	t.Parallel()

	dec := make(chan tools.Decision, 1)
	dec <- tools.ApproveOnce
	c := &fakeController{interrupted: false, dec: dec, intr: make(chan struct{}), cleanups: 0}
	u, buf := newControllerUI(t, c)

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.ApproveOnce {
		t.Fatalf("got %v, want ApproveOnce", got)
	}
	// The key was consumed with echo off, so the decision path must end the prompt line.
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("a single-key decision must end the prompt line with a newline, got %q", buf.String())
	}
}
