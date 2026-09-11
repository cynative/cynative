package sandbox

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/sobek"
)

const testMaxOutput = 32 * 1024

var errTest = errors.New("tool failed")

// TestLoop_BoundedConcurrency proves that no more than the configured number of
// inner tool calls run simultaneously, while still running them in parallel.
func TestLoop_BoundedConcurrency(t *testing.T) {
	t.Parallel()

	const capacity = 2

	var (
		cur, peak int32
		gate      = make(chan struct{})
	)

	funcs := map[string]ToolFunc{
		"work": func(_ context.Context, _ string) (string, error) {
			n := atomic.AddInt32(&cur, 1)

			for {
				m := atomic.LoadInt32(&peak)
				if n <= m || atomic.CompareAndSwapInt32(&peak, m, n) {
					break
				}
			}

			<-gate // Hold the slot until released.
			atomic.AddInt32(&cur, -1)

			return "1", nil
		},
	}

	s, err := New(funcs, nil, testMaxOutput, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go func() {
		// Release slots after concurrency has plateaued at the cap.
		time.Sleep(50 * time.Millisecond)
		close(gate)
	}()

	out, err := s.Run(context.Background(), `
		await Promise.all([1,2,3,4,5].map(() => work({})));
		console.log("done");`, 5*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "done\n" {
		t.Errorf("out = %q", out)
	}

	if got := atomic.LoadInt32(&peak); got != capacity {
		t.Errorf("peak concurrency = %d, want %d", got, capacity)
	}
}

// TestLoop_TimeoutMidFlight is the end-to-end witness that a run tears down
// under real contention: with capacity 1 one worker is inside fn when the
// timeout fires while a second is queued for the only slot, and Run must return
// once both have unblocked. Which escape each worker takes is up to the
// scheduler here, so this test pins neither of them; the acquire-side escape is
// pinned deterministically by TestRunWorker_QueuedCallIsAbandoned.
func TestLoop_TimeoutMidFlight(t *testing.T) {
	t.Parallel()

	escaped := make(chan struct{}, 2)

	funcs := map[string]ToolFunc{
		"slow": func(ctx context.Context, _ string) (string, error) {
			<-ctx.Done() // Block until the run times out.
			defer func() { escaped <- struct{}{} }()

			return "", ctx.Err()
		},
	}

	s, err := New(funcs, nil, testMaxOutput, 1, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `
		await Promise.all([slow({}), slow({})]);
		console.log("unreachable");`, 30*time.Millisecond)
	if !errors.Is(err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", err)
	}

	if !strings.Contains(out, "timed out") {
		t.Errorf("out = %q, want timeout suffix", out)
	}

	// The worker that took the slot always reaches fn; whether the queued one
	// also reaches it depends on the schedule, so one escape is all this test
	// can rely on. Run returning at all is what proves both workers unblocked.
	select {
	case <-escaped:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not unblock after timeout")
	}
}

// TestLoop_InterruptDuringDrain covers loop's pb()-returns-error branch. The
// awaited continuation spins, so the timeout interrupt fires while the loop is
// inside resolve's microtask drain; resolve then returns an *InterruptedError
// that propagates settle -> pb -> loop, which returns it. assemble still reports
// the timeout (runCtx fired), but the loop's error return is what is exercised.
func TestLoop_InterruptDuringDrain(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"trigger": func(_ context.Context, _ string) (string, error) {
			return "1", nil
		},
	}

	s, err := New(funcs, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `await trigger({}); while (true) {}`, 50*time.Millisecond)
	if !errors.Is(err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", err)
	}

	if !strings.Contains(out, "timed out") {
		t.Errorf("out = %q, want timeout suffix", out)
	}
}

// TestLoop_TimeoutThenReuse guards the worker-drain invariant: a Run that times
// out with a worker still in flight must wait for that worker to escape before
// returning, so the next Run can safely rewrite the per-run fields the worker
// reads. Run under -race; without the drain this trips the race detector.
func TestLoop_TimeoutThenReuse(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"slow": func(ctx context.Context, _ string) (string, error) {
			<-ctx.Done()

			return "", ctx.Err()
		},
		"quick": func(_ context.Context, _ string) (string, error) { return "1", nil },
	}

	s, err := New(funcs, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for range 20 {
		// Time out with a worker blocked in fn, then immediately reuse the sandbox.
		if _, rerr := s.Run(context.Background(), `await slow({});`, 5*time.Millisecond); !errors.Is(rerr, ErrScript) {
			t.Fatalf("Run (slow): want ErrScript, got %v", rerr)
		}

		out, rerr := s.Run(context.Background(), `await quick({}); console.log("ok");`, time.Second)
		if rerr != nil {
			t.Fatalf("Run (quick): %v", rerr)
		}

		if out != "ok\n" {
			t.Errorf("reuse out = %q, want ok", out)
		}
	}
}

// TestLoop_ParentCancel reports a parent-context cancellation distinctly from a
// timeout.
func TestLoop_ParentCancel(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"slow": func(ctx context.Context, _ string) (string, error) {
			<-ctx.Done()

			return "", ctx.Err()
		},
	}

	s, err := New(funcs, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	out, err := s.Run(ctx, `await slow({}); console.log("unreachable");`, 5*time.Second)
	if !errors.Is(err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", err)
	}

	if !strings.Contains(out, "cancelled") {
		t.Errorf("out = %q, want cancelled suffix", out)
	}
}

// TestRun_ScriptThrowRejects surfaces an uncaught throw inside the async IIFE as
// a rejected-promise error suffix.
func TestRun_ScriptThrowRejects(t *testing.T) {
	t.Parallel()

	s, err := New(nil, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `throw new Error("boom");`, time.Second)
	if !errors.Is(err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", err)
	}

	if !strings.Contains(out, "boom") {
		t.Errorf("out = %q, want error boom", out)
	}
}

// TestRun_ToolErrorRejects proves a tool error becomes a catchable JS rejection.
func TestRun_ToolErrorRejects(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"bad": func(_ context.Context, _ string) (string, error) {
			return "", errTest
		},
	}

	s, err := New(funcs, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `
		try { await bad({}); } catch (e) { console.log("caught:" + e.message); }`, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(out, "caught:") {
		t.Errorf("out = %q, want caught error", out)
	}
}

// TestRun_CompileError covers the compile-after-wrap failure path.
func TestRun_CompileError(t *testing.T) {
	t.Parallel()

	s, err := New(nil, nil, testMaxOutput, 4, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `const = ;`, time.Second)
	if !errors.Is(err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", err)
	}

	if !strings.Contains(out, "[error]") {
		t.Errorf("out = %q, want syntax error", out)
	}
}

// TestToJSResult_NonJSONStaysString covers the toJSResult fallback: a non-JSON
// result and a JSON-shaped-but-invalid result both pass through as strings.
func TestToJSResult_NonJSONStaysString(t *testing.T) {
	t.Parallel()

	vm := sobek.New()

	if got := toJSResult(vm, "plain text"); got != "plain text" {
		t.Errorf("got %v, want string passthrough", got)
	}

	if got := toJSResult(vm, "{not json"); got != "{not json" {
		t.Errorf("got %v, want invalid-JSON passthrough", got)
	}
}

// queuedCallLine is the verbose line the sandbox writes when the script calls
// the queued tool, ahead of spawning that call's worker.
const queuedCallLine = "\u2192 queued "

// callSignal reports the queued call's verbose line. The sandbox writes that
// line on the loop goroutine inside toolFunc, immediately before that same
// function spawns the call's worker, so a line seen here means the worker is
// spawned before the loop goroutine can act on the test's cancel.
type callSignal chan struct{}

// Write reports the queued call's line and drops every other line.
func (c callSignal) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte(queuedCallLine)) {
		select {
		case c <- struct{}{}:
		default:
		}
	}

	return len(p), nil
}

// TestRunWorker_QueuedCallIsAbandoned pins the acquire-side <-s.done escape: a
// tool call still queued for a concurrency slot when its run ends is abandoned
// rather than started. The test holds the sandbox's only slot for the whole run
// and never releases it, so the acquire select's semaphore arm can never become
// ready and <-s.done is the worker's only way out, whatever order the goroutines
// happen to be scheduled in. The abandoned call must not reach the tool, must
// not take a slot, and must return, because Run waits for it before returning.
func TestRunWorker_QueuedCallIsAbandoned(t *testing.T) {
	t.Parallel()

	const (
		capacity   = 1
		escapeWait = 10 * time.Second
	)

	var started atomic.Int32

	funcs := map[string]ToolFunc{
		"queued": func(context.Context, string) (string, error) {
			started.Add(1)

			return "", nil
		},
	}

	calling := make(callSignal, 1)

	s, err := New(funcs, calling, testMaxOutput, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	s.sem <- struct{}{} // Hold the only slot; nothing ever releases it.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		runErr   error
		returned = make(chan struct{})
	)

	go func() {
		defer close(returned)

		_, runErr = s.Run(ctx, `await queued({});`, time.Minute)
	}()

	select {
	case <-calling:
	case <-time.After(escapeWait):
		t.Fatal("the sandbox never logged the call, so no worker ever queued for a slot")
	}

	cancel() // End the run with that call still queued.

	select {
	case <-returned:
	case <-time.After(escapeWait):
		t.Fatal("Run never returned: the call queued for a slot never escaped through <-s.done")
	}

	if !errors.Is(runErr, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", runErr)
	}

	if n := started.Load(); n != 0 {
		t.Errorf("the tool ran %d time(s) on a run that had already ended, want 0", n)
	}

	if len(s.sem) != capacity {
		t.Errorf("semaphore holds %d slots, want %d: the abandoned call took one", len(s.sem), capacity)
	}
}
