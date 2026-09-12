package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/sobek"
)

const testMaxOutput = 32 * 1024

var errTest = errors.New("tool failed")

// TestLoop_BoundedConcurrency proves that no more than the configured number of
// inner tool calls run simultaneously, while still running them in parallel. The
// gate opens on a signal rather than after a wait: the releaser opens it once
// capacity calls have reported themselves inside the tool, and no call can leave
// before it opens, so the peak asserted below is a fact about calls that really
// did overlap rather than a guess about how fast the runner is.
func TestLoop_BoundedConcurrency(t *testing.T) {
	t.Parallel()

	const (
		capacity = 2
		calls    = 5
	)

	var cur, peak atomic.Int32

	var (
		entered = make(chan struct{}, calls)
		gate    = make(chan struct{})
		stop    = make(chan struct{})
	)

	t.Cleanup(func() { close(stop) })

	funcs := map[string]ToolFunc{
		"work": func(ctx context.Context, _ string) (string, error) {
			n := cur.Add(1)

			for {
				m := peak.Load()
				if n <= m || peak.CompareAndSwap(m, n) {
					break
				}
			}

			entered <- struct{}{}

			select {
			case <-gate: // Hold the slot until the cap has been reached.
			case <-ctx.Done(): // The run gave up: report the shortfall, do not hang it.
			}

			cur.Add(-1)

			return "1", nil
		},
	}

	s, err := New(funcs, nil, testMaxOutput, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go func() {
		for range capacity {
			select {
			case <-entered:
			case <-stop: // The test ended without filling the cap; it says so below.
				return
			}
		}

		close(gate)
	}()

	out, err := s.Run(context.Background(), fmt.Sprintf(`
		await Promise.all(Array.from({length: %d}, () => work({})));
		console.log("done");`, calls), 5*time.Second)

	// Asserted before the error, because a cap that never filled leaves the run
	// to time out and would otherwise be reported as a bare execution failure.
	if got := peak.Load(); got != capacity {
		t.Errorf("peak concurrency = %d, want %d: the calls never overlapped at the cap", got, capacity)
	}

	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "done\n" {
		t.Errorf("out = %q", out)
	}
}

// TestLoop_TeardownUnderContention is the end-to-end witness that a run tears
// down under real contention, and that the call queued behind the busy slot
// never starts. Capacity is 1, so the second call cannot reach the tool while
// the first holds the slot, and the first returns only once the run ends. The
// test waits for both halves of that shape before it ends the run: the tool
// reports that a call is inside it, and the verbose writer reports both call
// lines, which the sandbox writes on the loop goroutine just ahead of spawning
// each call's worker. Nothing here is timed, so the shape is a fact rather than
// an assumption about the runner. The run ends by cancellation; the timeout
// suffix is covered by TestLoop_TimeoutThenReuse and TestLoop_InterruptDuringDrain.
func TestLoop_TeardownUnderContention(t *testing.T) {
	t.Parallel()

	const (
		capacity   = 1
		calls      = 2
		escapeWait = 10 * time.Second
	)

	var started atomic.Int32

	inside := make(chan struct{}, calls)

	funcs := map[string]ToolFunc{
		"queued": func(ctx context.Context, _ string) (string, error) {
			started.Add(1)
			inside <- struct{}{}

			<-ctx.Done() // Holds the only slot until the run ends.

			return "", ctx.Err()
		},
	}

	calling := make(callSignal, calls)

	s, err := New(funcs, calling, testMaxOutput, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		out string
		err error
	}

	returned := make(chan outcome, 1)

	go func() {
		out, rerr := s.Run(ctx, `
			await Promise.all([queued({}), queued({})]);
			console.log("unreachable");`, time.Minute)

		returned <- outcome{out: out, err: rerr}
	}()

	for range calls {
		select {
		case <-calling:
		case <-time.After(escapeWait):
			t.Fatal("the sandbox never logged both calls, so none was ever queued for the slot")
		}
	}

	select {
	case <-inside:
	case <-time.After(escapeWait):
		t.Fatal("no call ever reached the tool, so the slot was never held")
	}

	cancel() // End the run with one call holding the slot and one queued for it.

	var got outcome

	select {
	case got = <-returned:
	case <-time.After(escapeWait):
		t.Fatal("Run never returned: a call holding or waiting for the slot never escaped")
	}

	if !errors.Is(got.err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", got.err)
	}

	if !strings.Contains(got.out, "cancelled") {
		t.Errorf("out = %q, want cancelled suffix", got.out)
	}

	if n := started.Load(); n != 1 {
		t.Errorf("%d call(s) reached the tool, want 1: the queued call started on a run that had ended", n)
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

	entered := make(chan struct{}, 1)

	funcs := map[string]ToolFunc{
		"slow": func(ctx context.Context, _ string) (string, error) {
			entered <- struct{}{}
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
		<-entered // Cancel once the call is under way, rather than after a wait.
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

// Write reports each queued-call line, up to the channel's capacity, and drops
// every other line.
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

// TestRunWorker_AcquiredCallIsAbandonedWhenRunEnded pins the re-check inside the
// acquire select's semaphore arm: a call that wins a concurrency slot on a run
// that has already ended must not reach the tool. Winning that arm proves nothing on
// its own, because the slot a call is queued behind is released by a worker the
// run's teardown just woke, so both arms can be ready at once and Go picks
// between them uniformly. Here s.done stays open and the semaphore starts
// empty, which leaves the acquire select exactly one ready arm, so the slot is
// taken on every schedule and the run's cancelled context is the only thing
// that can still stop the call.
func TestRunWorker_AcquiredCallIsAbandonedWhenRunEnded(t *testing.T) {
	t.Parallel()

	const capacity = 1

	var started atomic.Int32

	fn := func(context.Context, string) (string, error) {
		started.Add(1)

		return "", nil
	}

	s, err := New(map[string]ToolFunc{"queued": fn}, nil, testMaxOutput, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Open for the whole test, so the semaphore is the acquire select's only
	// ready arm; buffered, so a call that wrongly reaches the tool posts its
	// result here instead of parking on an unread channel.
	s.done = make(chan struct{})
	s.pending = make(chan func() error, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // The run is over before this call gets its slot.

	s.runWorker(ctx, "queued", fn, emptyObject, nil, nil)

	if n := started.Load(); n != 0 {
		t.Errorf("the tool ran %d time(s) on a run that had already ended, want 0", n)
	}

	if n := len(s.pending); n != 0 {
		t.Errorf("the abandoned call posted %d result(s), want 0", n)
	}

	if n := len(s.sem); n != 0 {
		t.Errorf("the abandoned call held on to %d slot(s), want 0", n)
	}
}

// TestRun_TopLevelThrowEndsCallsInFlight covers the run that ends with its
// context still live. The script closes the async IIFE the sandbox wraps it in
// and throws at top level, so RunProgram returns an error, the worker loop is
// skipped and the run tears down while its calls are still in flight, with the
// run's own deadline minutes away. Run has to end those calls itself: it waits
// for every worker before it returns, and the tools here return only when the
// run's context is done. The error the script threw must survive that teardown,
// because Run captures why the run ended before it cancels.
//
// The script waits for a call to be inside the tool before it throws, so the
// shape is a fact rather than a matter of scheduling. It waits through a
// synchronous host function rather than an await, because the wrapper it closed
// to reach a top-level throw is the thing that made top-level await legal, and
// an await inside the wrapper would turn the throw into a rejection and take the
// ordinary loop path instead.
func TestRun_TopLevelThrowEndsCallsInFlight(t *testing.T) {
	t.Parallel()

	const (
		// More than one, so teardown meets a fan-out rather than a single call.
		calls = 64
		// Far enough apart that a run ended by its deadline is unmistakable.
		runTimeout   = time.Minute
		teardownWait = 10 * time.Second
	)

	var entered sync.Once

	inside := make(chan struct{})

	funcs := map[string]ToolFunc{
		"slow": func(ctx context.Context, _ string) (string, error) {
			entered.Do(func() { close(inside) })

			<-ctx.Done() // Returns only once the run ends this call.

			return "", ctx.Err()
		},
	}

	s, err := New(funcs, nil, testMaxOutput, calls, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Runs on the loop goroutine, so it holds the script at the line below until
	// a call is inside the tool. The wait is bounded only so a regression that
	// keeps every call out of the tool fails loudly instead of hanging.
	handshook := make(chan struct{}, 1)

	if serr := s.vm.Set("waitForEntry", func() {
		select {
		case <-inside:
			handshook <- struct{}{}
		case <-time.After(teardownWait):
		}
	}); serr != nil {
		t.Fatalf("register waitForEntry: %v", serr)
	}

	type result struct {
		out string
		err error
	}

	returned := make(chan result, 1)

	go func() {
		out, rerr := s.Run(context.Background(), fmt.Sprintf(`});
			for (let i = 0; i < %d; i++) slow({});
			waitForEntry();
			throw new Error("boom");
			void (async () => {`, calls), runTimeout)

		returned <- result{out: out, err: rerr}
	}()

	var got result

	select {
	case got = <-returned:
	case <-time.After(teardownWait):
		t.Fatal("Run never returned: the script ended with calls in flight and nothing ended them")
	}

	if len(handshook) != 1 {
		t.Fatal("no call was inside the tool when the script threw, so the run never tore down over one")
	}

	if !errors.Is(got.err, ErrScript) {
		t.Fatalf("Run: want ErrScript, got %v", got.err)
	}

	if !strings.Contains(got.out, "boom") {
		t.Errorf("out = %q, want the thrown error", got.out)
	}

	if strings.Contains(got.out, "timed out") || strings.Contains(got.out, "cancelled") {
		t.Errorf("out = %q, want the thrown error rather than an ended-context suffix", got.out)
	}
}
