package sandbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/sandbox"
)

const noOutput = "[script completed with no output]"

// identityRedact is the no-op redactor for tests. sandbox.New requires a
// non-nil redactor, so call sites pass this rather than nil.
func identityRedact(s string) string { return s }

// newSandbox builds a sandbox for tests with a 32 KB output cap. Pass nil for
// verbose to disable logging; pass a [bytes.Buffer] pointer to capture it.
func newSandbox(t *testing.T, funcs map[string]sandbox.ToolFunc, verbose io.Writer) *sandbox.Sandbox {
	t.Helper()

	s, err := sandbox.New(funcs, verbose, 32*1024, sandbox.DefaultMaxConcurrency, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return s
}

// run is a helper: a 5s timeout is ample for non-looping scripts.
func run(t *testing.T, s *sandbox.Sandbox, code string) string {
	t.Helper()

	out, err := s.Run(context.Background(), code, 5*time.Second)
	if err != nil {
		t.Fatalf("Run returned a Go error (should be nil): %v", err)
	}

	return out
}

// runFailed runs code expecting a script failure (sandbox.ErrScript) and returns
// the diagnostic output (which still carries the detail for the model).
func runFailed(t *testing.T, s *sandbox.Sandbox, code string) string {
	t.Helper()

	out, err := s.Run(context.Background(), code, 5*time.Second)
	if !errors.Is(err, sandbox.ErrScript) {
		t.Fatalf("Run: want sandbox.ErrScript, got %v", err)
	}

	return out
}

func TestRun_ConsoleLogPrimitives(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil), `console.log("hello", 42, true)`)
	if got != "hello 42 true\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_ConsoleLogObjectAndArray(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil), `console.log({a:1}); console.log([1,2])`)
	if !strings.Contains(got, `{"a":1}`) || !strings.Contains(got, `[1,2]`) {
		t.Errorf("got %q", got)
	}
}

func TestRun_ConsoleLogNullUndefined(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil), `console.log(null, undefined)`)
	if got != "null undefined\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_ConsoleLogObjectMarshalFallback(t *testing.T) {
	t.Parallel()

	// An object holding a function cannot be JSON-marshaled, so console formatting
	// falls back to the JS string form.
	got := run(t, newSandbox(t, nil, nil), `console.log({f: function(){}})`)
	if !strings.Contains(got, "[object Object]") {
		t.Errorf("expected fallback string form, got %q", got)
	}
}

func TestRun_LoggedPrimitive(t *testing.T) {
	t.Parallel()

	// The async IIFE wrap discards a trailing expression's value, so output comes
	// only from console.log.
	if got := run(t, newSandbox(t, nil, nil), `console.log(2 + 3)`); got != "5\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_LoggedObject(t *testing.T) {
	t.Parallel()

	if got := run(t, newSandbox(t, nil, nil), `console.log({a:1})`); got != `{"a":1}`+"\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_TrailingExpressionDiscarded(t *testing.T) {
	t.Parallel()

	// A bare trailing expression is not rendered: the async IIFE returns a Promise,
	// not the expression's value.
	if got := run(t, newSandbox(t, nil, nil), `2 + 3`); got != noOutput {
		t.Errorf("got %q", got)
	}
}

func TestRun_NoOutput(t *testing.T) {
	t.Parallel()

	if got := run(t, newSandbox(t, nil, nil), `var x = 1;`); got != noOutput {
		t.Errorf("got %q", got)
	}
}

func TestRun_Truncation(t *testing.T) {
	t.Parallel()

	s, err := sandbox.New(nil, nil, 10, sandbox.DefaultMaxConcurrency, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := run(t, s, `console.log("0123456789ABCDEF")`)
	if !strings.Contains(got, "truncated at 10 bytes") {
		t.Errorf("expected truncation marker, got %q", got)
	}
}

func TestRun_InvalidUTF8Sanitized(t *testing.T) {
	t.Parallel()

	// A lone surrogate exports to invalid UTF-8; it must be replaced.
	got := run(t, newSandbox(t, nil, nil), `console.log("\uD800")`)
	if !strings.Contains(got, "�") {
		t.Errorf("expected replacement char, got %q", got)
	}
}

func TestRun_ToolFuncSuccess(t *testing.T) {
	t.Parallel()

	var gotArgs string

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, argsJSON string) (string, error) {
			gotArgs = argsJSON

			return "RESP", nil
		},
	}

	got := run(t, newSandbox(t, funcs, nil), `console.log(await probe({x:1}))`)
	if !strings.Contains(got, "RESP") {
		t.Errorf("got %q", got)
	}

	if gotArgs != `{"x":1}` {
		t.Errorf("tool received args %q", gotArgs)
	}
}

func TestRun_ToolFuncErrorThrows(t *testing.T) {
	t.Parallel()

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, _ string) (string, error) {
			return "", context.DeadlineExceeded
		},
	}

	got := run(t, newSandbox(t, funcs, nil),
		`try { await probe({}) } catch (e) { console.log("caught:" + e.message) }`)
	if !strings.Contains(got, "caught:") || !strings.Contains(got, context.DeadlineExceeded.Error()) {
		t.Errorf("expected caught error, got %q", got)
	}
}

func TestRun_MarshalArgUndefinedBecomesEmptyObject(t *testing.T) {
	t.Parallel()

	var gotArgs string

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, argsJSON string) (string, error) {
			gotArgs = argsJSON

			return "", nil
		},
	}

	run(t, newSandbox(t, funcs, nil), `probe()`)

	if gotArgs != "{}" {
		t.Errorf("expected empty object for missing arg, got %q", gotArgs)
	}
}

func TestRun_MarshalArgFallbackEmptyObject(t *testing.T) {
	t.Parallel()

	var gotArgs string

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, argsJSON string) (string, error) {
			gotArgs = argsJSON

			return "", nil
		},
	}

	run(t, newSandbox(t, funcs, nil), `probe({f: function(){}})`)

	if gotArgs != "{}" {
		t.Errorf("expected empty object on marshal failure, got %q", gotArgs)
	}
}

func TestRun_VerboseLogsCalls(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, _ string) (string, error) { return "ok", nil },
	}

	run(t, newSandbox(t, funcs, &log), `probe({a:1})`)

	if !strings.Contains(log.String(), "→ probe") || !strings.Contains(log.String(), "← probe") {
		t.Errorf("verbose log = %q", log.String())
	}
}

func TestRun_VerboseLogsToolError(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, _ string) (string, error) { return "", context.Canceled },
	}

	run(t, newSandbox(t, funcs, &log), `try { await probe({}) } catch (e) {}`)

	if !strings.Contains(log.String(), "→ probe") {
		t.Errorf("expected request log, got %q", log.String())
	}

	// On error the worker logs an error line rather than a result.
	if !strings.Contains(log.String(), "← probe error: "+context.Canceled.Error()) {
		t.Errorf("expected error result log, got %q", log.String())
	}
}

func TestRun_Timeout(t *testing.T) {
	t.Parallel()

	out, err := newSandbox(t, nil, nil).Run(context.Background(), `while (true) {}`, 30*time.Millisecond)
	if !errors.Is(err, sandbox.ErrScript) {
		t.Fatalf("Run: want sandbox.ErrScript, got %v", err)
	}

	if !strings.Contains(out, "timed out") {
		t.Errorf("expected timeout message, got %q", out)
	}
}

func TestRun_Cancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out, err := newSandbox(t, nil, nil).Run(ctx, `while (true) {}`, time.Hour)
	if !errors.Is(err, sandbox.ErrScript) {
		t.Fatalf("Run: want sandbox.ErrScript, got %v", err)
	}

	if !strings.Contains(out, "cancelled") {
		t.Errorf("expected cancellation message, got %q", out)
	}
}

func TestRun_ScriptError(t *testing.T) {
	t.Parallel()

	got := runFailed(t, newSandbox(t, nil, nil), `throw new Error("boom")`)
	if !strings.Contains(got, "[error]") || !strings.Contains(got, "boom") {
		t.Errorf("got %q", got)
	}
}

func TestRun_SyntaxError(t *testing.T) {
	t.Parallel()

	got := runFailed(t, newSandbox(t, nil, nil), `this is not js`)
	if !strings.Contains(got, "[error]") {
		t.Errorf("got %q", got)
	}
}

func TestRun_StatePersistsAcrossCalls(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	run(t, s, `globalThis.counter = 7;`)

	if got := run(t, s, `console.log(globalThis.counter)`); got != "7\n" {
		t.Errorf("state did not persist, got %q", got)
	}
}

func TestRun_ConcurrentCallsSerialize(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := s.Run(context.Background(), `1 + 1`, time.Second); err != nil {
				t.Errorf("concurrent Run: %v", err)
			}
		})
	}

	wg.Wait()
}

func TestRun_VerboseClipsLongStrings(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer

	// Build a string longer than 200 chars so clip truncates it.
	long := strings.Repeat("x", 250)

	funcs := map[string]sandbox.ToolFunc{
		"probe": func(_ context.Context, _ string) (string, error) { return long, nil },
	}

	run(t, newSandbox(t, funcs, &log), `probe({a:"`+strings.Repeat("y", 210)+`"})`)

	if !strings.Contains(log.String(), "…") {
		t.Errorf("expected clip ellipsis in verbose log, got %q", log.String())
	}
}

func TestRun_ConsoleOutputBeforeError(t *testing.T) {
	t.Parallel()

	got := runFailed(t, newSandbox(t, nil, nil), `console.log("start"); throw new Error("boom")`)
	if !strings.Contains(got, "start") {
		t.Errorf("expected pre-error console output, got %q", got)
	}

	if !strings.Contains(got, "boom") || !strings.Contains(got, "[error]") {
		t.Errorf("expected error suffix, got %q", got)
	}
}

func TestRun_ConsoleOutputBeforeTimeout(t *testing.T) {
	t.Parallel()

	out, err := newSandbox(
		t,
		nil,
		nil,
	).Run(context.Background(), `console.log("partial"); while (true) {}`, 30*time.Millisecond)
	if !errors.Is(err, sandbox.ErrScript) {
		t.Fatalf("Run: want sandbox.ErrScript, got %v", err)
	}

	if !strings.Contains(out, "partial") {
		t.Errorf("expected pre-timeout console output, got %q", out)
	}

	if !strings.Contains(out, "timed out") {
		t.Errorf("expected timeout suffix, got %q", out)
	}
}

func TestRun_AwaitAndParallel(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	funcs := map[string]sandbox.ToolFunc{
		// Returns a JSON object string -> sandbox auto-parses to a JS object.
		"fetch": func(_ context.Context, argsJSON string) (string, error) {
			calls.Add(1)

			return `{"v":` + extractN(argsJSON) + `}`, nil
		},
	}
	s := newSandbox(t, funcs, nil)

	out := run(t, s, `
		const xs = await Promise.all([1,2,3].map(n => fetch({ n })));
		console.log(JSON.stringify(xs.map(x => x.v)));`)

	if out != "[1,2,3]\n" {
		t.Errorf("out = %q, want [1,2,3]", out)
	}

	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

// extractN pulls the integer value of "n" out of a {"n":<int>} args JSON.
func extractN(argsJSON string) string {
	var m struct {
		N json.Number `json:"n"`
	}

	_ = json.Unmarshal([]byte(argsJSON), &m)

	return m.N.String()
}

func TestNew_ClampsNonPositiveMaxConcurrency(t *testing.T) {
	t.Parallel()

	for name, n := range map[string]int{"zero": 0, "negative": -3} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			funcs := map[string]sandbox.ToolFunc{
				"work": func(_ context.Context, _ string) (string, error) { return "ok", nil },
			}

			s, err := sandbox.New(funcs, nil, 32*1024, n, identityRedact)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			out, err := s.Run(context.Background(), `console.log(await work({}));`, 2*time.Second)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if out != "ok\n" {
				t.Errorf("out = %q, want ok (a zero-capacity semaphore parks every call until timeout)", out)
			}
		})
	}
}

func TestNew_ClampFallsBackToDefaultMaxConcurrency(t *testing.T) {
	t.Parallel()

	const items = sandbox.DefaultMaxConcurrency + 4

	var (
		verbose syncBuffer
		arrived = make(chan struct{}, items)
		release = make(chan struct{})
	)

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			arrived <- struct{}{}
			<-release

			return argsJSON, nil
		},
	}

	// maxConcurrency 0 must clamp to DefaultMaxConcurrency specifically (not
	// just any positive value), which is observable as mapConcurrent's baked-in
	// default limit: with no JS limit and items > DefaultMaxConcurrency, exactly
	// DefaultMaxConcurrency calls are issued before the first settle.
	s, err := sandbox.New(funcs, &verbose, 32*1024, 0, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	issued := make(chan int, 1)

	go func() {
		for range sandbox.DefaultMaxConcurrency {
			<-arrived
		}
		issued <- verbose.count("→ work")
		close(release)
	}()

	out, err := s.Run(context.Background(), `
		const items = Array.from({ length: `+strconv.Itoa(items)+` }, (_, i) => i);
		const xs = await mapConcurrent(items, (n) => work({ n }));
		console.log(xs.length);`, 10*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != strconv.Itoa(items)+"\n" {
		t.Errorf("out = %q, want all %d results", out, items)
	}

	if got := <-issued; got != sandbox.DefaultMaxConcurrency {
		t.Errorf("calls issued at the barrier = %d, want DefaultMaxConcurrency (%d)",
			got, sandbox.DefaultMaxConcurrency)
	}
}

func TestMapConcurrent_BoundedAndOrdered(t *testing.T) {
	t.Parallel()

	const (
		jsLimit  = 2
		capacity = 8 // Strictly greater than jsLimit so the Go semaphore is not the limiter.
	)

	var (
		cur, peak int32
		arrived   = make(chan struct{}, 5)
		release   = make(chan struct{})
	)

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			n := atomic.AddInt32(&cur, 1)
			for {
				m := atomic.LoadInt32(&peak)
				if n <= m || atomic.CompareAndSwapInt32(&peak, m, n) {
					break
				}
			}
			arrived <- struct{}{}
			<-release
			atomic.AddInt32(&cur, -1)

			return argsJSON, nil
		},
	}

	s, err := sandbox.New(funcs, nil, 32*1024, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go func() {
		// Deterministic barrier: wait until exactly jsLimit workers sit inside
		// the tool, then release everything. No sleeps.
		for range jsLimit {
			<-arrived
		}
		close(release)
	}()

	out, err := s.Run(context.Background(), `
		const xs = await mapConcurrent([0,1,2,3,4], (n) => work({ n }), 2);
		console.log(JSON.stringify(xs.map((x) => x.n)));`, 10*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "[0,1,2,3,4]\n" {
		t.Errorf("out = %q, want input-order results", out)
	}

	if got := atomic.LoadInt32(&peak); got != jsLimit {
		t.Errorf("peak concurrency = %d, want %d (the JS limit, not the capacity-%d semaphore)", got, jsLimit, capacity)
	}
}

func TestMapConcurrent_OrderUnderPermutedCompletion(t *testing.T) {
	t.Parallel()

	arrived := make(chan int, 3)
	release := [3]chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			var args struct {
				N int `json:"n"`
			}
			if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
				return "", err
			}
			arrived <- args.N
			<-release[args.N]

			return argsJSON, nil
		},
	}

	s, err := sandbox.New(funcs, nil, 32*1024, sandbox.DefaultMaxConcurrency, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go func() {
		for range 3 {
			<-arrived
		}
		// Complete in reverse order; results must still come back in input order.
		close(release[2])
		close(release[1])
		close(release[0])
	}()

	out, err := s.Run(context.Background(), `
		const xs = await mapConcurrent([0,1,2], (n) => work({ n }), 3);
		console.log(JSON.stringify(xs.map((x) => x.n)));`, 10*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "[0,1,2]\n" {
		t.Errorf("out = %q, want input order despite reverse completion", out)
	}
}

func TestMapConcurrent_FirstFailureStopsNewWorkAndPropagates(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			calls.Add(1)
			if strings.Contains(argsJSON, `"n":1`) {
				return "", errors.New("item one exploded")
			}

			return argsJSON, nil
		},
	}

	s, err := sandbox.New(funcs, nil, 32*1024, sandbox.DefaultMaxConcurrency, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// limit 1 serializes the pool: items 0 and 1 run, then the failure stops
	// the worker from pulling items 2 and 3.
	out, err := s.Run(context.Background(), `
		await mapConcurrent([0,1,2,3], (n) => work({ n }), 1);
		console.log("unreachable");`, 10*time.Second)
	if !errors.Is(err, sandbox.ErrScript) {
		t.Fatalf("Run: want sandbox.ErrScript, got %v", err)
	}

	if !strings.Contains(out, "[error]") || !strings.Contains(out, "item one exploded") {
		t.Errorf("out = %q, want the propagated first error", out)
	}

	if strings.Contains(out, "unreachable") {
		t.Errorf("out = %q, script continued past a rejected mapConcurrent", out)
	}

	if got := calls.Load(); got != 2 {
		t.Errorf("tool calls = %d, want 2 (no new work after the first failure)", got)
	}
}

func TestMapConcurrent_RejectionCatchableInScript(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	out := run(t, s, `
		try {
			await mapConcurrent([0], () => { throw new Error("boom"); });
		} catch (e) {
			console.log("caught: " + e.message);
		}`)

	if out != "caught: boom\n" {
		t.Errorf("out = %q, want the caught error", out)
	}
}

// syncBuffer is a goroutine-safe verbose writer so the test can sample it while
// Run is still in flight.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.Write(p)
}

func (s *syncBuffer) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return strings.Count(s.b.String(), sub)
}

func TestMapConcurrent_DefaultLimitIsHostCap(t *testing.T) {
	t.Parallel()

	const capacity = 2 // Host cap; must also become the default JS limit.

	var (
		verbose syncBuffer
		arrived = make(chan struct{}, 5)
		release = make(chan struct{})
	)

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			arrived <- struct{}{}
			<-release

			return argsJSON, nil
		},
	}

	s, err := sandbox.New(funcs, &verbose, 32*1024, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	issued := make(chan int, 1)

	go func() {
		// "→ work" verbose lines are written at JS call time on the loop
		// goroutine, synchronously, before any worker can settle. Once
		// `capacity` calls sit inside the tool, a correctly-defaulted pool has
		// issued exactly `capacity` calls; an unlimited default would already
		// have issued all 5. Sample, then release everything.
		for range capacity {
			<-arrived
		}
		issued <- verbose.count("→ work")
		close(release)
	}()

	out, err := s.Run(context.Background(), `
		const xs = await mapConcurrent([0,1,2,3,4], (n) => work({ n }));
		console.log(JSON.stringify(xs.map((x) => x.n)));`, 10*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "[0,1,2,3,4]\n" {
		t.Errorf("out = %q", out)
	}

	if got := <-issued; got != capacity {
		t.Errorf("calls issued at the barrier = %d, want %d (default limit must be the host cap)", got, capacity)
	}
}

func TestMapConcurrent_ExplicitLimitClampedToHostCap(t *testing.T) {
	t.Parallel()

	const (
		capacity = 2
		items    = 6
	)

	var (
		verbose syncBuffer
		arrived = make(chan struct{}, items)
		release = make(chan struct{})
	)

	funcs := map[string]sandbox.ToolFunc{
		"work": func(_ context.Context, argsJSON string) (string, error) {
			arrived <- struct{}{}
			<-release

			return argsJSON, nil
		},
	}

	s, err := sandbox.New(funcs, &verbose, 32*1024, capacity, identityRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	issued := make(chan int, 1)

	go func() {
		for range capacity {
			<-arrived
		}
		issued <- verbose.count("→ work")
		close(release)
	}()

	// Explicit limit 50 far above the host cap 2: the worker count must clamp to
	// the cap, so only `capacity` Go goroutines are ever spawned — not `items`.
	// (The semaphore bounds REAL concurrency regardless; this pins that the
	// logical fan-out — spawned goroutines/promises — is bounded too. Without
	// the clamp, all `items` "→ work" lines would be issued up front.)
	out, err := s.Run(context.Background(), `
		const xs = await mapConcurrent([0,1,2,3,4,5], (n) => work({ n }), 50);
		console.log(JSON.stringify(xs.map((x) => x.n)));`, 10*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "[0,1,2,3,4,5]\n" {
		t.Errorf("out = %q, want ordered results", out)
	}

	if got := <-issued; got != capacity {
		t.Errorf("calls issued at the barrier = %d, want %d (explicit limit must clamp to host cap)", got, capacity)
	}
}

func TestMapConcurrent_PlainValuesAndIndex(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	out := run(t, s, `console.log(JSON.stringify(await mapConcurrent([1,2,3], (x, i) => x + i)));`)
	if out != "[1,3,5]\n" {
		t.Errorf("out = %q, want fn(item, index) over plain values", out)
	}
}

func TestMapConcurrent_EmptyItems(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	out := run(t, s, `console.log(JSON.stringify(await mapConcurrent([], (x) => x)));`)
	if out != "[]\n" {
		t.Errorf("out = %q, want []", out)
	}
}

func TestMapConcurrent_NonArrayItemsThrows(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	out := run(t, s, `
		try {
			await mapConcurrent("nope", (x) => x);
		} catch (e) {
			console.log("caught: " + e.message);
		}`)

	if out != "caught: mapConcurrent: items must be an array\n" {
		t.Errorf("out = %q, want the TypeError", out)
	}
}

func TestMapConcurrent_NotOverwritable(t *testing.T) {
	t.Parallel()

	s := newSandbox(t, nil, nil)

	// Sloppy-mode assignment to a non-writable global is a silent no-op; the
	// helper must survive for the next Run (globalThis persists).
	out := run(t, s, `globalThis.mapConcurrent = "owned"; console.log(typeof globalThis.mapConcurrent);`)
	if out != "function\n" {
		t.Errorf("out = %q, want function (overwrite must not stick)", out)
	}

	out = run(t, s, `console.log(JSON.stringify(await mapConcurrent([1,2], (x) => x * 2)));`)
	if out != "[2,4]\n" {
		t.Errorf("out = %q, helper broken after attempted overwrite", out)
	}
}
