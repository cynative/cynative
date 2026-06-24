// Package sandbox runs untrusted JavaScript in an embedded sobek runtime,
// exposing host capabilities to scripts only through explicitly registered tool
// functions. A single runtime persists for the sandbox's lifetime, so state set
// by one Run is visible to later Runs.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/grafana/sobek"
)

// ErrScript signals that a Run failed — a compile/syntax error, an uncatchable
// runtime error, a timeout/cancellation, or an uncaught rejection. The returned
// result string still carries the full diagnostic for the model; the error lets
// the caller record the failure (e.g. in an audit log) without parsing the text.
var ErrScript = errors.New("sandbox: script execution failed")

// ToolFunc is a host capability exposed to scripts as a JS function. It receives
// the call's argument object encoded as a JSON string and returns a result
// string. A returned error is surfaced to the script as a thrown JS exception.
// It runs on a worker goroutine and MUST honor ctx: when ctx is done it should
// return promptly, because Run waits for all in-flight tool calls to finish
// before it returns.
type ToolFunc func(ctx context.Context, argsJSON string) (string, error)

const (
	noOutputMessage  = "[script completed with no output]"
	emptyObject      = "{}"
	verboseClipLimit = 200
	interruptReason  = "sandbox: execution interrupted"
)

// DefaultMaxConcurrency is the default cap on how many inner tool calls run
// simultaneously; callers pass it to New. New also falls back to it when asked
// for a non-positive cap.
const DefaultMaxConcurrency = 16

// Sandbox is a persistent JavaScript runtime guarded by a mutex. Build it with
// New; drive it with Run.
type Sandbox struct {
	mu        sync.Mutex
	vm        *sobek.Runtime
	out       *bytes.Buffer
	maxOutput int
	verbose   io.Writer
	redact    func(string) string
	sem       chan struct{}

	// Per-run state, owned by the loop goroutine (set under mu at the start of
	// each Run). runCtx is the in-flight Run's timeout context; pending carries
	// worker postbacks to the loop; done is closed when the Run finishes so
	// parked workers can escape; inFlight counts outstanding tool calls; workers
	// tracks spawned worker goroutines so Run can wait for them all to escape
	// before it returns (and before the next Run rewrites these fields).
	runCtx   context.Context
	pending  chan func() error
	done     chan struct{}
	inFlight int
	workers  sync.WaitGroup
}

// New builds a sandbox whose runtime exposes console.log/console.error plus one
// JS function per entry in funcs. verbose, when non-nil, receives a line per
// inner tool call. maxOutput caps the bytes returned by Run; when output exceeds
// maxOutput, the returned string is the first maxOutput bytes plus a short
// truncation marker, so the result can slightly exceed maxOutput. redact is
// applied to every tool result and error message at the sandbox boundary (ahead
// of the verbose log, resolve, and reject) and MUST be non-nil: it is a security
// boundary, so a nil redact is a programming error that panics on first use
// rather than silently leaking unredacted content.
func New(
	funcs map[string]ToolFunc, verbose io.Writer, maxOutput, maxConcurrency int, redact func(string) string,
) (*Sandbox, error) {
	if maxConcurrency < 1 {
		// A zero-capacity semaphore would park every tool call until the Run
		// timeout (and a negative one panics in make), so a non-positive cap
		// falls back to the default.
		maxConcurrency = DefaultMaxConcurrency
	}

	s := &Sandbox{ //nolint:exhaustruct // per-run fields are set in Run.
		out:       &bytes.Buffer{},
		maxOutput: maxOutput,
		verbose:   verbose,
		redact:    redact,
		sem:       make(chan struct{}, maxConcurrency),
	}

	return s, buildRuntime(s, funcs)
}

// Run executes code on the persistent runtime and returns its captured output.
// Script errors and timeouts are included in the result string so the caller can
// hand them to the model, AND are signaled by returning ErrScript so the caller
// can record the failure (e.g. in an audit log) without parsing the text. A
// successful run returns a nil error.
func (s *Sandbox) Run(ctx context.Context, code string, timeout time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.out.Reset()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	s.runCtx = runCtx
	s.pending = make(chan func() error)
	s.done = make(chan struct{})
	s.inFlight = 0
	s.workers = sync.WaitGroup{}

	watchDone := make(chan struct{})

	var watch sync.WaitGroup

	watch.Go(func() {
		select {
		case <-runCtx.Done():
			s.vm.Interrupt(interruptReason)
		case <-watchDone:
		}
	})

	var value sobek.Value

	prog, runErr := compileWrapped(code)
	if runErr == nil {
		value, runErr = s.vm.RunProgram(prog)
		if runErr == nil {
			runErr = s.loop()
		}
	}

	// Release any parked workers, then wait for every worker and the watchdog to
	// exit before returning, so the next Run can safely rewrite the per-run
	// fields these goroutines read.
	close(s.done)
	s.workers.Wait()

	close(watchDone)
	watch.Wait()
	s.vm.ClearInterrupt()

	// Pass the parent ctx (not runCtx) so assemble/ctxSuffix can distinguish
	// caller cancellation from an expiring internal timeout.
	out, failed := s.assemble(ctx, value, runErr, timeout)
	if failed {
		return out, ErrScript
	}

	return out, nil
}

// assemble builds the result string from the output buffer plus a trailing
// diagnostic and reports whether the run failed. It reports a timeout/cancellation
// first (the runCtx fired), then an uncatchable run error, then a rejected IIFE
// promise (an uncaught script or tool error). A fulfilled promise contributes
// nothing and is not a failure: only console output returns.
func (s *Sandbox) assemble(
	ctx context.Context, value sobek.Value, runErr error, timeout time.Duration,
) (string, bool) {
	out := s.out.String()
	failed := false

	switch {
	case s.runCtx.Err() != nil:
		out += ctxSuffix(ctx, timeout)
		failed = true
	case runErr != nil:
		out += "\n[error] " + runErr.Error()
		failed = true
	default:
		if p, ok := value.Export().(*sobek.Promise); ok && p.State() == sobek.PromiseStateRejected {
			out += "\n[error] " + p.Result().String()
			failed = true
		}
	}

	return s.finalize(out), failed
}

// ctxSuffix renders a timeout vs. a parent cancellation.
func ctxSuffix(ctx context.Context, timeout time.Duration) string {
	if ctx.Err() != nil {
		return "\n[execution cancelled]"
	}

	return fmt.Sprintf("\n[execution timed out after %s]", timeout)
}

// finalize truncates to maxOutput, repairs invalid UTF-8, and substitutes a
// placeholder for empty output.
func (s *Sandbox) finalize(out string) string {
	if len(out) > s.maxOutput {
		out = out[:s.maxOutput] + fmt.Sprintf("\n... [output truncated at %d bytes]", s.maxOutput)
	}

	out = strings.ToValidUTF8(out, "�")

	if out == "" {
		return noOutputMessage
	}

	return out
}

// registerAll sets each entry on the runtime via set, wrapping the first failure
// with the offending name. Pure over the injected setter so it is unit-tested with
// a fake setter (covering both the success and error-wrap paths) instead of a live
// sobek runtime — keeping buildRuntime (the shell) under the thin-shell budget.
func registerAll(set func(name string, value any) error, entries map[string]any) error {
	for name, value := range entries {
		if err := set(name, value); err != nil {
			return fmt.Errorf("sandbox: register %q: %w", name, err)
		}
	}
	return nil
}

// consoleLog appends its arguments to the per-run output buffer.
func (s *Sandbox) consoleLog(call sobek.FunctionCall) sobek.Value {
	parts := make([]string, len(call.Arguments))
	for i, arg := range call.Arguments {
		parts[i] = formatValue(arg)
	}

	s.out.WriteString(strings.Join(parts, " "))
	s.out.WriteByte('\n')

	return sobek.Undefined()
}

// marshalArg encodes a JS value as a JSON object string. Undefined/null and
// unmarshalable values become an empty object so tools always get valid JSON.
func marshalArg(v sobek.Value) string {
	if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
		return emptyObject
	}

	if b, err := json.Marshal(v.Export()); err == nil {
		return string(b)
	}

	return emptyObject
}

// formatValue renders a JS value for console output: strings raw, objects and
// arrays as JSON, everything else via its JS string form.
func formatValue(v sobek.Value) string {
	if v == nil || sobek.IsUndefined(v) {
		return "undefined"
	}

	if sobek.IsNull(v) {
		return "null"
	}

	switch v.Export().(type) {
	case string:
		return v.String()
	case map[string]any, []any:
		if b, err := json.Marshal(v.Export()); err == nil {
			return string(b)
		}
	}

	return v.String()
}

// clip shortens a string to a single line for verbose logging.
func clip(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > verboseClipLimit {
		return s[:verboseClipLimit] + "…"
	}

	return s
}
