package audit

import (
	"context"
	"sync"
	"sync/atomic"
)

// ctxKey is the unexported context-key type for this package's values.
type ctxKey int

const (
	scopeKey ctxKey = iota
	decisionKey
	fatalKey
	failureKey
)

// Scope is the per-call correlation threaded from the agent dispatch loop into
// tools, so code_execution can stamp its inner http_request records with the
// enclosing call's session/run/depth.
type Scope struct {
	SessionID string
	RunID     string
	Depth     int
}

// WithScope attaches s to ctx.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey, s)
}

// ScopeFrom returns the Scope attached to ctx, if any.
func ScopeFrom(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey).(Scope)

	return s, ok
}

// Decision is the approval outcome the approval decorator records and the
// dispatch loop reads. Using a context-carried pointer makes the decision
// unforgeable — a tool's output string can no longer masquerade as a denial.
type Decision struct {
	Decided  bool
	Approved bool
	// Session is set when the approval came from a pre-existing per-tool session
	// grant (the operator's earlier [a]) rather than a fresh prompt for this call.
	Session bool
}

// WithDecision installs a fresh Decision recorder on ctx and returns it.
func WithDecision(ctx context.Context) (context.Context, *Decision) {
	d := &Decision{} //nolint:exhaustruct // Decided, Approved, and Session all default false until recorded.

	return context.WithValue(ctx, decisionKey, d), d
}

// RecordDecision records the approval outcome on the recorder in ctx. It is a
// no-op when no recorder is installed (e.g. unit tests of the bare tool).
func RecordDecision(ctx context.Context, approved bool) {
	if d, ok := ctx.Value(decisionKey).(*Decision); ok {
		d.Decided = true
		d.Approved = approved
	}
}

// RecordSessionApproval records an approval that came from a standing session
// grant (no fresh human review of this call). It is a no-op when no recorder is
// installed.
func RecordSessionApproval(ctx context.Context) {
	if d, ok := ctx.Value(decisionKey).(*Decision); ok {
		d.Decided, d.Approved, d.Session = true, true, true
	}
}

// SessionApproved reports whether the decision recorder on ctx (if any) marks a
// session-grant approval. False when no recorder is installed.
func SessionApproved(ctx context.Context) bool {
	d, ok := ctx.Value(decisionKey).(*Decision)

	return ok && d.Session
}

// Fatal latches the first fatal inner audit-write error so code_execution.Run
// can return it (aborting the run) even though the sandbox stringifies ordinary
// script errors.
type Fatal struct {
	mu  sync.Mutex
	err error
}

// WithFatal installs a fresh Fatal latch on ctx and returns it.
func WithFatal(ctx context.Context) (context.Context, *Fatal) {
	f := &Fatal{} //nolint:exhaustruct // mu/err zero-init.

	return context.WithValue(ctx, fatalKey, f), f
}

// FatalFrom returns the Fatal latch attached to ctx, if any.
func FatalFrom(ctx context.Context) (*Fatal, bool) {
	f, ok := ctx.Value(fatalKey).(*Fatal)

	return f, ok
}

// Set latches err the first time it is called with a non-nil error.
func (f *Fatal) Set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = err
	}
}

// Err returns the latched error, or nil.
func (f *Fatal) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.err
}

// Failure lets an I/O tool that returns its execution failure as a result string
// (so the model can self-correct rather than aborting the run) still signal a
// non-OK outcome to the dispatch loop for the audit record. It counts failures so a
// code_execution script's concurrent inner http_request calls can each mark a failure
// safely (the count is atomic) and the dispatch loop can credit each one to the
// consecutive-failure halt instead of collapsing them into a single increment.
type Failure struct {
	count    atomic.Int64 // no-progress outcomes (errors, denials, >=400 responses).
	progress atomic.Int64 // useful outcomes (a <400 response), so a mixed fan-out is not "stuck".
}

// WithFailure installs a fresh Failure recorder on ctx and returns it.
func WithFailure(ctx context.Context) (context.Context, *Failure) {
	f := &Failure{} //nolint:exhaustruct // count's zero value is a valid atomic.Int64.

	return context.WithValue(ctx, failureKey, f), f
}

// MarkFailed records one non-OK tool outcome on the recorder in ctx. It is a no-op
// when no recorder is installed, and safe to call from concurrent sandbox workers.
func MarkFailed(ctx context.Context) {
	if f, ok := ctx.Value(failureKey).(*Failure); ok {
		f.count.Add(1)
	}
}

// FailureFrom returns the failure recorder installed on ctx, if any.
func FailureFrom(ctx context.Context) (*Failure, bool) {
	f, ok := ctx.Value(failureKey).(*Failure)

	return f, ok
}

// MarkProgress records one useful (non-failed) outcome on the recorder in ctx — a
// request that got a sub-4xx response. No-op without a recorder; concurrency-safe.
func MarkProgress(ctx context.Context) {
	if f, ok := ctx.Value(failureKey).(*Failure); ok {
		f.progress.Add(1)
	}
}

// Failed reports whether the call was marked failed at least once.
func (f *Failure) Failed() bool { return f.count.Load() > 0 }

// Count returns how many times the call (or its inner sandbox calls) was marked failed.
func (f *Failure) Count() int { return int(f.count.Load()) }

// Progress returns how many useful (sub-4xx) outcomes the call (or its inner sandbox
// calls) recorded — used to keep a mixed-success fan-out off the no-progress halt.
func (f *Failure) Progress() int { return int(f.progress.Load()) }
