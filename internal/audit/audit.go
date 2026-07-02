// Package audit writes a persistent, structured JSONL trail of every tool call
// (and approval decision) the agent makes. It is a pure leaf over the standard
// library and internal/redact, so nothing it depends on can create an import
// cycle. The file open and rotation live in the excluded audit_shell.go.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cynative/cynative/internal/redact"
)

// Record is one audited tool invocation. Time, Seq, and Actor are stamped by the
// Logger; the caller (the dispatch loop or the code_execution invoker) sets the
// rest. An attempt record carries no Decision/Outcome/Result.
type Record struct {
	Time      time.Time       `json:"time"`
	Seq       uint64          `json:"seq"`
	SessionID string          `json:"session_id"`
	RunID     string          `json:"run_id"`
	CallID    string          `json:"call_id"`
	Depth     int             `json:"depth"`
	Actor     string          `json:"actor"`
	Phase     string          `json:"phase"`
	Via       string          `json:"via,omitempty"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Decision  string          `json:"decision,omitempty"`
	Outcome   string          `json:"outcome,omitempty"`
	Result    string          `json:"result,omitempty"`
	// RedactArgs requests redaction of Arguments before logging. It is set for
	// calls whose arguments were never shown at an approval prompt (inner
	// code_execution calls, ungated orchestration tools, unknown tools), so a
	// secret-shaped value a script or the model copied from earlier output is not
	// persisted verbatim. Not serialized.
	RedactArgs bool `json:"-"`
}

// Phase, Decision, Outcome, and Via field values.
const (
	PhaseAttempt = "attempt"
	PhaseResult  = "result"

	DecisionApproved        = "approved"
	DecisionDenied          = "denied"
	DecisionUngated         = "ungated"
	DecisionApprovedSession = "approved_session"

	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"

	ViaCodeExecution = "code_execution"
)

// ErrLog wraps any audit write/marshal failure. [errors.Is](err, ErrLog) marks a
// fatal audit error that must abort the run (fail-closed).
var ErrLog = errors.New("audit: log write failed")

// Sink records audit events. *Logger implements it; a nil sink (used when audit
// is disabled, or in tests) is treated as a no-op by callers.
type Sink interface {
	Log(rec Record) error
}

// redactor is the subset of *redact.Redactor the Logger needs.
type redactor interface {
	Redact(string) string
}

// Logger serializes Records as one JSON object per line to w. It is safe for
// concurrent use: every Log call is serialized under mu, so concurrent inner
// sandbox workers and the verifier panel can share one Logger.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	clock    func() time.Time
	redactor redactor
	actor    string
	seq      uint64
}

// Option configures a Logger at construction.
type Option func(*Logger)

// WithActor sets the actor identity stamped on every record (e.g. provider/model).
func WithActor(a string) Option {
	return func(l *Logger) { l.actor = a }
}

// New builds a Logger writing to w. The clock defaults to [time.Now] and the
// redactor to redact.New().
func New(w io.Writer, opts ...Option) *Logger {
	l := &Logger{ //nolint:exhaustruct // mu/seq/actor zero-init; clock/redactor defaulted below.
		w:        w,
		clock:    time.Now,
		redactor: redact.New(),
	}
	for _, o := range opts {
		o(l)
	}

	return l
}

// Log stamps Time/Seq/Actor, redacts only the Result (arguments stay verbatim —
// they equal what the operator saw at the approval prompt), and writes one JSONL
// line. Any marshal/write error is wrapped with ErrLog so callers fail closed.
func (l *Logger) Log(rec Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	rec.Seq = l.seq
	rec.Time = l.clock()
	rec.Actor = l.actor
	rec.Result = l.redactor.Redact(rec.Result)
	// Approval-gated I/O arguments are verbatim — the operator saw and approved them
	// at the prompt. Everything else (inner code_execution calls, ungated
	// orchestration tools, unknown tools) was never approval-shown, so a resolved
	// secret a script or the model copied into the call — e.g. a signed redirect URL
	// or evidence lifted from prior output — must be scrubbed from its arguments.
	if rec.RedactArgs {
		rec.Arguments = RawArgs(l.redactor.Redact(string(rec.Arguments)))
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("%w: marshal: %w", ErrLog, err)
	}
	line = append(line, '\n')
	if _, werr := l.w.Write(line); werr != nil {
		return fmt.Errorf("%w: write: %w", ErrLog, werr)
	}

	return nil
}

// RawArgs returns s as a [json.RawMessage] when it is valid JSON, otherwise a
// JSON-quoted string of s, so a malformed argument blob can never make a Record
// fail to marshal.
func RawArgs(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	quoted, _ := json.Marshal(s) // Marshaling a string cannot fail.

	return quoted
}
