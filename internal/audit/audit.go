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

// AgentProvenance identifies the agent file that framed a run, so an audited
// action is attributable to the instructions that produced it.
//
// Source is a string, not the catalog's Source enum, for two reasons: this
// package is a leaf and must not import internal/agentcatalog, and an integer
// enum would be an unstable value to write into a forensic log. Valid values
// are "user" and "builtin".
//
// The agent BODY is never logged; SHA256 over the exact raw file bytes is what
// ties a record back to a specific file revision.
type AgentProvenance struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

// Record is one audited tool invocation. Time, Seq, and Actor are stamped by the
// Logger; the caller (the dispatch loop or the code_execution invoker) sets the
// rest. An attempt record carries no Decision/Outcome/Result.
type Record struct {
	Time      time.Time `json:"time"`
	Seq       uint64    `json:"seq"`
	SessionID string    `json:"session_id"`
	RunID     string    `json:"run_id"`
	CallID    string    `json:"call_id"`
	// ParentCallID is the call ID of the tool call a child record belongs to: a lookup_read is one credentialed
	// read an api_reference call made. Empty on every other record.
	ParentCallID string `json:"parent_call_id,omitempty"`
	Depth        int    `json:"depth"`
	Actor        string `json:"actor"`
	// Agent is the agent file that framed this run, when one was selected. Set
	// by the Logger, never by the caller.
	Agent     *AgentProvenance `json:"agent,omitempty"`
	Phase     string           `json:"phase"`
	Via       string           `json:"via,omitempty"`
	Tool      string           `json:"tool"`
	Arguments json.RawMessage  `json:"arguments"`
	Decision  string           `json:"decision,omitempty"`
	Outcome   string           `json:"outcome,omitempty"`
	Result    string           `json:"result,omitempty"`
	// Route is the egress route transport.do selected for an http_request
	// result (RouteDirect or RouteProxy); empty when the request was rejected
	// before selection or the record is not an http_request result.
	Route string `json:"route,omitempty"`
	// RedactArgs requests redaction of Arguments before logging. It is set for
	// calls whose arguments were never shown at an approval prompt (inner
	// code_execution calls, ungated orchestration tools, unknown tools), so a
	// secret-shaped value a script or the model copied from earlier output is not
	// persisted verbatim. Not serialized.
	RedactArgs bool `json:"-"`
}

// Phase, Decision, Outcome and Via field values. The Route values live in
// context.go, beside the recorder that produces them.
const (
	PhaseAttempt = "attempt"
	PhaseResult  = "result"

	DecisionApproved        = "approved"
	DecisionDenied          = "denied"
	DecisionUngated         = "ungated"
	DecisionApprovedSession = "approved_session"
	// DecisionUnprompted labels a call that ran without a prompt by design and could use a connector's credentials
	// for metadata reads at host-built paths: a targeted api_reference lookup and each read it made.
	DecisionUnprompted = "unprompted"

	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"

	ViaCodeExecution = "code_execution"
	ViaAPIReference  = "api_reference"

	// ToolLookupRead is the tool name of a child record for one credentialed read a targeted api_reference
	// lookup made.
	ToolLookupRead = "lookup_read"
	// ToolLookupBootstrap is the tool name of a child record for one control-plane call a targeted api_reference
	// lookup triggered while it resolved its target: a cluster resolution or the ClusterRole fetch.
	ToolLookupBootstrap = "lookup_bootstrap"
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
//
// The first write or marshal failure latches: every later Log returns that same
// error, writes nothing and spends no sequence number. A record written from a
// goroutine that outlives its tool call can fail after the loop's last write, so
// the latch keeps that failure for the closer to report.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	clock    func() time.Time
	redactor redactor
	actor    string
	agent    *AgentProvenance
	seq      uint64
	err      error

	// drain bounds how long the closer waits for held records; holds counts them, and drained is closed when the
	// count returns to zero. They have their own lock, so a record written by a holder never waits on a closer.
	drain   time.Duration
	notice  func(time.Duration)
	holdMu  sync.Mutex
	holds   int
	drained chan struct{}
}

// Option configures a Logger at construction.
type Option func(*Logger)

// WithDrain sets how long the closer waits for records still held (Hold) before it closes the writer.
func WithDrain(d time.Duration) Option {
	return func(l *Logger) { l.drain = d }
}

// WithDrainNotice sets a function the closer calls once, with the bound, when it is about to wait for a held
// record, so a run that pauses at exit can say why.
func WithDrainNotice(notice func(time.Duration)) Option {
	return func(l *Logger) { l.notice = notice }
}

// PendingRecordsError reports records held (Hold) that were not written before the log closed. It matches ErrLog,
// since the log is missing records.
type PendingRecordsError struct {
	Records int
}

func (e *PendingRecordsError) Error() string {
	if e.Records == 1 {
		return ErrLog.Error() + ": 1 record was not written before the log closed"
	}

	return fmt.Sprintf("%s: %d records were not written before the log closed", ErrLog, e.Records)
}

// Is reports that a PendingRecordsError is an ErrLog.
func (e *PendingRecordsError) Is(target error) bool { return target == ErrLog }

// WithActor sets the actor identity stamped on every record (e.g. provider/model).
func WithActor(a string) Option {
	return func(l *Logger) { l.actor = a }
}

// WithAgent sets the agent provenance stamped on every record. The Logger keeps
// its own copy, so a later mutation by the caller cannot alter what is logged.
func WithAgent(p AgentProvenance) Option {
	return func(l *Logger) {
		copied := p
		l.agent = &copied
	}
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

	if l.err != nil {
		return l.err
	}

	l.seq++
	rec.Seq = l.seq
	rec.Time = l.clock()
	rec.Actor = l.actor
	// Provenance is the Logger's to set, like Actor: a caller-supplied value is
	// overwritten so a tool call can never forge the agent it claims to be under.
	rec.Agent = l.agent
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
		l.err = fmt.Errorf("%w: marshal: %w", ErrLog, err)

		return l.err
	}
	line = append(line, '\n')
	if _, werr := l.w.Write(line); werr != nil {
		l.err = fmt.Errorf("%w: write: %w", ErrLog, werr)

		return l.err
	}

	return nil
}

// Err returns the latched write or marshal failure, or nil while every write has
// succeeded.
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.err
}

// Holder is a Sink that can be asked, at close, to wait for a record still to be written. *Logger implements it.
type Holder interface {
	Hold() (release func())
}

var _ Holder = (*Logger)(nil)

// Hold reports a record that will be written later, by a call that can outlive the tool call that started it: a
// targeted lookup's control-plane call runs on after the lookup returns when it times out. The closer waits for
// every hold to be released before it closes. The release it returns counts once, however often it is called.
func (l *Logger) Hold() func() {
	l.holdMu.Lock()
	if l.holds == 0 {
		l.drained = make(chan struct{})
	}
	l.holds++
	l.holdMu.Unlock()
	var once sync.Once

	return func() {
		once.Do(func() {
			l.holdMu.Lock()
			defer l.holdMu.Unlock()
			if l.holds--; l.holds == 0 {
				close(l.drained)
			}
		})
	}
}

// pendingAfter waits up to the drain bound for every hold to be released and returns how many are still held. It
// re-reads the holds after every wake, so a hold taken after the count reached zero is waited for too.
func (l *Logger) pendingAfter() int {
	deadline := time.Now().Add(l.drain)
	noticed := false
	for {
		n, drained := l.held()
		if n == 0 {
			return 0
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return n
		}
		if !noticed && l.notice != nil {
			l.notice(l.drain)
		}
		noticed = true
		timer := time.NewTimer(wait)
		select {
		case <-drained:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// held returns the open holds and the channel closed when they reach zero.
func (l *Logger) held() (int, chan struct{}) {
	l.holdMu.Lock()
	defer l.holdMu.Unlock()

	return l.holds, l.drained
}

// Closer wraps the audit writer's close for the composition root. It first waits, up to the drain bound, for the
// records still held, then always closes. It returns the latched failure when there is one, then a held record
// that never arrived, then the close error, so a failed or missing write that no later record reported still ends
// the run with an error.
func (l *Logger) Closer(closeWriter func() error) func() error {
	return func() error {
		// A latched failure is what the closer returns whatever a held record does, so it does not wait for one.
		pending := 0
		if l.Err() == nil {
			pending = l.pendingAfter()
		}
		cerr := closeWriter()
		// A hold taken once the wait was over may not land before the process exits, so it counts as missing too.
		if late, _ := l.held(); late > pending {
			pending = late
		}
		if err := l.Err(); err != nil {
			return err
		}
		if pending > 0 {
			return &PendingRecordsError{Records: pending}
		}

		return cerr
	}
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
