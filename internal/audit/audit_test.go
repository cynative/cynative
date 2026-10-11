package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/audit"
)

type fixedRedactor struct{}

func (fixedRedactor) Redact(s string) string { return strings.ReplaceAll(s, "SECRET", "[REDACTED]") }

func fixedClock() func() time.Time {
	ts := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

	return func() time.Time { return ts }
}

func TestLogger_Log_StampsRedactsAndSequences(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(
		&buf,
		audit.WithClock(fixedClock()),
		audit.WithRedactor(fixedRedactor{}),
		audit.WithActor("anthropic/claude-opus-4-8"),
	)

	if err := l.Log(audit.Record{ //nolint:exhaustruct // Logger stamps the rest.
		RunID: "R1", Tool: "http_request", Phase: audit.PhaseResult,
		Arguments: json.RawMessage(`{"url":"https://x"}`),
		Decision:  audit.DecisionApproved, Outcome: audit.OutcomeOK, Result: "token=SECRET",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Log(audit.Record{ //nolint:exhaustruct // Logger stamps the rest.
		RunID: "R1", Tool: "code_execution", Phase: audit.PhaseAttempt,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Seq != 1 {
		t.Errorf("Seq: got %d want 1", rec.Seq)
	}
	if rec.Actor != "anthropic/claude-opus-4-8" {
		t.Errorf("Actor: got %q", rec.Actor)
	}
	if rec.Time.IsZero() {
		t.Error("Time not stamped")
	}
	if rec.Result != "token=[REDACTED]" {
		t.Errorf("Result not redacted: %q", rec.Result)
	}
	if string(rec.Arguments) != `{"url":"https://x"}` {
		t.Errorf("Arguments not verbatim: %s", rec.Arguments)
	}
	var rec2 audit.Record
	_ = json.Unmarshal([]byte(lines[1]), &rec2)
	if rec2.Seq != 2 {
		t.Errorf("Seq monotonic: got %d want 2", rec2.Seq)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestLogger_Log_WriteError_WrapsErrLog(t *testing.T) {
	t.Parallel()

	l := audit.New(failWriter{})
	err := l.Log(audit.Record{Tool: "x", Phase: audit.PhaseAttempt}) //nolint:exhaustruct // Logger stamps the rest.
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want errors.Is ErrLog, got %v", err)
	}
}

func TestLogger_Log_ConcurrentSafe(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(&buf)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_ = l.Log(
				audit.Record{Tool: "x", Phase: audit.PhaseAttempt},
			) //nolint:exhaustruct // Logger stamps the rest.
		})
	}
	wg.Wait()

	if got := strings.Count(buf.String(), "\n"); got != 50 {
		t.Errorf("want 50 lines, got %d", got)
	}
}

func TestRawArgs(t *testing.T) {
	t.Parallel()

	if got := audit.RawArgs(`{"a":1}`); string(got) != `{"a":1}` {
		t.Errorf("valid JSON not passed through: %s", got)
	}
	got := audit.RawArgs("not json")
	if string(got) != `"not json"` {
		t.Errorf("invalid JSON not quoted: %s", got)
	}
	if !json.Valid(got) {
		t.Errorf("RawArgs produced invalid JSON: %s", got)
	}
}

func TestLogger_Log_MarshalError_WrapsErrLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(&buf)
	// An invalid json.RawMessage makes json.Marshal of the Record fail.
	err := l.Log(audit.Record{ //nolint:exhaustruct // only Arguments matters here.
		Tool: "x", Phase: audit.PhaseAttempt, Arguments: json.RawMessage("{bad"),
	})
	if !errors.Is(err, audit.ErrLog) {
		t.Fatalf("want ErrLog on marshal failure, got %v", err)
	}
}

func TestNew_NilOptionsKeepDefaults(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(&buf, audit.WithClock(nil), audit.WithRedactor(nil))
	if err := l.Log(
		audit.Record{Tool: "x", Phase: audit.PhaseAttempt},
	); err != nil { //nolint:exhaustruct // Logger stamps the rest.
		t.Fatalf("Log with nil options: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"tool":"x"`)) {
		t.Errorf("unexpected line: %s", buf.Bytes())
	}
}

func TestLogger_Log_RedactsArgumentsWhenRequested(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(&buf, audit.WithRedactor(fixedRedactor{}))

	// RedactArgs set (inner code_execution / ungated / unknown call): arguments are
	// redacted because they were never shown at an approval prompt.
	if err := l.Log(audit.Record{ //nolint:exhaustruct // Logger stamps the rest.
		Tool: "http_request", Phase: audit.PhaseAttempt, Via: audit.ViaCodeExecution,
		Arguments: json.RawMessage(`{"url":"https://x?sig=SECRET"}`), RedactArgs: true,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// RedactArgs unset (approval-gated I/O call): arguments stay verbatim.
	if err := l.Log(audit.Record{ //nolint:exhaustruct // Logger stamps the rest.
		Tool: "http_request", Phase: audit.PhaseAttempt,
		Arguments: json.RawMessage(`{"url":"https://x?sig=SECRET"}`),
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	if strings.Contains(lines[0], "SECRET") || !strings.Contains(lines[0], "[REDACTED]") {
		t.Errorf("RedactArgs record not redacted: %s", lines[0])
	}
	if !strings.Contains(lines[1], "sig=SECRET") {
		t.Errorf("verbatim record should keep arguments: %s", lines[1])
	}
}

func TestLog_StampsAgentProvenance(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	prov := audit.AgentProvenance{
		Name:   "public-exposure",
		Source: "project",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	l := audit.New(&buf, audit.WithAgent(prov))

	//nolint:exhaustruct // only the stamped fields matter.
	if err := l.Log(audit.Record{Tool: "http_request", Phase: audit.PhaseAttempt}); err != nil {
		t.Fatalf("Log() = %v", err)
	}

	var rec audit.Record
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if rec.Agent == nil {
		t.Fatal("Agent provenance was not stamped")
	}
	if *rec.Agent != prov {
		t.Fatalf("Agent = %+v, want %+v", *rec.Agent, prov)
	}
}

func TestLog_OmitsAgentWhenUnset(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	l := audit.New(&buf)
	//nolint:exhaustruct // only the stamped fields matter.
	if err := l.Log(audit.Record{Tool: "http_request", Phase: audit.PhaseAttempt}); err != nil {
		t.Fatalf("Log() = %v", err)
	}

	if strings.Contains(buf.String(), `"agent"`) {
		t.Fatalf("agent key present with no provenance configured: %s", buf.String())
	}
}

// A caller-supplied Agent on the Record must not survive: the logger is the
// single source of provenance, exactly as it is for Actor.
func TestLog_OverwritesCallerSuppliedAgent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	configured := audit.AgentProvenance{Name: "real", Source: "user", SHA256: "abc"}
	l := audit.New(&buf, audit.WithAgent(configured))

	forged := audit.AgentProvenance{Name: "forged", Source: "project", SHA256: "000"}
	//nolint:exhaustruct // only the stamped fields matter.
	if err := l.Log(audit.Record{Tool: "t", Phase: audit.PhaseAttempt, Agent: &forged}); err != nil {
		t.Fatalf("Log() = %v", err)
	}

	var rec audit.Record
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if rec.Agent == nil || rec.Agent.Name != "real" {
		t.Fatalf("Agent = %+v, want the logger's configured provenance", rec.Agent)
	}
}

func TestLog_ParentCallIDFollowsCallIDAndIsOmittedWhenEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := audit.New(&buf, audit.WithClock(fixedClock()), audit.WithActor("a"))
	for _, rec := range []audit.Record{
		{CallID: "C", Phase: audit.PhaseAttempt, Tool: "api_reference", Arguments: json.RawMessage(`{}`)},
		{
			CallID: "K", ParentCallID: "C", Phase: audit.PhaseAttempt, Via: audit.ViaAPIReference,
			Tool: audit.ToolLookupRead, Arguments: json.RawMessage(`{}`),
		},
	} {
		if err := l.Log(rec); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if strings.Contains(lines[0], "parent_call_id") {
		t.Errorf("parent record carries parent_call_id: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"call_id":"K","parent_call_id":"C","depth":0`) ||
		!strings.Contains(lines[1], `"via":"api_reference","tool":"lookup_read"`) {
		t.Errorf("child record: %s", lines[1])
	}
}

// flakyWriter fails exactly its failOn-th write (1-based) and accepts every other one.
type flakyWriter struct {
	buf    bytes.Buffer
	n      int
	failOn int
}

func (w *flakyWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n == w.failOn {
		return 0, errors.New("disk full")
	}

	return w.buf.Write(p)
}

// TestLogger_Log_LatchesTheFirstFailure pins the sticky latch: once a write fails, every later Log returns that
// same error and writes nothing, even when the writer would accept the line, and Err reports it.
func TestLogger_Log_LatchesTheFirstFailure(t *testing.T) {
	t.Parallel()

	w := &flakyWriter{failOn: 2}
	l := audit.New(w)
	rec := audit.Record{Tool: "x", Phase: audit.PhaseAttempt} //nolint:exhaustruct // Logger stamps the rest.
	if err := l.Log(rec); err != nil || l.Err() != nil {
		t.Fatalf("first Log = %v, Err = %v, want both nil", err, l.Err())
	}
	first := l.Log(rec)
	if !errors.Is(first, audit.ErrLog) {
		t.Fatalf("second Log = %v, want ErrLog", first)
	}
	later := l.Log(rec)
	if !errors.Is(later, first) || !errors.Is(l.Err(), first) {
		t.Errorf("later Log = %v and Err = %v, want the latched %v", later, l.Err(), first)
	}
	if w.n != 2 || strings.Count(w.buf.String(), "\n") != 1 {
		t.Errorf("writer saw %d writes and kept %q, want two writes and one line", w.n, w.buf.String())
	}
}

// TestLogger_Log_LatchesAMarshalFailure pins that a marshal failure latches as a write failure does.
func TestLogger_Log_LatchesAMarshalFailure(t *testing.T) {
	t.Parallel()

	w := &flakyWriter{}
	l := audit.New(w)
	bad := audit.Record{Tool: "x", Arguments: json.RawMessage(`{`)} //nolint:exhaustruct // Logger stamps the rest.
	first := l.Log(bad)
	if !errors.Is(first, audit.ErrLog) {
		t.Fatalf("Log = %v, want ErrLog", first)
	}
	good := audit.Record{Tool: "x", Phase: audit.PhaseAttempt} //nolint:exhaustruct // Logger stamps the rest.
	if err := l.Log(good); !errors.Is(err, first) || !errors.Is(l.Err(), first) || w.n != 0 {
		t.Errorf("Log after a marshal failure = %v, Err = %v, %d writes; want the latched %v and none",
			err, l.Err(), w.n, first)
	}
}

// TestLogger_Closer pins the closer the composition root returns: it always closes, reports the latched audit
// failure ahead of any close error, and the close error otherwise.
func TestLogger_Closer(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("flush failed")
	for _, tc := range []struct {
		name    string
		latched bool
		close   error
		want    string
	}{
		{"clean", false, nil, ""},
		{"close error only", false, closeErr, "flush failed"},
		{"latched", true, nil, "audit: log write failed: write: disk full"},
		{"latched beats the close error", true, closeErr, "audit: log write failed: write: disk full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &flakyWriter{}
			if tc.latched {
				w.failOn = 1
			}
			l := audit.New(w)
			_ = l.Log(audit.Record{Tool: "x"}) //nolint:exhaustruct // Logger stamps the rest.
			closed := false
			err := l.Closer(func() error { closed = true; return tc.close })()
			got := ""
			if err != nil {
				got = err.Error()
			}
			if !closed || got != tc.want {
				t.Errorf("closer = %q (closed %v), want %q", got, closed, tc.want)
			}
		})
	}
}

// TestLogger_CloserWaitsForAHeldRecord pins that the closer waits for a record still to be written before it
// closes, so a late write lands in the log and a late write that fails is reported.
func TestLogger_CloserWaitsForAHeldRecord(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		failOn int
		want   string
	}{
		{"the late write succeeds", 0, ""},
		{"the late write fails", 1, "audit: log write failed: write: disk full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &flakyWriter{failOn: tc.failOn}
			// The bound is far longer than the late write takes, so the closer can only return through the release.
			l := audit.New(w, audit.WithDrain(time.Minute))
			release := l.Hold()
			var closedAfter int
			go func() {
				time.Sleep(20 * time.Millisecond)
				_ = l.Log(audit.Record{Tool: "late"}) //nolint:exhaustruct // Logger stamps the rest.
				release()
			}()
			err := l.Closer(func() error { closedAfter = w.n; return nil })()
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tc.want || closedAfter != w.n {
				t.Errorf("closer = %q, closed after %d of %d writes; want %q after the late one", got, closedAfter,
					w.n, tc.want)
			}
		})
	}
}

// TestLogger_CloserReportsARecordStillHeldAtTheBound pins the fail-closed end of the wait: a record still held when
// the bound passes is reported as missing, after the writer is closed, and a release called twice counts once.
func TestLogger_CloserReportsARecordStillHeldAtTheBound(t *testing.T) {
	t.Parallel()

	l := audit.New(&flakyWriter{}, audit.WithDrain(10*time.Millisecond))
	released := l.Hold()
	released()
	released()
	_ = l.Hold()
	closed := false
	err := l.Closer(func() error { closed = true; return nil })()
	if !errors.Is(err, audit.ErrLog) || !closed ||
		err.Error() != "audit: log write failed: 1 held records were still pending after 10ms" {
		t.Errorf("closer = %v (closed %v), want 1 pending record reported", err, closed)
	}
}

// TestLogger_CloserWithNothingHeldDoesNotWait pins that a run with no record in flight closes at once, whatever
// the bound.
func TestLogger_CloserWithNothingHeldDoesNotWait(t *testing.T) {
	t.Parallel()

	l := audit.New(&flakyWriter{}, audit.WithDrain(time.Hour))
	l.Hold()()
	start := time.Now()
	if err := l.Closer(func() error { return nil })(); err != nil || time.Since(start) > time.Minute {
		t.Errorf("closer = %v after %s", err, time.Since(start))
	}
}
