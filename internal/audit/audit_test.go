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
