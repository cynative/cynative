package llm

import (
	"bytes"
	"strings"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

func TestRedactingLogger_WritesRedactedJSONLinesFromWarnUp(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	l := redactingLogger{
		out:    &out,
		redact: func(s string) string { return strings.ReplaceAll(s, "SECRET", "[REDACTED]") },
	}

	l.Debug("d %s", "SECRET")
	l.Info("i %s", "SECRET")
	l.Warn("upstream said: %s", "SECRET 100% sure\x1b[31m")
	l.Error("e %d %s", 7, "SECRET")
	l.Fatal("f SECRET")

	// Debug and info are dropped, the "%" in an argument prints literally, and the
	// escape character reaches the writer JSON-escaped.
	want := `{"level":"warn","message":"upstream said: [REDACTED] 100% sure\u001b[31m"}
{"level":"error","message":"e 7 [REDACTED]"}
{"level":"fatal","message":"f [REDACTED]"}
`
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRedactingLogger_IgnoresSettingsAndDropsHTTPLogs(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	l := redactingLogger{out: &out, redact: func(s string) string { return s }}
	l.SetLevel(bschemas.LogLevelDebug)
	l.SetOutputType(bschemas.LoggerOutputTypePretty)
	l.Info("still dropped")
	if b := l.LogHTTPRequest(bschemas.LogLevelInfo, "SECRET"); b != bschemas.NoopLogEvent {
		t.Errorf("LogHTTPRequest builder = %v, want the no-op builder", b)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing written", out.String())
	}
}
