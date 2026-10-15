package llm

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// recordLogger is a bschemas.Logger that records each call's level, format and args.
type recordLogger struct {
	lines  []string
	level  bschemas.LogLevel
	output bschemas.LoggerOutputType
}

func (r *recordLogger) rec(lvl, msg string, args ...any) {
	r.lines = append(r.lines, lvl+"|"+msg+"|"+fmt.Sprint(args...))
}

func (r *recordLogger) Debug(m string, a ...any)                  { r.rec("debug", m, a...) }
func (r *recordLogger) Info(m string, a ...any)                   { r.rec("info", m, a...) }
func (r *recordLogger) Warn(m string, a ...any)                   { r.rec("warn", m, a...) }
func (r *recordLogger) Error(m string, a ...any)                  { r.rec("error", m, a...) }
func (r *recordLogger) Fatal(m string, a ...any)                  { r.rec("fatal", m, a...) }
func (r *recordLogger) SetLevel(l bschemas.LogLevel)              { r.level = l }
func (r *recordLogger) SetOutputType(o bschemas.LoggerOutputType) { r.output = o }

func (r *recordLogger) LogHTTPRequest(bschemas.LogLevel, string) bschemas.LogEventBuilder {
	r.lines = append(r.lines, "http")

	return bschemas.NoopLogEvent
}

func TestRedactingLogger_RedactsEveryLevelAndKeepsPercentLiteral(t *testing.T) {
	t.Parallel()

	inner := &recordLogger{}
	l := redactingLogger{
		inner:  inner,
		redact: func(s string) string { return strings.ReplaceAll(s, "SECRET", "[REDACTED]") },
	}

	l.Debug("d %s", "SECRET")
	l.Info("i %s", "SECRET")
	l.Warn("upstream said: %s", "SECRET 100% sure")
	l.Error("e %d %s", 7, "SECRET")
	l.Fatal("f SECRET")

	want := []string{
		"debug|%s|d [REDACTED]",
		"info|%s|i [REDACTED]",
		"warn|%s|upstream said: [REDACTED] 100% sure",
		"error|%s|e 7 [REDACTED]",
		"fatal|%s|f [REDACTED]",
	}
	// The "%" reaches the inner logger as the argument of "%s", so it prints literally.
	if !slices.Equal(inner.lines, want) {
		t.Errorf("lines = %q, want %q", inner.lines, want)
	}
}

func TestRedactingLogger_ForwardsSettingsAndDropsHTTPLogs(t *testing.T) {
	t.Parallel()

	inner := &recordLogger{}
	l := redactingLogger{inner: inner, redact: func(s string) string { return s }}
	l.SetLevel(bschemas.LogLevelError)
	l.SetOutputType(bschemas.LoggerOutputTypeJSON)
	if b := l.LogHTTPRequest(bschemas.LogLevelInfo, "SECRET"); b != bschemas.NoopLogEvent {
		t.Errorf("LogHTTPRequest builder = %v, want the no-op builder", b)
	}
	if inner.level != bschemas.LogLevelError || inner.output != bschemas.LoggerOutputTypeJSON {
		t.Errorf("settings = %v/%v, want them forwarded", inner.level, inner.output)
	}
	if len(inner.lines) != 0 {
		t.Errorf("lines = %q, want the HTTP log dropped before the inner logger", inner.lines)
	}
}
