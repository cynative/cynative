package llm

import (
	"encoding/json"
	"fmt"
	"io"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// redactingLogger is the logger handed to Bifrost. It redacts every line and
// writes it to out, stderr in production, so SDK diagnostics never mix with the
// answer on stdout (Bifrost's default logger prints warnings to stdout). Bifrost
// logs upstream error text, which can echo request content, including reasoning
// replayed unredacted to the backend that issued it. Each line is written as one
// JSON object, so a control character in upstream text reaches the terminal
// escaped, never raw. Lines below warn are dropped, the level cynative ran
// Bifrost's default logger at.
type redactingLogger struct {
	out    io.Writer
	redact func(string) string
}

var _ bschemas.Logger = redactingLogger{}

// logLine is the JSON shape of one written line.
type logLine struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// write formats one log call, redacts it and writes it at level.
func (l redactingLogger) write(level, msg string, args []any) {
	// Encoding a struct of two strings cannot fail, and a failed write to
	// stderr has nowhere better to be reported, so the error is dropped.
	_ = json.NewEncoder(l.out).Encode(logLine{Level: level, Message: l.redact(fmt.Sprintf(msg, args...))})
}

// Debug drops a debug line.
func (redactingLogger) Debug(string, ...any) {}

// Info drops an info line.
func (redactingLogger) Info(string, ...any) {}

// Warn writes a redacted warning line.
func (l redactingLogger) Warn(msg string, args ...any) { l.write("warn", msg, args) }

// Error writes a redacted error line.
func (l redactingLogger) Error(msg string, args ...any) { l.write("error", msg, args) }

// Fatal writes a redacted fatal line. It does not exit: Bifrost core never
// calls it, and ending the process is the cli's decision.
func (l redactingLogger) Fatal(msg string, args ...any) { l.write("fatal", msg, args) }

// SetLevel is ignored; the level is fixed at warn. Bifrost core never calls it.
func (redactingLogger) SetLevel(bschemas.LogLevel) {}

// SetOutputType is ignored; lines are always JSON. Bifrost core never calls it.
func (redactingLogger) SetOutputType(bschemas.LoggerOutputType) {}

// LogHTTPRequest drops structured HTTP access logs. Their fields bypass the
// line redaction above, and no chat path in Bifrost core emits them.
func (redactingLogger) LogHTTPRequest(bschemas.LogLevel, string) bschemas.LogEventBuilder {
	return bschemas.NoopLogEvent
}
