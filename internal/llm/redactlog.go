package llm

import (
	"fmt"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// redactingLogger wraps the logger handed to Bifrost so every line is redacted
// before it is printed. Bifrost logs upstream error text, which can echo request
// content, including reasoning replayed unredacted to the backend that issued it.
// Each line is formatted here, redacted, and passed on as the argument of "%s",
// so a "%" in the redacted text is printed, never read as a verb.
type redactingLogger struct {
	inner  bschemas.Logger
	redact func(string) string
}

var _ bschemas.Logger = redactingLogger{}

// line formats one log call and redacts the result.
func (l redactingLogger) line(msg string, args []any) string {
	return l.redact(fmt.Sprintf(msg, args...))
}

// Debug logs a redacted debug line.
func (l redactingLogger) Debug(msg string, args ...any) { l.inner.Debug("%s", l.line(msg, args)) }

// Info logs a redacted info line.
func (l redactingLogger) Info(msg string, args ...any) { l.inner.Info("%s", l.line(msg, args)) }

// Warn logs a redacted warning line.
func (l redactingLogger) Warn(msg string, args ...any) { l.inner.Warn("%s", l.line(msg, args)) }

// Error logs a redacted error line.
func (l redactingLogger) Error(msg string, args ...any) { l.inner.Error("%s", l.line(msg, args)) }

// Fatal logs a redacted fatal line.
func (l redactingLogger) Fatal(msg string, args ...any) { l.inner.Fatal("%s", l.line(msg, args)) }

// SetLevel forwards the level to the inner logger.
func (l redactingLogger) SetLevel(level bschemas.LogLevel) { l.inner.SetLevel(level) }

// SetOutputType forwards the output type to the inner logger.
func (l redactingLogger) SetOutputType(t bschemas.LoggerOutputType) { l.inner.SetOutputType(t) }

// LogHTTPRequest drops structured HTTP access logs. Their fields bypass the
// line redaction above, and no chat path in Bifrost core emits them.
func (redactingLogger) LogHTTPRequest(bschemas.LogLevel, string) bschemas.LogEventBuilder {
	return bschemas.NoopLogEvent
}
