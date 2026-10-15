package llm

import "github.com/cynative/cynative/internal/schema"

// WithUsageRecorder installs a sink invoked with the token usage of every
// successful Generate. The cli composition root wires it. The default sink is a
// no-op.
func WithUsageRecorder(sink func(schema.Usage)) ChatModelOption {
	return func(m *BifrostChatModel) {
		if sink != nil {
			m.recordUsage = sink
		}
	}
}

// WithLogRedactor redacts every line Bifrost logs. The cli composition root
// passes the same redaction rules the chat model's requests go through. A nil
// func is ignored, leaving lines unchanged.
func WithLogRedactor(redact func(string) string) ChatModelOption {
	return func(m *BifrostChatModel) {
		if redact != nil {
			m.redactLog = redact
		}
	}
}
