package llm

import "github.com/cynative/cynative/internal/schema"

// WithUsageRecorder installs a sink invoked with the token usage of every
// successful Generate. It is the package's one production-facing ChatModelOption
// (the cli composition root wires it; the other options are test-only). The
// default sink is a no-op.
func WithUsageRecorder(sink func(schema.Usage)) ChatModelOption {
	return func(m *BifrostChatModel) {
		if sink != nil {
			m.recordUsage = sink
		}
	}
}
