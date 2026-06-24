package llm

import (
	"context"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// WithBackend injects a ready BifrostBackend test double, replacing the default
// shell backend factory so NewBifrostChatModel never calls the real SDK.
func WithBackend(b BifrostBackend) ChatModelOption {
	return func(m *BifrostChatModel) {
		m.newBackend = func(context.Context, bschemas.BifrostConfig) (BifrostBackend, error) { return b, nil }
	}
}

// WithBackendFactory injects a backend constructor, covering the init-error path.
func WithBackendFactory(
	f func(context.Context, bschemas.BifrostConfig) (BifrostBackend, error),
) ChatModelOption {
	return func(m *BifrostChatModel) { m.newBackend = f }
}
