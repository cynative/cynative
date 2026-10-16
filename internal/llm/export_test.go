package llm

import (
	"context"
	"io"

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

// WithLogOutput replaces stderr as the writer Bifrost's log lines go to.
func WithLogOutput(w io.Writer) ChatModelOption {
	return func(m *BifrostChatModel) { m.logOut = w }
}
