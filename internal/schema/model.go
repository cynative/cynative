package schema

import "context"

// ChatModel is the provider-agnostic chat interface the agent loop drives. The
// llm package's BifrostChatModel is the production implementation; tests inject a
// fake. Tools are bound per call via the tools argument (nil for a tool-less
// call). Implementations must be safe for concurrent use: the agent's verifier
// panel issues Generate calls from multiple goroutines.
type ChatModel interface {
	Generate(ctx context.Context, msgs []*Message, tools []*ToolInfo) (*Message, error)
}
