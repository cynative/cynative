package schema

import "context"

// ChatModel is the provider-agnostic chat interface the agent loop drives. The
// llm package's BifrostChatModel is the production implementation; tests inject a
// fake. Tools are bound per call via the tools argument (nil for a tool-less
// call). Implementations must be safe for concurrent use: the agent's verifier
// panel issues Generate calls from multiple goroutines.
//
// Generate returns a Generation rather than a bare Message so the stop reason
// stays correlated with the response it describes, which a construction-time
// callback could not do under that concurrency guarantee.
type ChatModel interface {
	Generate(ctx context.Context, msgs []*Message, tools []*ToolInfo) (Generation, error)
}
