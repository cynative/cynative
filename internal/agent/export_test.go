package agent

import (
	"context"
	"io"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

// newAgent builds an Agent via New, failing the test on a construction error, so
// callers keep no outer err in scope (avoiding shadowing of Run's error).
func newAgent(t *testing.T, cfg Config) *Agent {
	t.Helper()

	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return a
}

// withSystemPrompt overrides the assembled system prompt; a test-only Option
// proving New applies its options after construction.
func withSystemPrompt(s string) Option {
	return func(a *Agent) { a.systemPrompt = s }
}

// newTestAgent builds a minimal Agent for loop/tool tests: the given model and a
// pre-indexed toolset, with a no-op renderer.
func newTestAgent(model schema.ChatModel, byName map[string]schema.InvokableTool) *Agent {
	infos := make([]*schema.ToolInfo, 0, len(byName))
	for _, t := range byName {
		info, _ := t.Info(context.Background())
		infos = append(infos, info)
	}

	return &Agent{ //nolint:exhaustruct // loop/tool tests only need model/tools/renderer/style
		model:    model,
		tools:    toolset{tools: byName, infos: infos},
		renderer: func(*schema.Message, string, io.Writer) {},
		style:    "notty",
	}
}

// WrapUntrustedForTest exposes wrapUntrusted to the external test package.
func WrapUntrustedForTest(toolName, content string) string {
	return wrapUntrusted(toolName, content)
}

// WithNewID overrides the ID generator so tests get deterministic
// session/run/call IDs.
func WithNewID(fn func() string) Option {
	return func(a *Agent) { a.newID = fn }
}
