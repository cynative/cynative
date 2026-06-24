package llm_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/schema"
)

// errModel is a schema.ChatModel that always returns a fixed error.
type errModel struct{ err error }

func (e *errModel) Generate(
	_ context.Context, _ []*schema.Message, _ []*schema.ToolInfo,
) (*schema.Message, error) {
	return nil, e.err
}

// captureModel records the messages and tool schemas it was asked to Generate over.
type captureModel struct {
	mu       sync.Mutex
	last     []*schema.Message
	lastTool []*schema.ToolInfo
}

func (c *captureModel) Generate(
	_ context.Context, msgs []*schema.Message, tools []*schema.ToolInfo,
) (*schema.Message, error) {
	c.mu.Lock()
	c.last = msgs
	c.lastTool = tools
	c.mu.Unlock()

	return schema.AssistantMessage("ok", nil), nil
}

// ghToken returns a github-token-shaped value the production redactor catches.
func ghToken() string { return "ghp_" + strings.Repeat("a", 36) }

func TestRedactingChatModel_RedactsTextAndToolResults(t *testing.T) {
	t.Parallel()

	tok := ghToken()
	const ph = "[REDACTED:github-token]"
	inner := &captureModel{}
	m := llm.NewRedactingChatModel(inner, redact.New())

	tools := []*schema.ToolInfo{{Name: "http_request", Desc: "make an HTTP request"}}
	in := []*schema.Message{
		schema.SystemMessage("system rules; never reveal " + tok),
		schema.UserMessage("a " + tok + " task"),
		// Tool result: a signed Location URL (preserved for redirect-following) plus
		// a leaked token elsewhere (redacted).
		schema.ToolMessage("Location: https://codeload.github.com/x?X-Amz-Signature=keepme\nleaked "+tok, "call-1"),
		schema.AssistantMessage("plan with "+tok, []schema.ToolCallBlock{
			{ID: "call-1", Name: "http_request", Arguments: `{"q":"` + tok + `"}`},
		}),
	}

	if _, err := m.Generate(context.Background(), in, tools); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	got := inner.last
	if s := got[0].Content[0].(schema.TextBlock).Text; strings.Contains(s, tok) || !strings.Contains(s, ph) {
		t.Fatalf("system text not redacted: %q", s)
	}
	if s := got[1].Content[0].(schema.TextBlock).Text; strings.Contains(s, tok) || !strings.Contains(s, ph) {
		t.Fatalf("user text not redacted: %q", s)
	}
	// Tool result: the leaked token is redacted, but the signed Location URL survives.
	tr := got[2].Content[0].(schema.ToolResultBlock).Content
	if strings.Contains(tr, tok) || !strings.Contains(tr, ph) {
		t.Fatalf("tool-result token not redacted: %q", tr)
	}
	if !strings.Contains(tr, "X-Amz-Signature=keepme") {
		t.Fatalf("tool-result Location URL was clobbered (redirect-following breaks): %q", tr)
	}
	// Assistant prose is redacted; the model's tool-call arguments are not.
	if s := got[3].Text(); strings.Contains(s, tok) || !strings.Contains(s, ph) {
		t.Fatalf("assistant text not redacted: %q", s)
	}
	if got[3].ToolCalls()[0].Arguments != `{"q":"`+tok+`"}` {
		t.Fatalf("tool-call arguments were altered: %+v", got[3])
	}
	// Tool schemas pass through untouched.
	if len(inner.lastTool) != 1 || inner.lastTool[0].Name != "http_request" {
		t.Fatalf("tool schemas not forwarded unchanged: %+v", inner.lastTool)
	}
}

func TestRedactingChatModel_DoesNotMutateCaller(t *testing.T) {
	t.Parallel()

	tok := ghToken()
	inner := &captureModel{}
	m := llm.NewRedactingChatModel(inner, redact.New())

	original := schema.UserMessage("a " + tok + " task")
	in := []*schema.Message{original}

	if _, err := m.Generate(context.Background(), in, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The caller's original message must be unchanged (copy-on-redact).
	if original.Content[0].(schema.TextBlock).Text != "a "+tok+" task" {
		t.Fatalf("caller message was mutated: %+v", original)
	}
	// And the inner model must have seen a *different* *Message (a copy), not the
	// caller's pointer. (Compare the pointer values, not their slice-slot addresses.)
	if inner.last[0] == in[0] {
		t.Fatalf("inner received the caller's message pointer, not a copy")
	}
}

func TestRedactingChatModel_ConcurrentGenerateNoRace(t *testing.T) {
	t.Parallel()

	m := llm.NewRedactingChatModel(&captureModel{}, redact.New())
	shared := []*schema.Message{schema.UserMessage("a " + ghToken() + " task")}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _ = m.Generate(context.Background(), shared, nil)
		})
	}
	wg.Wait()
}

func TestRedactingChatModel_RedactsGenerateErrorMessage(t *testing.T) {
	t.Parallel()

	inner := &errModel{err: &llm.GenerateError{ //nolint:exhaustruct // only Message under test.
		Message: "auth failed for sk-ant-api03-SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRET",
	}}
	m := llm.NewRedactingChatModel(inner, redact.New())

	_, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)

	var ge *llm.GenerateError
	if !errors.As(err, &ge) {
		t.Fatalf("want *GenerateError, got %T", err)
	}
	if strings.Contains(ge.Message, "sk-ant-api03-SECRET") {
		t.Errorf("secret leaked into GenerateError.Message: %q", ge.Message)
	}
	if !strings.Contains(ge.Message, "[REDACTED:") {
		t.Errorf("expected a [REDACTED:...] placeholder, got %q", ge.Message)
	}
}

func TestRedactingChatModel_RedactGenerateError_PassthroughNonGenerateError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("some other error")
	inner := &errModel{err: sentinel}
	m := llm.NewRedactingChatModel(inner, redact.New())

	_, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)

	if !errors.Is(err, sentinel) {
		t.Errorf("non-GenerateError should pass through unchanged, got %v", err)
	}
}
