package llm_test

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// assistantResp builds a BifrostChatResponse with a simple assistant text message.
func assistantResp(content string) *schemas.BifrostChatResponse {
	msg := schemas.ChatMessage{ //nolint:exhaustruct // only fields under test populated
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: new(content)},
	}
	return &schemas.BifrostChatResponse{ //nolint:exhaustruct // only Choices needed
		Choices: []schemas.BifrostResponseChoice{
			{ //nolint:exhaustruct // only ChatNonStreamResponseChoice needed
				ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{
					Message: &msg,
				},
			},
		},
	}
}

// TestAssistantResp is a compile-time smoke test ensuring assistantResp returns
// a well-formed response. The real behavioural coverage lives in chatmodel_test.go.
func TestAssistantResp(t *testing.T) {
	t.Parallel()

	resp := assistantResp("hello")
	if len(resp.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(resp.Choices))
	}
	choice := resp.Choices[0]
	if choice.ChatNonStreamResponseChoice == nil || choice.ChatNonStreamResponseChoice.Message == nil {
		t.Fatal("message is nil")
	}
	msg := choice.ChatNonStreamResponseChoice.Message
	if msg.Content == nil || msg.Content.ContentStr == nil || *msg.Content.ContentStr != "hello" {
		t.Errorf("content = %v, want hello", msg.Content)
	}
}
