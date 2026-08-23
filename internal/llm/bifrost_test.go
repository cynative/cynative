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

// assistantRespReason is assistantResp with a finish reason on the choice. A nil
// reason models the anthropic / cohere / openai-passthrough spelling of "not
// reported"; gemini and bedrock instead send a pointer to "".
func assistantRespReason(content string, reason *string) *schemas.BifrostChatResponse {
	resp := assistantResp(content)
	resp.Choices[0].FinishReason = reason

	return resp
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

// TestAssistantRespReason is a compile-time smoke test ensuring
// assistantRespReason lands the finish reason on the choice, matching this
// file's existing convention of smoke-testing its own helpers.
func TestAssistantRespReason(t *testing.T) {
	t.Parallel()

	reason := "length"
	resp := assistantRespReason("hello", &reason)
	if resp.Choices[0].FinishReason == nil || *resp.Choices[0].FinishReason != "length" {
		t.Errorf("FinishReason = %v, want \"length\"", resp.Choices[0].FinishReason)
	}
}
