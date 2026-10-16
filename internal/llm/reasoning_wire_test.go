package llm_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/providers/openai"
	bschemas "github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/schema"
)

// replayRequests runs one Generate that returns reply, then a second Generate
// over [system, user, reply, tool result] plus any trailing messages, and
// returns the Bifrost request of the second call.
func replayRequest(
	t *testing.T, reply *bschemas.BifrostChatResponse, trailing ...*schema.Message,
) *bschemas.BifrostChatRequest {
	t.Helper()

	mock := &llm.BifrostBackendMock{
		ChatCompletionRequestFunc: func(
			*bschemas.BifrostContext, *bschemas.BifrostChatRequest,
		) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return reply, nil
		},
		ShutdownFunc: func() {},
	}
	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}
	turn := []*schema.Message{schema.SystemMessage("sys"), schema.UserMessage("go")}
	gen, err := m.Generate(context.Background(), turn, nil)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	callID := gen.Message.ToolCalls()[0].ID
	turn = append(turn, gen.Message, schema.ToolMessage("result", callID))
	turn = append(turn, trailing...)
	if _, err = m.Generate(context.Background(), turn, nil); err != nil {
		t.Fatalf("Generate 2: %v", err)
	}

	return mock.ChatCompletionRequestCalls()[1].Req
}

// decodeOpenAIMessage decodes one OpenAI-wire assistant message through
// Bifrost's own type, the way a provider response reaches the adapter.
func decodeOpenAIMessage(t *testing.T, raw string) *bschemas.ChatMessage {
	t.Helper()

	var msg bschemas.ChatMessage
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return &msg
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return string(b)
}

func TestReasoningReplay_OpenAIWireIsByteIdentical(t *testing.T) {
	t.Parallel()

	const reasoning = "plan: \"quoted\", back\\slash, café, 日本\nline two"
	msg := decodeOpenAIMessage(t, `{"role":"assistant","content":null,"reasoning_content":`+mustJSON(t, reasoning)+
		`,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"echo","arguments":"{}"}}]}`)

	req := replayRequest(t, messageResp(msg))
	req.Provider = bschemas.OpenAI
	ctx := bschemas.NewBifrostContext(context.Background(), time.Time{})
	body, err := json.Marshal(openai.ToOpenAIChatRequest(ctx, req))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wire struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("decode wire: %v", err)
	}
	var got string
	if err = json.Unmarshal(wire.Messages[2]["reasoning_content"], &got); err != nil {
		t.Fatalf("assistant turn has no reasoning_content: %s", body)
	}
	if got != reasoning {
		t.Errorf("reasoning_content = %q, want %q", got, reasoning)
	}
}

func TestReasoningReplay_AnthropicWireKeepsSignedAndRedactedThinking(t *testing.T) {
	t.Parallel()

	raw := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","stop_reason":"tool_use",` +
		`"content":[{"type":"thinking","thinking":"step one","signature":"SIG-1"},` +
		`{"type":"redacted_thinking","data":"ENC-1"},` +
		`{"type":"tool_use","id":"toolu_1","name":"echo","input":{}}],` +
		`"usage":{"input_tokens":1,"output_tokens":1}}`
	var resp anthropic.AnthropicMessageResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ctx := bschemas.NewBifrostContext(context.Background(), time.Time{})

	req := replayRequest(t, resp.ToBifrostChatResponse(ctx))
	req.Provider = bschemas.Anthropic
	req.Model = "claude-x"
	body, berr := anthropic.BuildAnthropicChatRequestBody(ctx, req,
		anthropic.AnthropicRequestBuildConfig{Provider: bschemas.Anthropic})
	if berr != nil {
		t.Fatalf("build: %v", berr.Error)
	}

	s := string(body)
	think := strings.Index(s, `"type":"thinking"`)
	redacted := strings.Index(s, `"type":"redacted_thinking"`)
	toolUse := strings.Index(s, `"type":"tool_use"`)
	if think < 0 || redacted < 0 || toolUse < 0 {
		t.Fatalf("body lacks a thinking, redacted_thinking or tool_use block: %s", s)
	}
	if think > redacted || redacted > toolUse {
		t.Errorf("want thinking, then redacted_thinking, then tool_use, as the reply ordered them: %s", s)
	}
	for _, want := range []string{`"thinking":"step one"`, `"signature":"SIG-1"`, `"data":"ENC-1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("body lacks %s: %s", want, s)
		}
	}
}

// TestReasoningReplay_SurvivesCacheMarking covers both cache cases: a textless
// tool-call turn (never marked) and a prose-bearing one, which cache marking
// rewrites into a content block. Either way the reasoning goes back unchanged.
func TestReasoningReplay_SurvivesCacheMarking(t *testing.T) {
	t.Parallel()

	const agg = "think\n"
	for name, content := range map[string]string{"textless": "null", "prose": `"working on it"`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			msg := decodeOpenAIMessage(t, `{"role":"assistant","content":`+content+
				`,"reasoning_content":`+mustJSON(t, agg)+
				`,"tool_calls":[{"id":"c1","type":"function","function":{"name":"echo","arguments":"{}"}}]}`)

			req := replayRequest(t, messageResp(msg))
			replayed := req.Input[2]
			am := replayed.ChatAssistantMessage
			if am == nil || am.Reasoning == nil || *am.Reasoning != agg {
				t.Fatalf("replayed assistant = %#v, want the aggregate %q", am, agg)
			}
			if len(am.ReasoningDetails) != 1 || *am.ReasoningDetails[0].Text != agg {
				t.Errorf("replayed details = %#v, want the synthesized text detail unchanged", am.ReasoningDetails)
			}
			if len(am.ToolCalls) != 1 || *am.ToolCalls[0].ID != "c1" {
				t.Errorf("replayed calls = %#v, want call c1", am.ToolCalls)
			}
			marked := replayed.Content != nil && len(replayed.Content.ContentBlocks) == 1 &&
				replayed.Content.ContentBlocks[0].CacheControl != nil
			if wantMarked := name == "prose"; marked != wantMarked {
				t.Errorf("assistant turn marked = %v, want %v", marked, wantMarked)
			}
		})
	}
}
