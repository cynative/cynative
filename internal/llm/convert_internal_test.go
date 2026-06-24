package llm

import (
	"slices"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/schema"
)

func TestUsageFromBifrost_Nil(t *testing.T) {
	t.Parallel()

	if got := usageFromBifrost(nil); got != (schema.Usage{}) {
		t.Errorf("usageFromBifrost(nil) = %+v, want zero", got)
	}
}

func TestUsageFromBifrost_TokensAndCache(t *testing.T) {
	t.Parallel()

	in := &bschemas.BifrostLLMUsage{ //nolint:exhaustruct // only fields under test.
		PromptTokens:     100,
		CompletionTokens: 20,
		TotalTokens:      120,
		PromptTokensDetails: &bschemas.ChatPromptTokensDetails{ //nolint:exhaustruct // only cache fields.
			CachedReadTokens:  80,
			CachedWriteTokens: 5,
		},
	}
	got := usageFromBifrost(in)
	if got.PromptTokens != 100 || got.CompletionTokens != 20 || got.TotalTokens != 120 {
		t.Errorf("tokens = %+v", got)
	}
	if got.CachedReadTokens != 80 || got.CachedWriteTokens != 5 {
		t.Errorf("cache = %+v", got)
	}
}

func TestUsageFromBifrost_NilDetails(t *testing.T) {
	t.Parallel()

	in := &bschemas.BifrostLLMUsage{ //nolint:exhaustruct // PromptTokensDetails nil on purpose.
		PromptTokens: 10,
		TotalTokens:  10,
	}
	got := usageFromBifrost(in)
	if got.CachedReadTokens != 0 || got.CachedWriteTokens != 0 {
		t.Errorf("cache = %+v, want zero when details nil", got)
	}
}

func TestMarkMessage_WrapsContentInCachedBlock(t *testing.T) {
	t.Parallel()

	text := "hello"
	m := bschemas.ChatMessage{ //nolint:exhaustruct // only Role/Content set
		Role:    bschemas.ChatMessageRoleUser,
		Content: &bschemas.ChatMessageContent{ContentStr: &text}, //nolint:exhaustruct // only ContentStr
	}

	markMessage(&m)

	if m.Content.ContentStr != nil {
		t.Errorf("ContentStr = %v, want nil after marking", m.Content.ContentStr)
	}
	if len(m.Content.ContentBlocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(m.Content.ContentBlocks))
	}
	block := m.Content.ContentBlocks[0]
	if block.Type != bschemas.ChatContentBlockTypeText {
		t.Errorf("block type = %q, want text", block.Type)
	}
	if block.Text == nil || *block.Text != "hello" {
		t.Errorf("block text not preserved: %v", block.Text)
	}
	if block.CacheControl == nil || block.CacheControl.Type != bschemas.CacheControlTypeEphemeral {
		t.Errorf("cache control = %+v, want ephemeral", block.CacheControl)
	}
}

func TestCacheMarkIndices(t *testing.T) {
	t.Parallel()

	str := func(s string) *string { return &s }
	msg := func(role bschemas.ChatMessageRole, s string) bschemas.ChatMessage {
		return bschemas.ChatMessage{ //nolint:exhaustruct // only Role/Content set
			Role:    role,
			Content: &bschemas.ChatMessageContent{ContentStr: str(s)}, //nolint:exhaustruct // only ContentStr
		}
	}
	user := func(s string) bschemas.ChatMessage { return msg(bschemas.ChatMessageRoleUser, s) }
	system := func(s string) bschemas.ChatMessage { return msg(bschemas.ChatMessageRoleSystem, s) }
	toolCallOnly := bschemas.ChatMessage{
		Role: bschemas.ChatMessageRoleAssistant,
	} //nolint:exhaustruct // no text content

	tests := []struct {
		name string
		in   []bschemas.ChatMessage
		want []int
	}{
		{name: "empty", in: nil, want: []int{}},
		{name: "system only", in: []bschemas.ChatMessage{system("s")}, want: []int{0}},
		{name: "system and user", in: []bschemas.ChatMessage{system("s"), user("u")}, want: []int{0, 1}},
		{name: "user only", in: []bschemas.ChatMessage{user("u")}, want: []int{0}},
		{name: "last two of three", in: []bschemas.ChatMessage{user("a"), user("b"), user("c")}, want: []int{1, 2}},
		{
			name: "system plus last two",
			in:   []bschemas.ChatMessage{system("s"), user("a"), user("b")},
			want: []int{0, 1, 2},
		},
		{name: "skips textless", in: []bschemas.ChatMessage{system("s"), toolCallOnly, user("r")}, want: []int{0, 2}},
		{
			name: "only last system",
			in:   []bschemas.ChatMessage{system("s1"), system("s2"), user("u")},
			want: []int{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cacheMarkIndices(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Errorf("indices = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyCacheBreakpoints_NilParamsStillMarksMessages(t *testing.T) {
	t.Parallel()

	text := "hi"
	req := &bschemas.BifrostChatRequest{ //nolint:exhaustruct // only Input set
		Input: []bschemas.ChatMessage{{ //nolint:exhaustruct // only Role/Content
			Role:    bschemas.ChatMessageRoleUser,
			Content: &bschemas.ChatMessageContent{ContentStr: &text}, //nolint:exhaustruct // only ContentStr
		}},
	}

	applyCacheBreakpoints(req)

	if req.Params != nil {
		t.Errorf("Params = %+v, want nil (untouched)", req.Params)
	}
	if len(req.Input[0].Content.ContentBlocks) != 1 {
		t.Error("message not marked when Params is nil")
	}
}

func TestApplyCacheBreakpoints_EmptyToolsAndInput(t *testing.T) {
	t.Parallel()

	req := &bschemas.BifrostChatRequest{ //nolint:exhaustruct // Params w/ empty tools
		Input:  []bschemas.ChatMessage{},
		Params: &bschemas.ChatParameters{Tools: []bschemas.ChatTool{}}, //nolint:exhaustruct // only Tools
	}

	applyCacheBreakpoints(req) // Must not panic on empty tools / empty input.

	if len(req.Params.Tools) != 0 {
		t.Errorf("tools = %d, want 0", len(req.Params.Tools))
	}
}

func TestApplyCacheBreakpoints_MarksLastToolOnly(t *testing.T) {
	t.Parallel()

	req := &bschemas.BifrostChatRequest{ //nolint:exhaustruct // only Params set
		Input: []bschemas.ChatMessage{},
		Params: &bschemas.ChatParameters{ //nolint:exhaustruct // only Tools
			Tools: []bschemas.ChatTool{
				{Type: bschemas.ChatToolTypeFunction}, //nolint:exhaustruct // marker test only
				{Type: bschemas.ChatToolTypeFunction}, //nolint:exhaustruct // marker test only
			},
		},
	}

	applyCacheBreakpoints(req)

	if req.Params.Tools[0].CacheControl != nil {
		t.Error("first tool unexpectedly marked")
	}
	last := req.Params.Tools[1].CacheControl
	if last == nil || last.Type != bschemas.CacheControlTypeEphemeral {
		t.Errorf("last tool not ephemeral-marked: %+v", last)
	}
}

// --- New schema* converter tests below. ---

func TestSchemaToBifrostMessages_RolesAndContent(t *testing.T) {
	t.Parallel()

	in := []*schema.Message{
		schema.SystemMessage("sys"),
		schema.UserMessage("hi"),
	}

	out := schemaToBifrostMessages(in)

	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Role != bschemas.ChatMessageRole("system") {
		t.Errorf("role = %q, want system", out[0].Role)
	}
	if out[1].Content == nil || out[1].Content.ContentStr == nil || *out[1].Content.ContentStr != "hi" {
		t.Errorf("content not carried: %+v", out[1].Content)
	}
}

func TestSchemaToBifrostMessages_AssistantToolCalls(t *testing.T) {
	t.Parallel()

	in := []*schema.Message{
		schema.AssistantMessage("", []schema.ToolCallBlock{
			{ID: "call-1", Name: "http_request", Arguments: `{"x":1}`},
		}),
	}

	out := schemaToBifrostMessages(in)

	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].ChatAssistantMessage == nil || len(out[0].ChatAssistantMessage.ToolCalls) != 1 {
		t.Fatalf("tool calls not carried")
	}
	tc := out[0].ChatAssistantMessage.ToolCalls[0]
	if tc.ID == nil || *tc.ID != "call-1" {
		t.Errorf("id = %v, want call-1", tc.ID)
	}
	if tc.Function.Name == nil || *tc.Function.Name != "http_request" {
		t.Errorf("name not carried: %v", tc.Function.Name)
	}
	if tc.Function.Arguments != `{"x":1}` {
		t.Errorf("args = %q", tc.Function.Arguments)
	}
	if tc.Index != 0 {
		t.Errorf("index = %d, want 0", tc.Index)
	}
	if tc.Type == nil || *tc.Type != string(bschemas.ChatToolTypeFunction) {
		t.Errorf("type = %v, want function", tc.Type)
	}
}

func TestSchemaToBifrostMessages_AssistantTextAndToolCalls(t *testing.T) {
	t.Parallel()

	in := []*schema.Message{
		schema.AssistantMessage("thinking", []schema.ToolCallBlock{
			{ID: "c1", Name: "tool", Arguments: `{}`},
		}),
	}

	out := schemaToBifrostMessages(in)

	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Content == nil || out[0].Content.ContentStr == nil || *out[0].Content.ContentStr != "thinking" {
		t.Errorf("text content not carried")
	}
	if out[0].ChatAssistantMessage == nil || len(out[0].ChatAssistantMessage.ToolCalls) != 1 {
		t.Errorf("tool calls not carried")
	}
}

func TestSchemaToBifrostMessages_ToolResult(t *testing.T) {
	t.Parallel()

	in := []*schema.Message{
		schema.ToolMessage("result", "call-1"),
	}

	out := schemaToBifrostMessages(in)

	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Role != bschemas.ChatMessageRole("tool") {
		t.Errorf("role = %q, want tool", out[0].Role)
	}
	if out[0].ChatToolMessage == nil || out[0].ChatToolMessage.ToolCallID == nil ||
		*out[0].ChatToolMessage.ToolCallID != "call-1" {
		t.Errorf("tool call id not carried")
	}
	// Content should be set via m.Text() → "result".
	if out[0].Content == nil || out[0].Content.ContentStr == nil || *out[0].Content.ContentStr != "result" {
		t.Errorf("tool result content not carried: %+v", out[0].Content)
	}
}

func TestSchemaToBifrostMessages_EmptyTextOmitted(t *testing.T) {
	t.Parallel()

	in := []*schema.Message{
		schema.AssistantMessage("", []schema.ToolCallBlock{
			{ID: "c", Name: "n", Arguments: `{}`},
		}),
	}

	out := schemaToBifrostMessages(in)

	if out[0].Content != nil {
		t.Errorf("Content = %+v, want nil when text empty", out[0].Content)
	}
}

func TestSchemaToBifrostToolCalls_IndexAndType(t *testing.T) {
	t.Parallel()

	in := []schema.ToolCallBlock{
		{ID: "c1", Name: "tool1", Arguments: `{"a":1}`},
		{ID: "c2", Name: "tool2", Arguments: `{"b":2}`},
	}

	out := schemaToBifrostToolCalls(in)

	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Index != 0 {
		t.Errorf("first index = %d, want 0", out[0].Index)
	}
	if out[1].Index != 1 {
		t.Errorf("second index = %d, want 1", out[1].Index)
	}
	if out[0].Type == nil || *out[0].Type != string(bschemas.ChatToolTypeFunction) {
		t.Errorf("type not set: %v", out[0].Type)
	}
}

func TestSchemaFromBifrostMessage_ContentAndToolCalls(t *testing.T) {
	t.Parallel()

	content := "answer"
	id := "call-9"
	name := "http_request"
	bm := bschemas.ChatMessage{ //nolint:exhaustruct // only fields under test
		Role:    bschemas.ChatMessageRole("assistant"),
		Content: &bschemas.ChatMessageContent{ContentStr: &content}, //nolint:exhaustruct // only ContentStr
		ChatAssistantMessage: &bschemas.ChatAssistantMessage{ //nolint:exhaustruct // only ToolCalls
			ToolCalls: []bschemas.ChatAssistantMessageToolCall{
				{ //nolint:exhaustruct // only fields under test
					ID: &id,
					Function: bschemas.ChatAssistantMessageToolCallFunction{
						Name:      &name,
						Arguments: `{}`,
					},
				},
			},
		},
	}

	out := schemaFromBifrostMessage(bm)

	if out.Role != schema.Assistant {
		t.Errorf("role = %q", out.Role)
	}
	if out.Text() != "answer" {
		t.Errorf("text = %q, want answer", out.Text())
	}
	calls := out.ToolCalls()
	if len(calls) != 1 || calls[0].ID != "call-9" || calls[0].Name != "http_request" {
		t.Errorf("tool calls not carried: %+v", calls)
	}
}

func TestSchemaFromBifrostMessage_EmptyContent(t *testing.T) {
	t.Parallel()

	bm := bschemas.ChatMessage{ //nolint:exhaustruct // only Role set
		Role: bschemas.ChatMessageRoleAssistant,
	}

	out := schemaFromBifrostMessage(bm)

	if out.Text() != "" {
		t.Errorf("text = %q, want empty", out.Text())
	}
	if len(out.Content) != 0 {
		t.Errorf("content blocks = %d, want 0", len(out.Content))
	}
}

func TestSchemaFromBifrostMessage_NilToolCallIDAndName(t *testing.T) {
	t.Parallel()

	bm := bschemas.ChatMessage{ //nolint:exhaustruct // only fields under test
		Role: bschemas.ChatMessageRoleAssistant,
		ChatAssistantMessage: &bschemas.ChatAssistantMessage{ //nolint:exhaustruct // only ToolCalls
			ToolCalls: []bschemas.ChatAssistantMessageToolCall{
				{ //nolint:exhaustruct // ID and Name intentionally nil
					Function: bschemas.ChatAssistantMessageToolCallFunction{Arguments: `{"x":1}`},
				},
			},
		},
	}

	out := schemaFromBifrostMessage(bm)

	calls := out.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("tool calls = %d, want 1", len(calls))
	}
	if calls[0].ID != "" {
		t.Errorf("id = %q, want empty", calls[0].ID)
	}
	if calls[0].Name != "" {
		t.Errorf("name = %q, want empty", calls[0].Name)
	}
	if calls[0].Arguments != `{"x":1}` {
		t.Errorf("args = %q", calls[0].Arguments)
	}
}

func TestSchemaToToolParameters_NilSchema(t *testing.T) {
	t.Parallel()

	if schemaToToolParameters(nil) != nil {
		t.Errorf("expected nil for nil schema")
	}
}

func TestSchemaToolsToParams_BuildsFunctionTool(t *testing.T) {
	t.Parallel()

	s, err := schema.ReflectParams[struct {
		URL string `json:"url" jsonschema:"description=the url,required"`
	}]()
	if err != nil {
		t.Fatalf("ReflectParams: %v", err)
	}

	infos := []*schema.ToolInfo{{
		Name:   "http_request",
		Desc:   "Make a request",
		Params: s,
	}}

	params := schemaToolsToParams(infos)

	if params == nil || len(params.Tools) != 1 {
		t.Fatalf("expected 1 tool")
	}
	fn := params.Tools[0].Function
	if fn == nil || fn.Name != "http_request" {
		t.Fatalf("function name not carried")
	}
	if fn.Description == nil || *fn.Description != "Make a request" {
		t.Errorf("description not carried: %v", fn.Description)
	}
	if fn.Parameters == nil {
		t.Errorf("parameters not carried")
	}
}

func TestSchemaToolsToParams_Empty(t *testing.T) {
	t.Parallel()

	if schemaToolsToParams(nil) != nil {
		t.Errorf("expected nil for no tools")
	}
}
