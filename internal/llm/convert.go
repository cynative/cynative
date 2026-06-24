package llm

import (
	"encoding/json"
	"slices"

	"github.com/invopop/jsonschema"
	bschemas "github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/schema"
)

// schemaToToolParameters marshals an invopop JSON Schema directly into Bifrost's
// typed tool-function parameters. Returns nil when the schema is absent. The
// marshal/unmarshal round-trip of a *jsonschema.Schema cannot fail, so neither
// error is checked.
func schemaToToolParameters(s *jsonschema.Schema) *bschemas.ToolFunctionParameters {
	if s == nil {
		return nil
	}

	data, _ := json.Marshal(s) //nolint:errchkjson // *jsonschema.Schema is JSON-safe.

	var params bschemas.ToolFunctionParameters
	_ = json.Unmarshal(data, &params) // infallible: re-decoding json.Marshal output.

	return &params
}

// schemaToolsToParams converts internal tool infos into Bifrost chat parameters.
// Returns nil when there are no tools so the request omits the tools field.
func schemaToolsToParams(infos []*schema.ToolInfo) *bschemas.ChatParameters {
	if len(infos) == 0 {
		return nil
	}

	tools := make([]bschemas.ChatTool, 0, len(infos))
	for _, info := range infos {
		desc := info.Desc
		tools = append(tools, bschemas.ChatTool{ //nolint:exhaustruct // optional Bifrost fields omitted
			Type: bschemas.ChatToolTypeFunction,
			Function: &bschemas.ChatToolFunction{ //nolint:exhaustruct // optional Bifrost fields omitted
				Name:        info.Name,
				Description: &desc,
				Parameters:  schemaToToolParameters(info.Params),
			},
		})
	}

	return &bschemas.ChatParameters{Tools: tools} //nolint:exhaustruct // only Tools populated
}

// schemaToBifrostMessages converts internal schema messages into Bifrost chat
// messages, mapping each content block onto Bifrost's content/tool fields.
func schemaToBifrostMessages(in []*schema.Message) []bschemas.ChatMessage {
	out := make([]bschemas.ChatMessage, 0, len(in))
	for _, m := range in {
		bm := bschemas.ChatMessage{ //nolint:exhaustruct // optional Bifrost fields intentionally omitted
			Role: bschemas.ChatMessageRole(m.Role),
		}

		// Collect text content from text blocks.
		if text := m.Text(); text != "" {
			content := text
			bm.Content = &bschemas.ChatMessageContent{ContentStr: &content} //nolint:exhaustruct // only ContentStr used
		}

		// Collect tool results' content as the message content when present.
		if results := m.ToolResults(); len(results) > 0 {
			content := results[0].Content
			if bm.Content == nil && content != "" {
				bm.Content = &bschemas.ChatMessageContent{ //nolint:exhaustruct // only ContentStr used
					ContentStr: &content,
				}
			}
			id := results[0].ToolCallID
			bm.ChatToolMessage = &bschemas.ChatToolMessage{ToolCallID: &id} //nolint:exhaustruct // only ToolCallID used
		}

		if calls := m.ToolCalls(); len(calls) > 0 {
			bm.ChatAssistantMessage = &bschemas.ChatAssistantMessage{ //nolint:exhaustruct // only ToolCalls populated
				ToolCalls: schemaToBifrostToolCalls(calls),
			}
		}

		out = append(out, bm)
	}

	return out
}

// schemaToBifrostToolCalls converts internal schema tool calls into Bifrost tool calls.
func schemaToBifrostToolCalls(in []schema.ToolCallBlock) []bschemas.ChatAssistantMessageToolCall {
	calls := make([]bschemas.ChatAssistantMessageToolCall, 0, len(in))
	fnType := string(bschemas.ChatToolTypeFunction)
	for i, tc := range in {
		id := tc.ID
		name := tc.Name
		calls = append(
			calls,
			bschemas.ChatAssistantMessageToolCall{ //nolint:exhaustruct // optional Bifrost fields intentionally omitted
				Index: uint16(i),
				Type:  &fnType,
				ID:    &id,
				Function: bschemas.ChatAssistantMessageToolCallFunction{
					Name:      &name,
					Arguments: tc.Arguments,
				},
			},
		)
	}

	return calls
}

// schemaFromBifrostMessage converts a Bifrost chat message into an internal schema message.
func schemaFromBifrostMessage(bm bschemas.ChatMessage) *schema.Message {
	out := &schema.Message{Role: schema.Role(bm.Role)} //nolint:exhaustruct // optional fields set below

	if bm.Content != nil && bm.Content.ContentStr != nil && *bm.Content.ContentStr != "" {
		out.Content = append(out.Content, schema.TextBlock{Text: *bm.Content.ContentStr})
	}

	if bm.ChatAssistantMessage != nil {
		for _, tc := range bm.ChatAssistantMessage.ToolCalls {
			call := schema.ToolCallBlock{Arguments: tc.Function.Arguments} //nolint:exhaustruct // ID/Name set below
			if tc.ID != nil {
				call.ID = *tc.ID
			}
			if tc.Function.Name != nil {
				call.Name = *tc.Function.Name
			}
			out.Content = append(out.Content, call)
		}
	}

	return out
}

// rollingCacheTurns is how many trailing text-bearing messages receive a cache
// breakpoint: the latest (written this turn) and the one before it (read next
// turn) — Anthropic's documented rolling multi-turn pattern.
const rollingCacheTurns = 2

// ephemeral returns a fresh ephemeral cache-control marker. A nil TTL selects
// Anthropic's default five-minute cache window.
func ephemeral() *bschemas.CacheControl {
	return &bschemas.CacheControl{Type: bschemas.CacheControlTypeEphemeral} //nolint:exhaustruct // TTL/Scope default
}

// markable reports whether a message carries plain-string text that a cache
// breakpoint can attach to. Messages without text content (e.g. an assistant
// message that is only tool calls) cannot be marked and are skipped.
func markable(m *bschemas.ChatMessage) bool {
	return m.Content != nil && m.Content.ContentStr != nil
}

// markMessage rewrites a string-content message into a single text content block
// carrying an ephemeral cache breakpoint. Only marked messages become blocks, so
// providers that ignore cache control see their other messages unchanged.
func markMessage(m *bschemas.ChatMessage) {
	text := *m.Content.ContentStr
	m.Content = &bschemas.ChatMessageContent{ //nolint:exhaustruct // only ContentBlocks set
		ContentBlocks: []bschemas.ChatContentBlock{{ //nolint:exhaustruct // text block with cache marker
			Type:         bschemas.ChatContentBlockTypeText,
			Text:         &text,
			CacheControl: ephemeral(),
		}},
	}
}

// cacheMarkIndices returns the message indices to mark with a cache breakpoint:
// the last system message plus the last rollingCacheTurns text-bearing messages,
// deduplicated and sorted. This is at most three message breakpoints which, with
// the one tool breakpoint, stays within Anthropic's four-breakpoint limit.
func cacheMarkIndices(msgs []bschemas.ChatMessage) []int {
	marked := make(map[int]struct{})

	lastSystem := -1
	for i := range msgs {
		if msgs[i].Role == bschemas.ChatMessageRoleSystem && markable(&msgs[i]) {
			lastSystem = i
		}
	}
	if lastSystem >= 0 {
		marked[lastSystem] = struct{}{}
	}

	count := 0
	for i := len(msgs) - 1; i >= 0 && count < rollingCacheTurns; i-- {
		if markable(&msgs[i]) {
			marked[i] = struct{}{}
			count++
		}
	}

	out := make([]int, 0, len(marked))
	for i := range marked {
		out = append(out, i)
	}
	slices.Sort(out)

	return out
}

// usageFromBifrost maps Bifrost's token-usage struct into the internal Usage.
// It is nil-safe at every level: a nil usage yields the zero Usage, and nil
// PromptTokensDetails yields zero cache counts.
func usageFromBifrost(u *bschemas.BifrostLLMUsage) schema.Usage {
	if u == nil {
		return schema.Usage{} //nolint:exhaustruct // no usage reported.
	}

	out := schema.Usage{ //nolint:exhaustruct // cache counts set below.
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
	}

	if d := u.PromptTokensDetails; d != nil {
		out.CachedReadTokens = d.CachedReadTokens
		out.CachedWriteTokens = d.CachedWriteTokens
	}

	return out
}

// applyCacheBreakpoints marks a request's stable prefix with ephemeral cache
// breakpoints: the last tool (covering the whole tool-schema array) plus the
// system and trailing conversation messages. Anthropic-family providers honor the
// markers; other providers' converters strip or ignore CacheControl (Bifrost's
// OpenAI converter removes it before sending), so this runs unconditionally and
// cannot malform a non-Anthropic request. Anthropic ignores breakpoints whose
// prefix is below its minimum cacheable length, so no token counting or provider
// check is needed.
func applyCacheBreakpoints(req *bschemas.BifrostChatRequest) {
	if req.Params != nil && len(req.Params.Tools) > 0 {
		req.Params.Tools[len(req.Params.Tools)-1].CacheControl = ephemeral()
	}

	for _, i := range cacheMarkIndices(req.Input) {
		markMessage(&req.Input[i])
	}
}
