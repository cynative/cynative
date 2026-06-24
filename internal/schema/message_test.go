package schema_test

import (
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

func TestBlockTypes_ImplementBlock(t *testing.T) {
	t.Parallel()

	blocks := []schema.Block{
		schema.TextBlock{Text: "hello"},
		schema.ToolCallBlock{ID: "c1", Name: "echo", Arguments: "{}"},
		schema.ToolResultBlock{ToolCallID: "c1", Content: "ok", IsError: false},
	}

	// Verify the blocks round-trip through the interface.
	if tb, ok := blocks[0].(schema.TextBlock); !ok || tb.Text != "hello" {
		t.Errorf("blocks[0] = %#v, want TextBlock{Text: \"hello\"}", blocks[0])
	}
	if tc, ok := blocks[1].(schema.ToolCallBlock); !ok || tc.ID != "c1" || tc.Name != "echo" || tc.Arguments != "{}" {
		t.Errorf("blocks[1] = %#v, want ToolCallBlock{ID: \"c1\", Name: \"echo\", Arguments: \"{}\"}", blocks[1])
	}
	if tr, ok := blocks[2].(schema.ToolResultBlock); !ok || tr.ToolCallID != "c1" || tr.Content != "ok" ||
		tr.IsError {
		t.Errorf(
			"blocks[2] = %#v, want ToolResultBlock{ToolCallID: \"c1\", Content: \"ok\", IsError: false}",
			blocks[2],
		)
	}
}

func TestMessage_FieldsRoundTrip(t *testing.T) {
	t.Parallel()

	m := schema.Message{
		Role:    schema.Assistant,
		Content: []schema.Block{schema.TextBlock{Text: "hi"}},
	}

	if m.Role != schema.Assistant {
		t.Errorf("role = %q, want assistant", m.Role)
	}
	if len(m.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(m.Content))
	}
}

func TestRoles(t *testing.T) {
	t.Parallel()

	roles := []schema.Role{
		schema.System,
		schema.User,
		schema.Assistant,
		schema.Tool,
	}

	expected := []string{"system", "user", "assistant", "tool"}
	for i, r := range roles {
		if string(r) != expected[i] {
			t.Errorf("role[%d] = %q, want %q", i, r, expected[i])
		}
	}
}

func TestConstructors(t *testing.T) {
	t.Parallel()

	if got := schema.SystemMessage("sys"); got.Role != schema.System || got.Text() != "sys" {
		t.Errorf("SystemMessage = %+v", got)
	}
	if got := schema.UserMessage("u"); got.Role != schema.User || got.Text() != "u" {
		t.Errorf("UserMessage = %+v", got)
	}

	calls := []schema.ToolCallBlock{{ID: "c1", Name: "echo", Arguments: "{}"}}
	am := schema.AssistantMessage("done", calls)
	if am.Role != schema.Assistant || am.Text() != "done" {
		t.Errorf("AssistantMessage text/role = %+v", am)
	}
	if got := am.ToolCalls(); len(got) != 1 || got[0].ID != "c1" {
		t.Errorf("ToolCalls = %+v", got)
	}

	tm := schema.ToolMessage("result", "c1")
	if tm.Role != schema.Tool {
		t.Errorf("ToolMessage role = %q", tm.Role)
	}
	if got := tm.ToolResults(); len(got) != 1 || got[0].ToolCallID != "c1" || got[0].Content != "result" {
		t.Errorf("ToolResults = %+v", got)
	}
}

func TestAssistantMessage_NoToolCalls(t *testing.T) {
	t.Parallel()

	am := schema.AssistantMessage("just text", nil)
	if len(am.ToolCalls()) != 0 {
		t.Errorf("expected no tool calls, got %+v", am.ToolCalls())
	}
}

func TestAssistantMessage_NoText(t *testing.T) {
	t.Parallel()

	am := schema.AssistantMessage("", []schema.ToolCallBlock{{ID: "c1", Name: "x", Arguments: "{}"}})
	if am.Text() != "" {
		t.Errorf("expected empty text, got %q", am.Text())
	}
	if len(am.ToolCalls()) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(am.ToolCalls()))
	}
}

func TestText_ConcatenatesTextBlocksSkippingToolBlocks(t *testing.T) {
	t.Parallel()

	m := schema.Message{Content: []schema.Block{
		schema.TextBlock{Text: "a"},
		schema.ToolCallBlock{ID: "c1"},
		schema.TextBlock{Text: "b"},
	}}
	if got := m.Text(); got != "ab" {
		t.Errorf("Text() = %q, want %q", got, "ab")
	}
}

func TestToolCallsAndResults_SkipNonMatching(t *testing.T) {
	t.Parallel()

	m := schema.Message{Content: []schema.Block{
		schema.TextBlock{Text: "x"},
		schema.ToolCallBlock{ID: "c1", Name: "n", Arguments: "{}"},
		schema.ToolResultBlock{ToolCallID: "c1", Content: "r"},
	}}
	if got := m.ToolCalls(); len(got) != 1 || got[0].ID != "c1" {
		t.Errorf("ToolCalls = %+v", got)
	}
	if got := m.ToolResults(); len(got) != 1 || got[0].Content != "r" {
		t.Errorf("ToolResults = %+v", got)
	}
}
