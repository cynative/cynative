// Package schema is the provider-agnostic message and tool "currency" shared by
// the llm, agent, tools, and ui packages. It is a pure leaf: it imports only the
// standard library and github.com/invopop/jsonschema, so nothing it depends on can
// create an import cycle. No internal import may ever be added here.
package schema

import "strings"

// Role identifies who produced a message.
type Role string

// The four message roles, matching the OpenAI/Anthropic chat convention.
const (
	System    Role = "system"
	User      Role = "user"
	Assistant Role = "assistant"
	Tool      Role = "tool"
)

// Message is one entry in a chat transcript. Content is a sequence of typed
// blocks (text, tool call, tool result) so a single message can carry assistant
// prose alongside tool calls, mirroring modern content-block chat APIs.
type Message struct {
	Role    Role
	Content []Block
}

// Block is one piece of a message's content. The sealed interface (unexported
// method) keeps the variant set closed to this package.
type Block interface {
	isBlock()
}

// TextBlock is plain assistant/user/system text.
type TextBlock struct {
	Text string
}

// ToolCallBlock is a model-issued request to call a tool. Arguments is the raw
// JSON argument object as the model produced it.
type ToolCallBlock struct {
	ID        string
	Name      string
	Arguments string
}

// ToolResultBlock is the host's reply to a ToolCallBlock, keyed by ToolCallID.
// IsError marks a failed call so the model can self-correct.
type ToolResultBlock struct {
	ToolCallID string
	Content    string
	IsError    bool
}

func (TextBlock) isBlock()       {}
func (ToolCallBlock) isBlock()   {}
func (ToolResultBlock) isBlock() {}

// SystemMessage builds a system-role message with a single text block.
func SystemMessage(text string) *Message {
	return &Message{Role: System, Content: []Block{TextBlock{Text: text}}}
}

// UserMessage builds a user-role message with a single text block.
func UserMessage(text string) *Message {
	return &Message{Role: User, Content: []Block{TextBlock{Text: text}}}
}

// AssistantMessage builds an assistant-role message: optional leading text
// followed by any tool calls. Empty text contributes no text block.
func AssistantMessage(text string, calls []ToolCallBlock) *Message {
	m := &Message{Role: Assistant}
	if text != "" {
		m.Content = append(m.Content, TextBlock{Text: text})
	}
	for _, c := range calls {
		m.Content = append(m.Content, c)
	}

	return m
}

// ToolMessage builds a tool-role message carrying one tool result.
func ToolMessage(content, toolCallID string) *Message {
	return &Message{
		Role:    Tool,
		Content: []Block{ToolResultBlock{ToolCallID: toolCallID, Content: content, IsError: false}},
	}
}

// Text concatenates the message's text blocks (ignoring tool blocks).
func (m *Message) Text() string {
	var b strings.Builder
	for _, blk := range m.Content {
		if t, ok := blk.(TextBlock); ok {
			b.WriteString(t.Text)
		}
	}

	return b.String()
}

// ToolCalls returns the message's tool-call blocks in order.
func (m *Message) ToolCalls() []ToolCallBlock {
	var out []ToolCallBlock
	for _, blk := range m.Content {
		if c, ok := blk.(ToolCallBlock); ok {
			out = append(out, c)
		}
	}

	return out
}

// ToolResults returns the message's tool-result blocks in order.
func (m *Message) ToolResults() []ToolResultBlock {
	var out []ToolResultBlock
	for _, blk := range m.Content {
		if r, ok := blk.(ToolResultBlock); ok {
			out = append(out, r)
		}
	}

	return out
}
