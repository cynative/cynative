package llm

import (
	"context"
	"errors"

	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/schema"
)

// RedactingChatModel wraps a schema.ChatModel and redacts all message content
// sent to the provider — TextBlock text (every role) and ToolResultBlock content
// — leaving ToolCallBlock (model-authored code) and the tool schemas
// untouched. Tool-result content is redacted with RedactPreservingLocation so a
// signed redirect Location URL survives (transport leaves it intact for
// redirect-following); operator/model text is fully redacted.
// It copies the transcript rather than mutating it, so it is safe to share
// across the main loop, task sub-agents, and the concurrent verifier panel.
type RedactingChatModel struct {
	inner    schema.ChatModel
	redactor *redact.Redactor
}

// Compile-time assertion: RedactingChatModel is a schema.ChatModel.
var _ schema.ChatModel = (*RedactingChatModel)(nil)

// NewRedactingChatModel wraps inner so every Generate call redacts message
// content via redactor before delegating. redactor must be non-nil.
func NewRedactingChatModel(inner schema.ChatModel, redactor *redact.Redactor) *RedactingChatModel {
	return &RedactingChatModel{inner: inner, redactor: redactor}
}

// Generate redacts a copy of msgs and delegates to the inner model, passing the
// tools (tool schemas) through unchanged. Any *GenerateError returned by the
// inner model has its Message field redacted before it reaches the caller.
func (m *RedactingChatModel) Generate(
	ctx context.Context, msgs []*schema.Message, tools []*schema.ToolInfo,
) (*schema.Message, error) {
	redacted := make([]*schema.Message, len(msgs))
	for i, msg := range msgs {
		redacted[i] = m.redactMessage(msg)
	}

	resp, err := m.inner.Generate(ctx, redacted, tools)

	return resp, m.redactGenerateError(err)
}

// redactGenerateError returns err with a *GenerateError's Message redacted. The
// inner model (BifrostChatModel) returns the bare *GenerateError, so this is the
// single redaction boundary every agent Generate flows through — making the
// message secret-free for the -v verbose log and the turn-≥2 %v path. It returns
// a COPY (never mutates the caller's error), keeping this wrapper safe for the
// concurrent verifier panel.
func (m *RedactingChatModel) redactGenerateError(err error) error {
	var ge *GenerateError
	if !errors.As(err, &ge) {
		return err
	}

	clone := *ge
	clone.Message = m.redactor.Redact(ge.Message)

	return &clone
}

// redactMessage returns a copy of msg with a fresh Content slice in which text
// and tool-result blocks are redacted, so the original message is never mutated.
// schema.Block is a sealed interface: the only block the default arm passes
// through today is ToolCallBlock (model-authored JS/JSON — redacting it could
// corrupt valid code, and by construction the model never held a raw secret to
// embed). Any NEW content-bearing Block variant added to internal/schema must
// gain its own redaction case here, or it would reach the provider unredacted.
func (m *RedactingChatModel) redactMessage(msg *schema.Message) *schema.Message {
	blocks := make([]schema.Block, len(msg.Content))
	for i, blk := range msg.Content {
		switch b := blk.(type) {
		case schema.TextBlock:
			blocks[i] = schema.TextBlock{Text: m.redactor.Redact(b.Text)}
		case schema.ToolResultBlock:
			blocks[i] = schema.ToolResultBlock{
				ToolCallID: b.ToolCallID,
				Content:    m.redactor.RedactPreservingLocation(b.Content),
			}
		default:
			// ToolCallBlock today (see doc comment); a future content-bearing
			// variant MUST be added as an explicit redaction case above.
			blocks[i] = blk
		}
	}

	return &schema.Message{Role: msg.Role, Content: blocks}
}
