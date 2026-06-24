package tools

import (
	"context"
	"sync/atomic"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/schema"
)

// DeniedMessage is returned as the tool result when the user denies a call.
const DeniedMessage = "User denied execution of this tool call."

// Decision is the operator's answer to an approval prompt.
type Decision int

const (
	// Deny rejects the call. It is the zero value, so an undecided, empty, or
	// EOF prompt fails closed.
	Deny Decision = iota
	// ApproveOnce approves this single call.
	ApproveOnce
	// ApproveSession approves this call and every later call to the same tool for
	// the rest of the session.
	ApproveSession
)

// Prompter asks the host to approve a tool call. alreadyGranted reports whether
// this tool already holds a session grant; when true the host displays the call
// and approves without pausing for input. It blocks (when it prompts) until the
// user decides. The same prompter is shared across the whole run (including task
// sub-agent runs), so every call funnels to one host.
type Prompter func(name, arguments, style string, alreadyGranted bool) Decision

// approvalTool decorates a schema.InvokableTool so each call requires synchronous
// host approval. On approval it runs the inner tool; on denial it returns
// DeniedMessage (not an error) so the loop continues and the model can adapt.
// granted latches once the operator answers ApproveSession, after which every
// later call to this tool is auto-approved (still displayed, never paused).
type approvalTool struct {
	inner    schema.InvokableTool
	prompter Prompter
	style    string
	granted  atomic.Bool
}

var _ schema.InvokableTool = (*approvalTool)(nil)

// NewApprovalTool wraps inner so each Run is gated by prompter. style is the
// render style passed through to the prompter for formatting.
func NewApprovalTool(inner schema.InvokableTool, prompter Prompter, style string) schema.InvokableTool {
	return &approvalTool{inner: inner, prompter: prompter, style: style}
}

// Info delegates to the inner tool so the model sees the real schema.
func (a *approvalTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return a.inner.Info(ctx)
}

// Run prompts for approval (or honors a standing session grant), records the
// decision on the context for the audit log, then runs or denies the inner tool.
func (a *approvalTool) Run(ctx context.Context, argumentsInJSON string) (string, error) {
	info, err := a.inner.Info(ctx)
	if err != nil {
		return "", err
	}

	granted := a.granted.Load()
	d := a.prompter(info.Name, argumentsInJSON, a.style, granted)
	if d == ApproveSession {
		a.granted.Store(true)
	}

	switch {
	case d == Deny:
		audit.RecordDecision(ctx, false)

		return DeniedMessage, nil
	case granted:
		// A standing grant auto-approved this call; no human reviewed it freshly.
		audit.RecordSessionApproval(ctx)
	default:
		// A human reviewed this call at the prompt (includes the initial ApproveSession).
		audit.RecordDecision(ctx, true)
	}

	return a.inner.Run(ctx, argumentsInJSON)
}
