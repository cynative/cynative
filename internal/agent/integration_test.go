package agent_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// twoStepModel drives the loop end-to-end: the first Generate calls the echo
// tool, the second returns the final answer. Tracking calls under a mutex keeps
// it race-safe even though the loop is single-threaded.
type twoStepModel struct {
	mu    sync.Mutex
	calls int
}

var _ schema.ChatModel = (*twoStepModel)(nil)

func (m *twoStepModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++

	if m.calls == 1 {
		return schema.AssistantMessage("", []schema.ToolCallBlock{
			{ID: "c1", Name: "echo", Arguments: "{}"},
		}), nil
	}

	return schema.AssistantMessage("final", nil), nil
}

// seqModel returns scripted messages in order and records every transcript it
// receives, so assertions can inspect what the sub-run saw.
type seqModel struct {
	mu    sync.Mutex
	msgs  []*schema.Message
	calls int
	seen  [][]*schema.Message
}

var _ schema.ChatModel = (*seqModel)(nil)

func (m *seqModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = append(m.seen, msgs)
	if m.calls >= len(m.msgs) {
		return nil, errors.New("seqModel: out of scripted messages")
	}
	msg := m.msgs[m.calls]
	m.calls++

	return msg, nil
}

// assistantCall builds an assistant message carrying a single tool call.
func assistantCall(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCallBlock{{ID: id, Name: name, Arguments: args}})
}

// echoInnerTool records whether its body ran so the deny path can assert it did
// not execute.
type echoInnerTool struct {
	ran *bool
}

var _ schema.InvokableTool = (*echoInnerTool)(nil)

func (*echoInnerTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "echo", Desc: "echo", Params: nil}
}

func (t *echoInnerTool) Run(context.Context, string) (string, error) {
	*t.ran = true

	return "echoed", nil
}

// recordingPrompter captures the arguments it was called with and returns a
// fixed decision, proving the approval wrapper funnels to the host. names
// accumulates every prompted tool name in call order.
type recordingPrompter struct {
	mu       sync.Mutex
	approve  bool
	called   bool
	names    []string
	gotName  string
	gotArgs  string
	gotStyle string
}

func (p *recordingPrompter) prompt(name, args, style string, _ bool) tools.Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.called = true
	p.names = append(p.names, name)
	p.gotName = name
	p.gotArgs = args
	p.gotStyle = style

	if p.approve {
		return tools.ApproveOnce
	}

	return tools.Deny
}

// promptedNames returns a copy of every tool name the prompter saw, in order.
func (p *recordingPrompter) promptedNames() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.names...)
}

// capturingRenderer appends a rendered message's text to w.
func capturingRenderer(msg *schema.Message, _ string, w io.Writer) {
	_, _ = io.WriteString(w, msg.Text())
}

// runWithModel builds the agent with the synchronous approval-wrapped echo tool
// and the given model, runs one task, and returns the rendered output and any
// error.
func runWithModel(
	t *testing.T,
	prompter *recordingPrompter,
	ran *bool,
	model schema.ChatModel,
) (string, error) {
	t.Helper()

	ctx := context.Background()
	echo := tools.NewApprovalTool(&echoInnerTool{ran: ran}, prompter.prompt, "notty")

	a := agent.New(ctx, agent.Config{ //nolint:exhaustruct // VerboseWriter/Metrics omitted
		Model: model,
		Cfg: config.Config{ //nolint:exhaustruct // only loop/render knobs matter
			MaxIterations:         10,
			RenderStyle:           "notty",
			MaxSubagentIterations: 10,
		},
		Tools:     []schema.InvokableTool{echo},
		Providers: nil,
		Renderer:  capturingRenderer,
	})

	var buf bytes.Buffer
	runErr := a.Run(ctx, "do it", &buf)

	return buf.String(), runErr
}

// runHITL drives the approval flow with the standard two-step model.
func runHITL(t *testing.T, prompter *recordingPrompter, ran *bool) (string, error) {
	t.Helper()

	return runWithModel(t, prompter, ran, &twoStepModel{}) //nolint:exhaustruct // zero state is initial
}

// TestIntegration_HITL_Approve drives the loop through a synchronous approval:
// the prompter approves, the inner echo tool runs, and the model produces its
// final answer.
func TestIntegration_HITL_Approve(t *testing.T) {
	t.Parallel()

	prompter := &recordingPrompter{approve: true} //nolint:exhaustruct // recorded fields start zero

	var ran bool

	out, err := runHITL(t, prompter, &ran)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !prompter.called {
		t.Fatal("prompter was never called; approval did not funnel to the host")
	}
	if prompter.gotName != "echo" {
		t.Errorf("prompter name = %q, want echo", prompter.gotName)
	}
	if prompter.gotArgs != "{}" {
		t.Errorf("prompter args = %q, want {}", prompter.gotArgs)
	}
	if prompter.gotStyle != "notty" {
		t.Errorf("prompter style = %q, want notty", prompter.gotStyle)
	}
	if !ran {
		t.Error("inner echo tool did not run on the approve path")
	}
	if !strings.Contains(out, "final") {
		t.Errorf("rendered output = %q, want it to contain final", out)
	}
}

// TestIntegration_HITL_Deny drives the loop with a denying prompter: the
// approval wrapper returns DeniedMessage instead of running the inner tool, the
// model still produces its final answer, and the run completes cleanly.
func TestIntegration_HITL_Deny(t *testing.T) {
	t.Parallel()

	prompter := &recordingPrompter{approve: false} //nolint:exhaustruct // recorded fields start zero

	var ran bool

	out, err := runHITL(t, prompter, &ran)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !prompter.called {
		t.Fatal("prompter was never called; approval did not funnel to the host")
	}
	if ran {
		t.Error("inner echo tool ran despite the user denying the call")
	}
	if !strings.Contains(out, "final") {
		t.Errorf("rendered output = %q, want it to contain final", out)
	}
}

// TestIntegration_SubagentIOStaysGated is the regression test for the
// load-bearing invariant behind ungating task: the sub-run reuses the parent's
// approval-wrapped I/O tools, so the host is prompted for the sub-agent's echo
// call — and ONLY for it; the orchestration tools (write_todos, task) never
// consult the prompter, and their activity is surfaced on the main output.
func TestIntegration_SubagentIOStaysGated(t *testing.T) {
	t.Parallel()

	prompter := &recordingPrompter{approve: true} //nolint:exhaustruct // recorded fields start zero

	var ran bool

	model := &seqModel{msgs: []*schema.Message{ //nolint:exhaustruct // calls/seen start zero
		assistantCall("c1", "write_todos", `{"todos":[{"content":"step one","status":"pending"}]}`),
		assistantCall("c2", "task", `{"description":"sub job"}`),
		assistantCall("c3", "echo", "{}"), // First sub-run turn.
		schema.AssistantMessage("sub done", nil),
		schema.AssistantMessage("parent final", nil),
	}}

	out, err := runWithModel(t, prompter, &ran, model)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if got := prompter.promptedNames(); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("prompted tools = %v, want exactly [echo]", got)
	}
	if !ran {
		t.Error("sub-agent echo did not run on the approve path")
	}
	for _, want := range []string{
		"step one",                       // Todo checklist surfaced without approval.
		"▶ Delegating sub-task: sub job", // Task bracket start.
		"■ Sub-task complete",            // Task bracket close.
		"parent final",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q; got %q", want, out)
		}
	}
}

// TestIntegration_SubagentIODenied proves the host keeps veto power over a
// sub-agent's I/O: the denial reaches the sub-agent as the echo call's tool
// result and the run still completes cleanly.
func TestIntegration_SubagentIODenied(t *testing.T) {
	t.Parallel()

	prompter := &recordingPrompter{approve: false} //nolint:exhaustruct // recorded fields start zero

	var ran bool

	model := &seqModel{msgs: []*schema.Message{ //nolint:exhaustruct // calls/seen start zero
		assistantCall("c1", "task", `{"description":"sub job"}`),
		assistantCall("c2", "echo", "{}"),
		schema.AssistantMessage("sub done", nil),
		schema.AssistantMessage("parent final", nil),
	}}

	out, err := runWithModel(t, prompter, &ran, model)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if ran {
		t.Error("inner echo tool ran despite the user denying the call")
	}
	if got := prompter.promptedNames(); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("prompted tools = %v, want exactly [echo]", got)
	}

	// Transcripts seen by Generate: [0] parent seed, [1] sub seed, [2] sub turn
	// after the denied echo dispatch, [3] parent turn after the task result.
	model.mu.Lock()
	subTurn := model.seen[2]
	model.mu.Unlock()

	last := subTurn[len(subTurn)-1]
	if last.Role != schema.Tool {
		t.Fatalf("sub-run last message role = %q, want tool", last.Role)
	}
	results := last.ToolResults()
	// echo is an I/O tool, so dispatch fences the denial message as untrusted; the
	// DeniedMessage content still rides inside that fence.
	if len(results) != 1 || !strings.Contains(results[0].Content, tools.DeniedMessage) {
		t.Fatalf("sub-run tool result = %+v, want DeniedMessage", results)
	}
	// The denial rides the original call ID as an ordinary result.
	if results[0].ToolCallID != "c2" {
		t.Errorf("tool result = %+v, want ToolCallID c2", results[0])
	}
	if !strings.Contains(out, "parent final") {
		t.Errorf("rendered output = %q, want parent final", out)
	}
}

// runWithVerifier mirrors runWithModel; verify_findings is always registered
// (verification is unconditional).
func runWithVerifier(
	t *testing.T,
	prompter *recordingPrompter,
	model schema.ChatModel,
) (string, error) {
	t.Helper()

	ctx := context.Background()

	// ran is required by echoInnerTool's unconditional write; this test never approves I/O, so it stays false and is deliberately unasserted.
	var ran bool
	echo := tools.NewApprovalTool(&echoInnerTool{ran: &ran}, prompter.prompt, "notty")

	a := agent.New(ctx, agent.Config{ //nolint:exhaustruct // VerboseWriter/Metrics omitted
		Model: model,
		Cfg: config.Config{ //nolint:exhaustruct // only loop/render knobs matter
			MaxIterations:         10,
			RenderStyle:           "notty",
			MaxSubagentIterations: 10,
		},
		Tools:     []schema.InvokableTool{echo},
		Providers: nil,
		Renderer:  capturingRenderer,
	})

	var buf bytes.Buffer
	runErr := a.Run(ctx, "audit it", &buf)

	return buf.String(), runErr
}

// verifierScriptModel scripts the supervisor turns and answers each batched
// verification pass (recognized by its verifier system prompt) statelessly with
// a single map-keyed verdict object: f1 (Open SG) confirmed, f2 (Stale key)
// refuted. Both passes return the same map, so Open SG is confirmed in both →
// VERIFIED and Stale key is refuted in either → REFUTED — a deterministic
// mixed-verdict panel regardless of pass order.
type verifierScriptModel struct {
	mu    sync.Mutex
	turns int
}

var _ schema.ChatModel = (*verifierScriptModel)(nil)

func (m *verifierScriptModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	if strings.Contains(msgs[0].Text(), "adversarial reviewer") {
		return schema.AssistantMessage(
			`{"f1":{"verdict":"confirmed","justification":"evidence holds"},`+
				`"f2":{"verdict":"refuted","justification":"the key was rotated"}}`, nil,
		), nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.turns++
	if m.turns == 1 {
		return assistantCall("v1", "verify_findings",
			`{"findings":[`+
				`{"title":"Open SG","claim":"sg-1 allows 0.0.0.0/0","evidence":"IpRanges: 0.0.0.0/0"},`+
				`{"title":"Stale key","claim":"key k1 is stale","evidence":"k1 rotated yesterday"}]}`), nil
	}

	// turns > 2 is unreachable: the scripted supervisor makes exactly two non-verifier turns (tool call, then final answer).
	return schema.AssistantMessage("report: Open SG (verified)", nil), nil
}

// TestIntegration_VerifierPanel drives supervisor → verify_findings → mixed
// verdicts → final answer: the panel renders both outcomes, the result reaches
// the supervisor, and — the load-bearing assertion — NO approval prompt fires
// for the verifier (skeptics are tool-less by construction; only I/O tools
// consult the prompter).
func TestIntegration_VerifierPanel(t *testing.T) {
	t.Parallel()

	prompter := &recordingPrompter{approve: true} //nolint:exhaustruct // recorded fields start zero

	out, err := runWithVerifier(t, prompter, &verifierScriptModel{}) //nolint:exhaustruct // zero state
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := prompter.promptedNames(); len(got) != 0 {
		t.Fatalf("prompted tools = %v, want none (verification must not trigger approvals)", got)
	}
	for _, want := range []string{
		"Verification panel",
		"✅ Open SG",
		"❌ Stale key",
		"report: Open SG (verified)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q; got %q", want, out)
		}
	}
}
