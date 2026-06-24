// Package agent drives the in-house DeepAgents-style research loop: a single
// tool-calling loop with a write_todos planning tool, a task sub-agent tool,
// and a verify_findings adversarial-verification tool.
// The credentialed I/O tools arrive approval-wrapped from the composition root;
// the orchestration tools are surfaced (rendered), not gated.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// todoStatus is one of the three DeepAgents todo states.
type todoStatus string

// The three todo states; anything else is normalized to todoPending.
const (
	todoPending    todoStatus = "pending"
	todoInProgress todoStatus = "in_progress"
	todoCompleted  todoStatus = "completed"
)

// todo is one planning item tracked via write_todos.
type todo struct {
	Content string     `json:"content" jsonschema_description:"What this step does."`
	Status  todoStatus `json:"status"  jsonschema_description:"One of pending, in_progress, completed."`
}

// maxOrchestrationTools caps the host orchestration tools New appends to the
// I/O tool set (write_todos, task, and verify_findings).
const maxOrchestrationTools = 3

// seedExtra is the number of non-history messages prepended/appended when
// seeding a top-level turn (the system message and the new user question).
const seedExtra = 2

// ConnectorMeta carries a registered connector's runtime identity and posture,
// surfaced in the system prompt so the model knows the connected environment
// (account/project/principal, hardening posture) on every run.
type ConnectorMeta struct {
	Identity string
	Posture  string
}

// Config holds the dependencies needed to build an Agent.
type Config struct {
	Model     schema.ChatModel
	Cfg       config.Config
	Tools     []schema.InvokableTool // approval-wrapped I/O tools (http_request, code_execution).
	Providers []auth.Provider
	// Connectors carries each registered connector's runtime identity/posture,
	// keyed by provider name, enriching the system-prompt provider list so the
	// connected environment is in the model's context on every run.
	Connectors map[string]ConnectorMeta
	// About is the curated product description (from the embedded README) woven
	// into the system prompt; empty inserts nothing. The composition root passes
	// cynative.About().
	About         string
	Renderer      func(msg *schema.Message, style string, w io.Writer)
	VerboseWriter io.Writer
	Metrics       *metrics.Accumulator // session telemetry; nil is safe (no-op).
	// DeniedToolResult is the trusted approval-denial sentinel; tool results equal
	// to it are returned unframed (a denial is a host/user control signal, not
	// untrusted external data).
	DeniedToolResult string
	// Audit is the sink every tool call is recorded to (attempt + result). Nil
	// disables auditing (no-op); the composition root passes a *audit.Logger when
	// the audit log is enabled.
	Audit audit.Sink
	// Interrupter requests a graceful stop and brackets each turn; nil is a safe no-op.
	Interrupter Interrupter
	// OnFirstResponse fires once, at depth 0, the moment the model's first response
	// of a turn is recorded (before that turn is rendered) — letting the CLI place
	// the LLM ✓ status right after Connectors. Stored immutably (set in New), so it
	// adds no per-run *Agent mutable state; nil is a safe no-op. Idempotency across
	// turns is the caller's concern (the CLI uses a once-guard).
	OnFirstResponse func()
}

// Option configures an Agent at construction time (test-only; see export_test.go).
type Option func(*Agent)

// Agent drives the research loop and carries Q&A history across interactive turns.
type Agent struct {
	model    schema.ChatModel
	tools    toolset
	renderer func(*schema.Message, string, io.Writer)
	style    string
	// verbose is the writer sub-runs render their output to; renderTurn also writes
	// per-tool-call notices here under --verbose. It is shared across all concurrent
	// sub-runs (each sub-run's out is set to verbose), so it must remain a
	// write-tolerant sink — stderr or io.Discard — until #140 adds framed per-run
	// output. Nil when --verbose is not set (verboseWriter falls back to io.Discard).
	verbose         io.Writer
	systemPrompt    string
	maxIter         int
	maxSubagentIter int
	history         []*schema.Message    // Q&A only: user questions + final answers.
	metrics         *metrics.Accumulator // Session telemetry (mirrors Config.Metrics); nil is a safe no-op.
	// deniedResult is the trusted approval-denial sentinel; results equal to it are
	// not framed as untrusted data (mirrors Config.DeniedToolResult).
	deniedResult           string
	audit                  audit.Sink    // Per-tool-call audit sink; nil is a safe no-op.
	sessionID              string        // Stable per-process correlation ID for the whole session.
	newID                  func() string // ID generator (session/run/call IDs); injectable for tests.
	interrupter            Interrupter   // Graceful-stop seam; nil is a no-op.
	maxConsecutiveFailures int           // Consecutive no-progress tool calls before a halt-and-summarize; 0 disables.
	welcomeTimeoutD        time.Duration // Overrides the default welcomeTimeout; 0 = use the constant default.
	onFirstResponse        func()        // Fired once at the first depth-0 model response; nil is a no-op.
}

// New builds the agent: it assembles the system prompt, registers the host
// orchestration tools (write_todos, task, and verify_findings) alongside the
// approval-wrapped I/O tools, and binds the tool schemas the model will see.
func New(_ context.Context, cfg Config, opts ...Option) (*Agent, error) {
	a := &Agent{ //nolint:exhaustruct // tools/history/sessionID set below or per Run
		model:                  cfg.Model,
		renderer:               cfg.Renderer,
		style:                  cfg.Cfg.RenderStyle,
		verbose:                cfg.VerboseWriter,
		systemPrompt:           systemPrompt(cfg.Providers, cfg.Connectors, cfg.About),
		maxIter:                cfg.Cfg.MaxIterations,
		maxSubagentIter:        cfg.Cfg.MaxSubagentIterations,
		metrics:                cfg.Metrics,
		deniedResult:           cfg.DeniedToolResult,
		audit:                  cfg.Audit,
		newID:                  uuid.NewString,
		interrupter:            cfg.Interrupter,
		maxConsecutiveFailures: cfg.Cfg.MaxConsecutiveFailures,
		onFirstResponse:        cfg.OnFirstResponse,
	}

	// Orchestration tools are surfaced, not gated: they perform no credentialed
	// I/O, so they are registered bare and render their activity (todo checklist,
	// sub-task bracket) instead of blocking on host approval. The I/O tools in
	// cfg.Tools arrive pre-wrapped from the composition root. verify_findings is
	// always registered: verification is unconditional.
	all := make([]schema.InvokableTool, 0, len(cfg.Tools)+maxOrchestrationTools)
	all = append(all, cfg.Tools...)
	all = append(all, newWriteTodosTool(a), newTaskTool(a), newVerifyFindingsTool(a))

	ts, err := buildToolset(all)
	if err != nil {
		return nil, err
	}
	a.tools = ts

	for _, o := range opts {
		o(a)
	}

	a.sessionID = a.newID()

	return a, nil
}

// WithWelcomeTimeout overrides the default welcome generate timeout for the
// agent built by [New]. Zero and negative values are silently ignored (the
// welcome constant is used). Intended for tests that need a short timeout to
// drive the [ErrWelcomeTimedOut] sentinel; production callers should omit it.
func WithWelcomeTimeout(d time.Duration) Option {
	return func(a *Agent) {
		if d > 0 {
			a.welcomeTimeoutD = d
		}
	}
}

// buildToolset indexes tools by name and collects their schemas.
func buildToolset(ts []schema.InvokableTool) (toolset, error) {
	out := toolset{
		tools: make(map[string]schema.InvokableTool, len(ts)),
		infos: make([]*schema.ToolInfo, 0, len(ts)),
	}
	for _, t := range ts {
		info, err := t.Info(context.Background())
		if err != nil {
			return toolset{}, fmt.Errorf("agent: read tool info: %w", err)
		}
		out.tools[info.Name] = t
		out.infos = append(out.infos, info)
	}

	return out, nil
}

// Run executes one research turn: it seeds the working transcript from the Q&A
// history plus the new question, drives the loop under a fresh root runState,
// and records the final answer. Run is not safe for concurrent use (it appends
// to history and brackets the turn's active-compute window via StartTurn/EndTurn);
// only the inner run loop supports concurrent callers.
func (a *Agent) Run(ctx context.Context, task string, w io.Writer) error {
	a.metrics.StartTurn()
	defer a.metrics.EndTurn()
	a.beginTurn()
	defer a.endTurn()

	rs := &runState{depth: 0, out: w, todos: nil, runID: a.newID()}

	seed := make([]*schema.Message, 0, len(a.history)+seedExtra)
	seed = append(seed, schema.SystemMessage(a.systemPrompt))
	seed = append(seed, a.history...)
	seed = append(seed, schema.UserMessage(task))

	answer, err := a.run(ctx, rs, seed, a.maxIter)
	if err != nil {
		if errors.Is(err, errInterrupted) {
			fmt.Fprintln(w, "\n⏸  Stopped. Tell me how you'd like to proceed, or refine the question.")

			return ErrInterrupted
		}
		if errors.Is(err, errBudgetExceeded) {
			fmt.Fprintf(w, "\n⚠️  Budget reached — %s. Stopping; restart with a higher limit to continue.\n",
				a.metrics.BudgetReason())

			return nil
		}

		return err
	}

	if answer == "" {
		fmt.Fprintln(w, "\n⚠️  Reached the iteration limit without a final answer.")

		return nil
	}

	a.history = append(a.history, schema.UserMessage(task), schema.AssistantMessage(answer, nil))

	return nil
}

// verboseWriter returns the writer sub-runs render verbose output to.
func (a *Agent) verboseWriter() io.Writer {
	if a.verbose != nil {
		return a.verbose
	}

	return io.Discard
}

// interrupted reports whether a graceful stop was requested; a nil interrupter never is.
func (a *Agent) interrupted() bool { return a.interrupter != nil && a.interrupter.Interrupted() }

// fireFirstResponse invokes the one-shot first-response hook when set; a nil hook
// is a no-op.
func (a *Agent) fireFirstResponse() {
	if a.onFirstResponse != nil {
		a.onFirstResponse()
	}
}

// maybeFireFirstResponse fires the one-shot hook on the first depth-0 model
// response of a run. The first parameter is the run-local flag that gates it to
// once-per-run; depth>0 sub-runs skip it entirely. The flag is taken by pointer
// so this helper can clear it without the branch contributing to run's cognitive
// complexity.
func (a *Agent) maybeFireFirstResponse(first *bool, depth int) {
	if *first && depth == 0 {
		*first = false
		a.fireFirstResponse()
	}
}

// beginTurn arms the interrupter for a turn; no-op when unset.
func (a *Agent) beginTurn() {
	if a.interrupter != nil {
		a.interrupter.BeginTurn()
	}
}

// endTurn disarms the interrupter; no-op when unset.
func (a *Agent) endTurn() {
	if a.interrupter != nil {
		a.interrupter.EndTurn()
	}
}
