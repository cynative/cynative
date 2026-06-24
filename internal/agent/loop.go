package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/schema"
)

// interruptPollInterval is how often a long blocking dispatch (a running
// code_execution script, a verifier skeptic) polls for a graceful stop, so the
// operator's interrupt cancels in-flight I/O promptly instead of waiting out the
// call's own timeout.
const interruptPollInterval = 50 * time.Millisecond

// errBudgetExceeded halts a run when the per-session token budget is
// reached. The main loop returns it; Run renders a notice and recovers (it is
// not a fatal error). It is errname-compliant (err-prefixed) and
// gochecknoglobals-exempt (error-typed global, like auth's sentinels).
var errBudgetExceeded = errors.New("agent: budget exceeded")

// errInterrupted halts a run when the operator requests a graceful stop (Esc / first
// Ctrl-C). Run renders a terse notice and returns ErrInterrupted (non-fatal in an
// interactive session; exit 130 in one-shot). Errname-compliant; the error type exempts
// it from gochecknoglobals.
var errInterrupted = errors.New("agent: interrupted")

// ErrInterrupted is the exported form so the cli/main can map a one-shot interrupt to
// exit code 130 and the interactive loop can treat it as non-fatal.
var ErrInterrupted = errInterrupted

// deniedInterruptResult is the model-facing message returned by invokeIO when the
// operator interrupted before the tool was dispatched; it matches the unframed
// denial convention (trusted host/user signal, not untrusted tool output).
const deniedInterruptResult = "Tool not run: the operator interrupted the turn."

// toolset indexes the tools the loop dispatches against and the schemas offered
// to the model.
type toolset struct {
	tools map[string]schema.InvokableTool // name → dispatchable tool; I/O tools arrive pre-wrapped.
	infos []*schema.ToolInfo              // schemas offered to the model.
}

// runState carries one run's mutable execution state. Each run — the top-level
// turn or a task sub-run — gets its own instance, so concurrent sub-runs share
// no mutable state on *Agent (the prerequisite for the verifier panel and for
// programmatic task fan-out, #140).
type runState struct {
	depth int       // Sub-agent nesting depth; 0 = top-level. Immutable after creation.
	out   io.Writer // This run's rendering target.
	// todos is this run's plan, written by write_todos. Write-only from the loop's
	// perspective — rendered when written, never read back into the loop.
	todos []todo
	// runID correlates every record of one turn (main run + its task sub-runs).
	runID string
	// consecutiveFailures counts no-progress tool calls in this run; reset on any
	// progress. At maxConsecutiveFailures the run halts into a model summary (#252).
	consecutiveFailures int
}

// runScopedTool is implemented by the in-package orchestration tools that need
// the current run's state. dispatch prefers runScoped over Run, so these tools
// never observe a foreign run's depth, plan, or output writer.
type runScopedTool interface {
	schema.InvokableTool
	runScoped(ctx context.Context, rs *runState, argumentsInJSON string) (string, error)
}

// run drives one tool-calling loop to a final answer. turn is the working
// transcript seeded by the caller; rs is this run's private state. The loop
// terminates when the model emits an assistant turn with no tool calls (the
// final answer) or after maxIter iterations (returns ""). Tool failures and
// unknown tools come back as tool-result content, never as a Go error, so the
// model can self-correct. A non-nil error from dispatch (fatal audit failure)
// aborts the run immediately.
func (a *Agent) run(ctx context.Context, rs *runState, turn []*schema.Message, maxIter int) (string, error) {
	firstResponse := true
	for range maxIter {
		// Top-of-iteration halt check: interrupt (highest priority) then budget.
		if err := a.haltErr(); err != nil {
			return "", err
		}

		// Cancel a hung/slow model call on the first graceful stop, so a one-shot is
		// not stuck for the provider timeout waiting on Generate (issue #270); the
		// poll mirrors invokeIO's in-flight cancellation.
		gctx, gcancel := context.WithCancel(ctx)
		gstop := a.cancelOnInterrupt(gcancel, interruptPollInterval)
		msg, err := a.model.Generate(gctx, turn, a.tools.infos)
		gstop()
		gcancel()
		a.metrics.AddRoundTrip()

		// Halt check ahead of the error return: a graceful stop (or budget cross)
		// during Generate wins over a coincident model error, so an interrupt that
		// canceled the in-flight call surfaces as ErrInterrupted/130 rather than a
		// generic model failure — and a normal response is never rendered after a stop.
		if herr := a.haltErr(); herr != nil {
			return "", herr
		}
		if err != nil {
			return "", fmt.Errorf("agent: model generate: %w", err)
		}
		// Record a true model response only when Generate returned a usable message
		// (not an error or cancellation). AddRoundTrip counts every attempt;
		// AddResponse counts only successful ones, used by the CLI liveness check.
		a.metrics.AddResponse()

		// Fire the one-shot first-response hook before rendering this turn, at depth 0
		// only, so the CLI can place the LLM ✓ status right after Connectors and before
		// the model's prose — in every mode. A local flag (not *Agent state) keeps
		// concurrent depth-0 runs race-free; depth>0 sub-runs never fire it.
		a.maybeFireFirstResponse(&firstResponse, rs.depth)

		turn = append(turn, msg)
		a.renderTurn(msg, rs.out)

		calls := msg.ToolCalls()
		if len(calls) == 0 {
			// Re-check after rendering: a stop that landed while the final answer was
			// being written still surfaces ErrInterrupted/130 instead of recording the
			// answer and exiting 0.
			if herr := a.haltErr(); herr != nil {
				return "", herr
			}

			return msg.Text(), nil
		}

		for _, tc := range calls {
			a.metrics.AddToolCall()
			var halt string
			turn, halt, err = a.dispatchAndTrack(ctx, rs, tc, turn)
			if err != nil {
				return "", err
			}
			if halt != "" {
				return halt, nil
			}
		}
	}

	return "", nil
}

// dispatchAndTrack dispatches one tool call, appends its result to turn, updates the
// consecutive-failure counter, and checks for halt conditions (interrupt, budget, failure
// ceiling). It returns the updated turn and — when a halt is triggered — the halt answer.
// A non-empty halt answer means the caller must return it immediately. A non-nil error is
// always fatal and must be propagated unwrapped.
func (a *Agent) dispatchAndTrack(
	ctx context.Context, rs *runState, tc schema.ToolCallBlock, turn []*schema.Message,
) ([]*schema.Message, string, error) {
	result, failures, derr := a.dispatch(ctx, rs, tc)
	if derr != nil {
		return turn, "", fmt.Errorf("agent: %w", derr)
	}
	// Tool errors ride in the result text; the Bifrost layer does not set/use IsError today.
	turn = append(turn, schema.ToolMessage(result, tc.ID))

	// Credit every failed attempt (a batched code_execution can carry several), so a
	// script probing N bad IDs reaches the ceiling instead of counting as one; any
	// progress (a call with no failures) resets the streak.
	if failures > 0 {
		rs.consecutiveFailures += failures
	} else {
		rs.consecutiveFailures = 0
	}

	// Post-dispatch halt check: interrupt or budget may have been crossed during this
	// tool call; interrupt and budget take precedence over the consecutive-failure halt.
	if err := a.haltErr(); err != nil {
		return turn, "", err
	}
	if a.failuresExhausted(rs) {
		answer, err := a.failureSummary(ctx, rs, turn)
		if err != nil {
			return turn, "", err
		}

		return turn, answer, nil
	}

	return turn, "", nil
}

// haltErr returns errInterrupted when a graceful stop was requested, errBudgetExceeded
// when the per-session budget is consumed, and nil otherwise. Interrupt takes
// priority over budget so the operator's Ctrl-C always wins. It is called at the
// top of each iteration, immediately after Generate, and after each dispatch.
func (a *Agent) haltErr() error {
	if a.interrupted() {
		return errInterrupted
	}
	if a.metrics.BudgetExceeded() {
		return errBudgetExceeded
	}

	return nil
}

// cancelOnInterrupt starts a goroutine that cancels (via cancel) when a graceful stop
// is requested, so in-flight I/O — a running code_execution script, a verifier skeptic
// — aborts promptly instead of running to its own timeout. The returned stop func ends
// the poll and blocks until the goroutine has exited, so it never outlives the dispatch.
func (a *Agent) cancelOnInterrupt(cancel context.CancelFunc, poll time.Duration) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if a.interrupted() {
					cancel()

					return
				}
			}
		}
	}()

	return func() {
		close(done)
		<-finished
	}
}

// callOutcome is the audit-facing classification of one tool call.
type callOutcome struct {
	decision string
	outcome  string
	result   string
	// failures counts the no-progress sub-outcomes inside this call: for an I/O tool
	// it is the failure recorder's count, so a code_execution script's N failed inner
	// http_request calls each credit the consecutive-failure halt (0 for an OK/scoped call).
	failures int
	// progress counts the useful sub-outcomes (sub-4xx responses); when > 0 the call made
	// progress, so a mixed-success fan-out resets the streak instead of halting (#270).
	progress int
}

// dispatch records an attempt, runs the tool, records the result, and returns the
// model-facing result, the no-progress failure count to credit, and any fatal error. A
// non-nil error is always a fatal audit-write failure (wrapped with audit.ErrLog) and
// aborts the run; ordinary tool errors ride in the result string. The count is the
// recorder's failure tally (so a code_execution script's N failed inner calls each
// count), floored at 1 for any non-OK outcome — but zero when the call also made useful
// progress, so a mixed-success fan-out resets the streak instead of halting.
func (a *Agent) dispatch(ctx context.Context, rs *runState, tc schema.ToolCallBlock) (string, int, error) {
	callID := ""
	if a.newID != nil {
		callID = a.newID()
	}
	args := audit.RawArgs(tc.Arguments)
	// Arguments are verbatim only for approval-gated I/O tools (shown at the prompt);
	// orchestration and unknown tools are never approval-shown, so redact theirs.
	redactArgs := !a.approvalShown(tc.Name)

	if err := a.audited(audit.Record{ //nolint:exhaustruct // attempt carries no decision/outcome/result.
		SessionID: a.sessionID, RunID: rs.runID, CallID: callID, Depth: rs.depth,
		Phase: audit.PhaseAttempt, Tool: tc.Name, Arguments: args, RedactArgs: redactArgs,
	}); err != nil {
		return "", 0, err
	}

	ret, oc, fatal := a.invoke(ctx, rs, tc)
	if fatal != nil {
		return "", 0, fatal
	}

	if err := a.audited(audit.Record{ //nolint:exhaustruct // Via unused for outer calls.
		SessionID: a.sessionID, RunID: rs.runID, CallID: callID, Depth: rs.depth,
		Phase: audit.PhaseResult, Tool: tc.Name, Arguments: args, RedactArgs: redactArgs,
		Decision: oc.decision, Outcome: oc.outcome, Result: oc.result,
	}); err != nil {
		return "", 0, err
	}

	return ret, creditedFailures(oc), nil
}

// creditedFailures is how many no-progress failures to add to the consecutive-failure
// streak for one tool call: the recorder's tally, floored at 1 for any non-OK outcome
// so a denial or a Go error (which records no count) still counts. It is ZERO when the
// call also made useful progress (a sub-4xx response) — a mixed-success code_execution
// fan-out is not a stuck streak — and zero for a plain OK call.
func creditedFailures(oc callOutcome) int {
	if oc.progress > 0 {
		return 0
	}
	if oc.failures > 0 {
		return oc.failures
	}
	if oc.outcome != audit.OutcomeOK {
		return 1
	}

	return 0
}

// failuresExhausted reports whether the run hit the consecutive-failure ceiling.
// A ceiling of 0 disables the trigger.
func (a *Agent) failuresExhausted(rs *runState) bool {
	return a.maxConsecutiveFailures > 0 && rs.consecutiveFailures >= a.maxConsecutiveFailures
}

// approvalShown reports whether a tool's arguments are displayed at the approval
// prompt — true only for the approval-gated I/O tools. Orchestration (runScoped)
// and unknown tools are not approval-shown, so their arguments are redacted.
func (a *Agent) approvalShown(name string) bool {
	t, ok := a.tools.tools[name]
	if !ok {
		return false
	}
	_, scoped := t.(runScopedTool)

	return !scoped
}

// audited logs rec when a sink is configured; a nil sink is a no-op.
func (a *Agent) audited(rec audit.Record) error {
	if a.audit == nil {
		return nil
	}

	return a.audit.Log(rec)
}

// invoke runs one tool call and classifies it. The returned error is non-nil
// only for a fatal audit-write failure surfaced by a tool (errors.Is ErrLog);
// every other tool failure is folded into the result string.
func (a *Agent) invoke(ctx context.Context, rs *runState, tc schema.ToolCallBlock) (string, callOutcome, error) {
	t, ok := a.tools.tools[tc.Name]
	if !ok {
		msg := fmt.Sprintf("Error: unknown tool %q.", tc.Name)

		return msg, callOutcome{decision: audit.DecisionUngated, outcome: audit.OutcomeError, result: msg}, nil
	}

	if rst, scoped := t.(runScopedTool); scoped {
		return a.invokeScoped(ctx, rs, rst, tc)
	}

	return a.invokeIO(ctx, rs, t, tc)
}

// invokeScoped runs an in-package orchestration tool (write_todos, task,
// verify_findings); these are never approval-gated, so the decision is "ungated".
func (a *Agent) invokeScoped(
	ctx context.Context, rs *runState, rst runScopedTool, tc schema.ToolCallBlock,
) (string, callOutcome, error) {
	out, err := rst.runScoped(ctx, rs, tc.Arguments)
	if err != nil {
		// A fatal audit failure inside a task sub-run must abort the parent run too;
		// it must not be folded into the transcript like an ordinary tool error.
		if errors.Is(err, audit.ErrLog) {
			return "", callOutcome{}, err //nolint:exhaustruct // fatal path ignores callOutcome.
		}
		msg := fmt.Sprintf("Error executing tool %q: %v", tc.Name, err)

		return msg, callOutcome{decision: audit.DecisionUngated, outcome: audit.OutcomeError, result: msg}, nil
	}

	return out, callOutcome{decision: audit.DecisionUngated, outcome: audit.OutcomeOK, result: out}, nil
}

// invokeIO runs an approval-wrapped I/O tool. It threads correlation (for inner
// sandbox auditing) and a decision recorder through the context; the audit
// decision comes from that recorder, while the existing deniedResult sentinel
// still drives the model-facing untrusted-framing (out of scope to change).
func (a *Agent) invokeIO(
	ctx context.Context, rs *runState, t schema.InvokableTool, tc schema.ToolCallBlock,
) (string, callOutcome, error) {
	ctx, dec := audit.WithDecision(ctx)
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: a.sessionID, RunID: rs.runID, Depth: rs.depth})
	ctx, fail := audit.WithFailure(ctx)

	// Fail-closed guard: if the operator interrupted since the dispatch loop
	// checked, skip the credentialed I/O tool entirely. The caller's post-dispatch
	// interrupt check then propagates errInterrupted (like a budget denial, this is
	// returned unframed — it is a host control signal, not untrusted tool output).
	if a.interrupted() {
		return deniedInterruptResult, callOutcome{
			decision: audit.DecisionDenied, outcome: audit.OutcomeDenied, result: deniedInterruptResult,
		}, nil
	}

	// A graceful stop during the call cancels its context, so a long-running
	// code_execution script stops launching further http_request calls promptly
	// instead of running to its own timeout before the post-dispatch halt (issue #270).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := a.cancelOnInterrupt(cancel, interruptPollInterval)
	defer stop()

	out, err := t.Run(ctx, tc.Arguments)
	if err != nil {
		if errors.Is(err, audit.ErrLog) {
			return "", callOutcome{}, err //nolint:exhaustruct // fatal path ignores callOutcome.
		}
		msg := fmt.Sprintf("Error executing tool %q: %v", tc.Name, err)

		return msg, callOutcome{decision: decisionLabel(dec), outcome: audit.OutcomeError, result: msg}, nil
	}

	decision := decisionLabel(dec)
	// An I/O tool reports execution failures as a result string with a nil error
	// (so the model can self-correct); fail.Failed() surfaces that for the audit
	// outcome. A denial takes precedence.
	outcome := audit.OutcomeOK
	switch {
	case decision == audit.DecisionDenied:
		outcome = audit.OutcomeDenied
	case fail.Failed():
		outcome = audit.OutcomeError
	}

	// Framing: a denial is a trusted host/user control signal — return it
	// unframed. Uses the existing sentinel (issue #160; out of scope to change).
	ret := wrapUntrusted(tc.Name, out)
	if a.deniedResult != "" && out == a.deniedResult {
		ret = out
	}

	return ret, callOutcome{
		decision: decision, outcome: outcome, result: out,
		failures: fail.Count(), progress: fail.Progress(),
	}, nil
}

// decisionLabel maps the approval recorder to an audit decision; an undecided
// recorder (no approval gate hit) defaults to approved.
func decisionLabel(d *audit.Decision) string {
	switch {
	case d.Decided && !d.Approved:
		return audit.DecisionDenied
	case d.Session:
		return audit.DecisionApprovedSession
	default:
		return audit.DecisionApproved
	}
}
