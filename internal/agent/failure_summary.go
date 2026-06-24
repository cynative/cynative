package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/schema"
)

// stopSummaryDirective is appended (as a trusted host user message) before the
// tool-less summary turn that explains the wall to the operator.
const stopSummaryDirective = "You have stopped because you hit several consecutive tool " +
	"failures and appear to be stuck. Do NOT call any more tools. In 2-4 sentences for the " +
	"operator: (1) the wall you hit, (2) the specific input, credential, or decision you need " +
	"to proceed, and (3) a concrete recommended next step they can confirm with \"yes\" or by " +
	"supplying the value. Be direct; do not apologize at length."

// deterministicFailureNotice is the fallback answer when the summary turn errors or
// returns blank text — so the halt is never silently dropped from history (an empty
// completion would otherwise look like an iteration-limit exit).
const deterministicFailureNotice = "I stopped after repeated tool failures and could not " +
	"summarize the cause. Please check the required inputs (e.g. an account/project ID, region, " +
	"or credentials) and tell me how to proceed."

// syntheticHaltResult answers a tool call that was never dispatched because the run
// halted at the failure ceiling partway through a tool-call batch. It keeps the
// summary transcript well-formed (every assistant tool call has a matching tool
// result) so providers that require paired tool calls/results — OpenAI-style — accept
// the tool-less summary Generate instead of rejecting the request.
const syntheticHaltResult = "Tool not run: the turn halted after repeated tool failures."

// completePendingToolResults appends a synthetic tool result for every assistant tool
// call in turn that has no matching tool result, so the transcript is valid for the
// follow-up summary Generate. The halt can fire mid-batch, leaving the trailing
// assistant message with unanswered tool-call IDs; results are appended in tool-call
// order, after any real results already present.
func completePendingToolResults(turn []*schema.Message) []*schema.Message {
	answered := make(map[string]bool)
	for _, m := range turn {
		for _, tr := range m.ToolResults() {
			answered[tr.ToolCallID] = true
		}
	}
	for _, m := range turn {
		for _, tc := range m.ToolCalls() {
			if answered[tc.ID] {
				continue
			}
			turn = append(turn, schema.ToolMessage(syntheticHaltResult, tc.ID))
			answered[tc.ID] = true // answer a tool call once, even if an ID repeats.
		}
	}

	return turn
}

// failureSummary halts the run after maxConsecutiveFailures no-progress calls: it
// renders a host header, runs ONE tool-less Generate asking the model to name the wall
// and the missing input, and returns that as the turn's answer (recorded to history so
// an interactive follow-up resumes with context). A blank/errored completion falls back
// to a deterministic notice. An interrupt arriving before or during the summary wins; a
// context cancellation during the summary Generate propagates rather than degrading to a
// successful notice; and a budget cross on that Generate returns errBudgetExceeded.
func (a *Agent) failureSummary(ctx context.Context, rs *runState, turn []*schema.Message) (string, error) {
	if a.interrupted() {
		return "", errInterrupted
	}
	fmt.Fprintf(rs.out, "\n⏸  Stopped after %d consecutive failures — here's where I'm stuck:\n",
		a.maxConsecutiveFailures)

	// A mid-batch halt can leave the trailing assistant message with unanswered tool
	// calls; pair them with synthetic results so the summary Generate is a valid request.
	turn = completePendingToolResults(turn)
	turn = append(turn, schema.UserMessage(stopSummaryDirective))
	// Cancel the summary call on the first graceful stop too, like the main loop, so a
	// hung/slow summarize does not wait out the provider timeout (issue #270).
	gctx, gcancel := context.WithCancel(ctx)
	gstop := a.cancelOnInterrupt(gcancel, interruptPollInterval)
	msg, err := a.model.Generate(gctx, turn, nil) // nil tools — the model cannot call tools.
	gstop()
	gcancel()
	a.metrics.AddRoundTrip()
	// Post-Generate halt checks, in precedence order: interrupt (operator stop) wins,
	// then a context cancellation must propagate (not be converted into a stopped
	// summary the CLI would treat as success), then a budget cross — this Generate's
	// usage is recorded before it returns, so it can be the call that exhausts the
	// ceiling, and it returns the same sentinel Run renders the budget notice for.
	if a.interrupted() {
		return "", errInterrupted
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if a.metrics.BudgetExceeded() {
		return "", errBudgetExceeded
	}

	if err != nil {
		fmt.Fprintln(rs.out, deterministicFailureNotice)

		return deterministicFailureNotice, nil //nolint:nilerr // Generate error is not fatal; fall back to deterministic notice.
	}
	text := ""
	if msg != nil {
		text = strings.TrimSpace(msg.Text())
	}
	if text == "" {
		fmt.Fprintln(rs.out, deterministicFailureNotice)

		return deterministicFailureNotice, nil
	}
	a.renderTurn(msg, rs.out)

	// Mirror the loop's post-render final-answer check: a stop (or budget cross)
	// landing while the summary is written surfaces ErrInterrupted/130 instead of
	// recording the rendered summary and exiting 0.
	if herr := a.haltErr(); herr != nil {
		return "", herr
	}

	return msg.Text(), nil
}
