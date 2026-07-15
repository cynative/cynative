package agent

import (
	"context"
	"encoding/json"

	"github.com/cynative/cynative/internal/schema"
)

// taskArgs is the task tool's argument schema.
type taskArgs struct {
	Description  string `json:"description"             jsonschema_description:"The self-contained task for the sub-agent. It starts with a fresh context and returns only a summary."` //nolint:lll // schema tag
	SubagentType string `json:"subagent_type,omitempty" jsonschema_description:"Optional sub-agent type. Currently a single general sub-agent is available."`                           //nolint:lll // schema tag
}

// taskTool delegates a focused sub-investigation to a quarantined sub-agent run.
type taskTool struct {
	agent *Agent
	info  *schema.ToolInfo
}

var (
	_ schema.InvokableTool = (*taskTool)(nil)
	_ runScopedTool        = (*taskTool)(nil)
)

const taskToolName = "task"

const taskDesc = "Delegate a focused sub-investigation to a sub-agent that starts " +
	"with a clean context and returns only a concise result. Use this to keep your " +
	"main context focused when a step requires many tool calls."

// maxTaskDepth bounds sub-agent nesting: the top-level agent (depth 0) may spawn
// sub-agents, but a sub-agent (depth 1) may not delegate further. The sub-run
// reuses the same *Agent whose toolset includes the task tool (each run carries
// its depth on its own runState), so without this bound a sub-agent could call
// task → task → ... until stack exhaustion.
const maxTaskDepth = 1

// subagentDelegationGuidance is returned (as a tool result, not a Go error) when
// a sub-agent tries to delegate, so the model self-corrects and does the work
// inline instead of recursing.
const subagentDelegationGuidance = "Sub-agents cannot themselves delegate with task; " +
	"do the work directly in this sub-agent."

// newTaskTool builds the task tool bound to a.
func newTaskTool(a *Agent) *taskTool {
	return &taskTool{
		agent: a,
		info:  &schema.ToolInfo{Name: taskToolName, Desc: taskDesc, Params: schema.ReflectParams[taskArgs]()},
	}
}

// Info returns the tool's static schema.
func (t *taskTool) Info() *schema.ToolInfo {
	return t.info
}

// Run satisfies schema.InvokableTool; dispatch never calls it (runScoped is
// preferred), so it returns fixed guidance.
func (t *taskTool) Run(context.Context, string) (string, error) {
	return orchestrationOutsideLoop, nil
}

// runScoped starts a sub-agent with a fresh transcript (system prompt + the
// task description) and its own runState, drives it under the sub-agent
// iteration budget, and returns only its final summary. The sub-run is
// bracketed on the parent run's output: a start notice announcing the
// description, and a close notice on every return path after it (the error
// path must close too — dispatch converts the error into a tool result and the
// parent loop continues, so an open bracket would dangle).
//
// INVARIANT: the sub-run reuses the parent's toolset (the same *Agent
// receiver), so every credentialed I/O call a sub-agent makes still goes
// through the parent's approval-wrapped http_request/code_execution tools.
// task itself is surfaced, not approval-gated; that is only safe while this
// reuse holds. Guarded by TestIntegration_SubagentIOStaysGated.
func (t *taskTool) runScoped(ctx context.Context, rs *runState, argumentsInJSON string) (string, error) {
	// Depth guard: a sub-agent already at the max nesting depth must not delegate
	// further. rs.depth is immutable per run, so the guard is race-free under
	// concurrent sub-runs. Returned as a tool result (not a Go error) so the
	// model self-corrects.
	if rs.depth >= maxTaskDepth {
		return subagentDelegationGuidance, nil
	}

	var args taskArgs
	if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil || args.Description == "" {
		// Bad args come back as a guidance result string (not a Go error) so the
		// model can self-correct, matching the tool-result contract.
		return "Provide a non-empty 'description' for the sub-agent task.", nil //nolint:nilerr // see comment above.
	}

	t.agent.metrics.AddSubagent()

	seed := []*schema.Message{
		schema.SystemMessage(t.agent.systemPrompt),
		schema.UserMessage(args.Description),
	}

	// The sub-run gets its own state: elevated depth (immutable), the verbose
	// writer as its output, and a fresh plan.
	sub := &runState{depth: rs.depth + 1, out: t.agent.verboseWriter(), runID: rs.runID}

	t.agent.renderTaskStart(args.Description, rs.out)
	answer, err := t.agent.run(ctx, sub, seed, t.agent.maxSubagentIter)
	t.agent.renderTaskEnd(err == nil, rs.out)
	if err != nil {
		return "", err
	}
	if answer == "" {
		return "Sub-agent reached its iteration limit without a conclusion.", nil
	}

	// The summary is shaped by a sub-investigation of external data, so fence it
	// as untrusted to close the instruction-laundering path.
	return wrapUntrusted(taskToolName, answer), nil
}
