package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cynative/cynative/internal/schema"
)

// writeTodosArgs is the write_todos tool's argument schema.
type writeTodosArgs struct {
	Todos []todo `json:"todos" jsonschema_description:"The full, current todo list (replaces any previous list)."`
}

// writeTodosTool records and renders the agent's investigation plan.
type writeTodosTool struct {
	agent *Agent
	info  *schema.ToolInfo
}

var (
	_ schema.InvokableTool = (*writeTodosTool)(nil)
	_ runScopedTool        = (*writeTodosTool)(nil)
)

// orchestrationOutsideLoop is returned by the orchestration tools' public Run,
// which is unreachable via dispatch (the loop always calls runScoped); it
// exists only to satisfy schema.InvokableTool.
const orchestrationOutsideLoop = "This orchestration tool runs only inside the agent loop."

const writeTodosDesc = "Record or update your investigation plan as a todo list for genuinely " +
	"multi-step investigations; skip it when a single objective can be answered with one or two scripts. " +
	"Pass the FULL list each time (it replaces the previous list) and update it only when the plan " +
	"materially changes — don't spend a turn just to tick boxes."

// newWriteTodosTool builds the write_todos tool bound to a.
func newWriteTodosTool(a *Agent) *writeTodosTool {
	return &writeTodosTool{
		agent: a,
		info: &schema.ToolInfo{
			Name:   "write_todos",
			Desc:   writeTodosDesc,
			Params: schema.ReflectParams[writeTodosArgs](),
		},
	}
}

// Info returns the tool's static schema.
func (t *writeTodosTool) Info() *schema.ToolInfo {
	return t.info
}

// Run satisfies schema.InvokableTool; dispatch never calls it (runScoped is
// preferred), so it returns fixed guidance.
func (t *writeTodosTool) Run(context.Context, string) (string, error) {
	return orchestrationOutsideLoop, nil
}

// runScoped parses the (possibly double-encoded) todo list, renders it to the
// owning run's output, and acknowledges. A parse failure comes back as a
// result string so the model can retry.
func (t *writeTodosTool) runScoped(_ context.Context, rs *runState, argumentsInJSON string) (string, error) {
	todos, ok := parseTodos(argumentsInJSON)
	if !ok {
		return "Could not parse todos; pass {\"todos\":[{\"content\":...,\"status\":...}]}.", nil
	}

	t.agent.renderTodos(todos, rs.out)

	return fmt.Sprintf("Recorded %d todo(s).", len(todos)), nil
}

// parseTodos tolerates a string-encoded todos array (double-encoded by some
// models) and defaults a missing/blank status to pending. It returns ok=false
// only when the payload cannot be parsed at all.
func parseTodos(argsJSON string) ([]todo, bool) {
	var strict writeTodosArgs
	if err := json.Unmarshal([]byte(argsJSON), &strict); err == nil {
		return normalizeStatuses(strict.Todos), true
	}

	var wrapper struct {
		Todos string `json:"todos"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &wrapper); err != nil {
		return nil, false
	}
	var todos []todo
	if err := json.Unmarshal([]byte(wrapper.Todos), &todos); err != nil {
		return nil, false
	}

	return normalizeStatuses(todos), true
}

// normalizeStatuses defaults any unrecognized status to pending.
func normalizeStatuses(todos []todo) []todo {
	for i := range todos {
		switch todos[i].Status {
		case todoPending, todoInProgress, todoCompleted:
		default:
			todos[i].Status = todoPending
		}
	}

	return todos
}
