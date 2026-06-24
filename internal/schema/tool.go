package schema

import (
	"context"

	"github.com/invopop/jsonschema"
)

// ToolInfo is the schema a model needs to call a tool: its name, a description,
// and a JSON Schema for its argument object (nil when the tool takes none).
type ToolInfo struct {
	Name   string
	Desc   string
	Params *jsonschema.Schema
}

// InvokableTool is a host capability the model can invoke. Run receives the
// model's raw JSON argument string and returns the result string; an execution
// failure is returned as the result (not a Go error) so the loop can hand it to
// the model.
type InvokableTool interface {
	Info(ctx context.Context) (*ToolInfo, error)
	Run(ctx context.Context, argumentsInJSON string) (string, error)
}

// StructuredRunner is an optional interface a Tool may also implement to provide
// a JSON-structured result for the code_execution sandbox, while its normal Run
// output is unchanged. The returned string MUST be valid JSON.
type StructuredRunner interface {
	StructuredRun(ctx context.Context, argumentsInJSON string) (string, error)
}
