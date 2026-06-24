package tools

import (
	"context"
	"io"
	"time"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/sandbox"
	"github.com/cynative/cynative/internal/schema"
)

// Seam rule: construction-time seams (read once while building, e.g. schema
// builder, sandbox factory) are injected as functional options.

// WithHTTPSchemaBuilder returns a functional option that replaces the
// http_request parameter-schema builder. Used in tests to force the error path.
func WithHTTPSchemaBuilder(fn schemaBuilderFunc) httpRequestOption {
	return func(o *httpRequestOptions) { o.schemaBuilder = fn }
}

// WithHTTPMarshalJSON returns a functional option that replaces the JSON
// marshaller used by StructuredRun. Used in tests to force the marshal error path.
func WithHTTPMarshalJSON(fn marshalFunc) httpRequestOption {
	return func(o *httpRequestOptions) { o.marshalJSON = fn }
}

// NewCodeExecutionToolWithOpts exposes the variadic-options constructor for
// package-internal tests that need to inject seams (schema builder, sandbox factory).
// It forwards a nil sink so all 10 existing callers compile unchanged.
func NewCodeExecutionToolWithOpts(
	inner []schema.InvokableTool,
	verbose io.Writer,
	maxConcurrency int,
	opts ...codeExecOption,
) (schema.InvokableTool, error) {
	return newCodeExecutionToolWithOpts(inner, verbose, maxConcurrency, nil, opts...)
}

// NewCodeExecutionToolWithSink exposes the constructor with an explicit audit
// sink for the inner-call auditing tests.
func NewCodeExecutionToolWithSink(
	inner []schema.InvokableTool,
	verbose io.Writer,
	maxConcurrency int,
	sink audit.Sink,
	opts ...codeExecOption,
) (schema.InvokableTool, error) {
	return newCodeExecutionToolWithOpts(inner, verbose, maxConcurrency, sink, opts...)
}

// CodeRunner re-exports the unexported codeRunner interface for tests.
type CodeRunner = codeRunner

// RunnerFunc adapts a function to codeRunner for tests.
type RunnerFunc func(ctx context.Context, code string, timeout time.Duration) (string, error)

// Run satisfies codeRunner.
func (f RunnerFunc) Run(ctx context.Context, code string, timeout time.Duration) (string, error) {
	return f(ctx, code, timeout)
}

// WithCodeArgsSchema injects a replacement schema builder for codeArgs.
func WithCodeArgsSchema(fn schemaBuilderFunc) codeExecOption {
	return func(o *codeExecOptions) { o.codeArgsSchema = fn }
}

// WithCodeSandboxFactory injects a replacement sandbox factory.
func WithCodeSandboxFactory(fn func(map[string]sandbox.ToolFunc, io.Writer, int) (codeRunner, error)) codeExecOption {
	return func(o *codeExecOptions) { o.newSandbox = fn }
}

// WithCodeIDFunc injects the inner call-ID generator for deterministic tests.
func WithCodeIDFunc(fn func() string) codeExecOption {
	return func(o *codeExecOptions) { o.newID = fn }
}
