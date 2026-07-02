package tools

import (
	"context"
	"io"
	"time"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/sandbox"
	"github.com/cynative/cynative/internal/schema"
)

// Seam rule: construction-time seams (read once while building, e.g. the
// sandbox factory) are injected as functional options.

// NewCodeExecutionToolWithOpts exposes the variadic-options constructor for
// package-internal tests that need to inject seams (sandbox factory, ID func).
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

// WithCodeSandboxFactory injects a replacement sandbox factory.
func WithCodeSandboxFactory(fn func(map[string]sandbox.ToolFunc, io.Writer, int) (codeRunner, error)) codeExecOption {
	return func(o *codeExecOptions) { o.newSandbox = fn }
}

// WithCodeIDFunc injects the inner call-ID generator for deterministic tests.
func WithCodeIDFunc(fn func() string) codeExecOption {
	return func(o *codeExecOptions) { o.newID = fn }
}
