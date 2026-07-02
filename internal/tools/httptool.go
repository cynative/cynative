// Package tools defines the schema tools available to the research agent.
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/transport"
)

// Compile-time assertions: httpRequestTool implements InvokableTool and StructuredRunner.
var (
	_ schema.InvokableTool    = (*httpRequestTool)(nil)
	_ schema.StructuredRunner = (*httpRequestTool)(nil)
)

const httpRequestDescription = "Make a generic HTTP request. Redirects are NOT followed: a 3xx response " +
	"is returned as-is — read its Location header and issue a new request for that URL (its host must be " +
	"authorized for the chosen auth_provider)."

// statusFloor is the lowest HTTP status treated as a failed request outcome.
const statusFloor = 400

// schemaBuilderFunc is the type of a function that builds a *jsonschema.Schema.
type schemaBuilderFunc func() (*jsonschema.Schema, error)

// marshalFunc is the type of a function that marshals a value to JSON bytes.
type marshalFunc func(any) ([]byte, error)

// httpRequestOptions holds the configurable seams for NewHTTPRequestTool.
type httpRequestOptions struct {
	schemaBuilder schemaBuilderFunc
	marshalJSON   marshalFunc
}

// httpRequestOption is a functional option for NewHTTPRequestTool.
type httpRequestOption func(*httpRequestOptions)

// httpRequestTool is the schema tool that executes HTTP requests via transport.
// It forwards the model's raw JSON arguments to the transport Client unchanged
// so the auth layer receives the exact bytes it expects.
type httpRequestTool struct {
	info        *schema.ToolInfo
	providers   []auth.Provider
	marshalJSON marshalFunc
	client      *transport.Client
}

// NewHTTPRequestTool builds the http_request tool, capturing the auth providers
// for use during execution.
func NewHTTPRequestTool(providers []auth.Provider, opts ...httpRequestOption) (schema.InvokableTool, error) {
	o := &httpRequestOptions{
		schemaBuilder: func() (*jsonschema.Schema, error) {
			return schema.ReflectParams[transport.RequestArgs]()
		},
		marshalJSON: json.Marshal,
	}

	for _, opt := range opts {
		opt(o)
	}

	params, err := o.schemaBuilder()
	if err != nil {
		return nil, fmt.Errorf("tools: build http_request schema: %w", err)
	}

	return &httpRequestTool{
		info: &schema.ToolInfo{
			Name:   "http_request",
			Desc:   httpRequestDescription,
			Params: params,
		},
		providers:   providers,
		marshalJSON: o.marshalJSON,
		client:      transport.NewClient(),
	}, nil
}

// Info returns the tool's schema.
func (t *httpRequestTool) Info() *schema.ToolInfo {
	return t.info
}

// Run executes the HTTP request described by argumentsInJSON. Execution failures
// are returned as the tool result (not a Go error) so the model can self-correct;
// returning an error would abort the entire research run. The failure is also
// signaled via audit.MarkFailed so the audit record's outcome is not "ok".
func (t *httpRequestTool) Run(ctx context.Context, argumentsInJSON string) (string, error) {
	out, status, err := t.client.Execute(ctx, argumentsInJSON, t.providers)
	if err != nil {
		audit.MarkFailed(ctx)

		return fmt.Sprintf("Error executing tool: %v", err), nil
	}
	// A server rejection (4xx/5xx) is a non-OK outcome: surface it to the failure
	// recorder so the agent's consecutive-failure counter sees it. A
	// sub-4xx response is progress, so a mixed fan-out is not treated as stuck.
	if status >= statusFloor {
		audit.MarkFailed(ctx)
	} else {
		audit.MarkProgress(ctx)
	}

	return out, nil
}

// StructuredRun executes the request and returns the structured response as JSON.
// This is the entrypoint the code_execution sandbox invokes (invokerToToolFunc prefers
// StructuredRunner), so it mirrors Run's failure signaling: a 4xx/5xx is surfaced to
// the failure recorder, whose context descends from the outer code_execution call, so
// repeated blocked requests inside a script still trip the consecutive-failure halt
// instead of looking like successful inner calls.
func (t *httpRequestTool) StructuredRun(ctx context.Context, argumentsInJSON string) (string, error) {
	resp, err := t.client.ExecuteStructured(ctx, argumentsInJSON, t.providers)
	if err != nil {
		// A transport/auth/argument error is a no-progress outcome too (mirror Run), so a
		// script catching the rejected promise still trips the consecutive-failure halt.
		audit.MarkFailed(ctx)

		return "", err
	}
	if resp.Status >= statusFloor {
		audit.MarkFailed(ctx)
	} else {
		audit.MarkProgress(ctx)
	}

	b, err := t.marshalJSON(resp)
	if err != nil {
		return "", fmt.Errorf("tools: marshal structured response: %w", err)
	}

	return string(b), nil
}
