//go:generate go tool moq -out codeexec_mock_test.go . codeRunner

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/invopop/jsonschema"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/sandbox"
	"github.com/cynative/cynative/internal/schema"
)

// Compile-time assertion: codeExecutionTool implements InvokableTool.
var _ schema.InvokableTool = (*codeExecutionTool)(nil)

const (
	codeExecutionName  = "code_execution"
	codeMaxOutputBytes = 32 * 1024
	emptyObject        = "{}"
)

const (
	minCodeTimeoutSeconds     = 1
	maxCodeTimeoutSeconds     = 600
	defaultCodeTimeoutSeconds = 120
)

// codeRunner is the subset of *sandbox.Sandbox the tool drives.
type codeRunner interface {
	Run(ctx context.Context, code string, timeout time.Duration) (string, error)
}

// codeArgs is the code_execution tool's argument schema.
type codeArgs struct {
	Code           string `json:"code"                      jsonschema_description:"JavaScript to run on the sobek engine (see this tool's description for runtime, helpers, and response shapes). console.log(...) to return output; tool functions are async — await them. State persists across calls only via globalThis; let/const/var/function are scoped to one call."` //nolint:lll // struct tags are indivisible
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema_description:"Execution timeout in seconds (1-600, default 120)."`
}

// toolDesc captures what the description needs from each exposed inner tool.
type toolDesc struct {
	name   string
	desc   string
	params *jsonschema.Schema
}

// codeExecOptions holds the configurable seams for NewCodeExecutionTool.
type codeExecOptions struct {
	codeArgsSchema schemaBuilderFunc
	newSandbox     func(map[string]sandbox.ToolFunc, io.Writer, int) (codeRunner, error)
	newID          func() string
}

// codeExecOption is a functional option for NewCodeExecutionTool.
type codeExecOption func(*codeExecOptions)

// codeExecutionTool runs model-authored JavaScript that can call the other tools
// programmatically. The backing sandbox persists across calls within a session.
type codeExecutionTool struct {
	info    *schema.ToolInfo
	sandbox codeRunner
}

// NewCodeExecutionTool builds the code_execution tool, exposing each inner tool
// as a JS function. sink, when non-nil, receives an attempt+result audit record
// for every inner tool call executed inside a script. verbose, when non-nil,
// receives a line per inner tool call. maxConcurrency caps how many inner tool
// calls run simultaneously inside one script (non-positive values are clamped by
// sandbox.New).
func NewCodeExecutionTool(
	inner []schema.InvokableTool,
	verbose io.Writer,
	maxConcurrency int,
	sink audit.Sink,
) (schema.InvokableTool, error) {
	return newCodeExecutionToolWithOpts(inner, verbose, maxConcurrency, sink)
}

// newCodeExecutionToolWithOpts is the real constructor, accepting an explicit
// audit sink and optional seam overrides via functional options.
func newCodeExecutionToolWithOpts(
	inner []schema.InvokableTool,
	verbose io.Writer,
	maxConcurrency int,
	sink audit.Sink,
	opts ...codeExecOption,
) (schema.InvokableTool, error) {
	o := &codeExecOptions{
		codeArgsSchema: func() (*jsonschema.Schema, error) {
			return schema.ReflectParams[codeArgs]()
		},
		newSandbox: func(funcs map[string]sandbox.ToolFunc, w io.Writer, mc int) (codeRunner, error) {
			// RedactPreservingLocation (not Redact): sandbox tool results are HTTP
			// responses whose signed Location URL must survive for redirect-following.
			return sandbox.New(funcs, w, codeMaxOutputBytes, mc, redact.New().RedactPreservingLocation)
		},
		newID: uuid.NewString,
	}

	for _, opt := range opts {
		opt(o)
	}

	funcs, descs, err := buildToolFuncs(inner, sink, o.newID)
	if err != nil {
		return nil, err
	}

	params, err := o.codeArgsSchema()
	if err != nil {
		return nil, fmt.Errorf("tools: build code_execution schema: %w", err)
	}

	sb, err := o.newSandbox(funcs, verbose, maxConcurrency)
	if err != nil {
		return nil, fmt.Errorf("tools: build sandbox: %w", err)
	}

	return &codeExecutionTool{
		info: &schema.ToolInfo{
			Name:   codeExecutionName,
			Desc:   codeDescription(descs, json.Marshal),
			Params: params,
		},
		sandbox: sb,
	}, nil
}

// Info returns the tool's schema.
func (t *codeExecutionTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return t.info, nil
}

// Run runs the script. Execution failures are returned as the tool result (not a
// Go error) so the model can self-correct. A fatal audit-write error (from an
// inner loggingToolFunc) is surfaced as a Go error to abort the run.
func (t *codeExecutionTool) Run(ctx context.Context, argumentsInJSON string) (string, error) {
	var args codeArgs
	if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
		audit.MarkFailed(ctx)

		return fmt.Sprintf("Error: invalid code_execution arguments: %v", err), nil
	}

	ctx, fatal := audit.WithFatal(ctx)

	out, err := t.sandbox.Run(ctx, args.Code, clampCodeTimeout(args.TimeoutSeconds))
	// The sandbox waits for all in-flight workers before returning, so a fatal
	// audit failure latched by any inner call is visible here. Surface it as a
	// Go error (ErrLog-wrapped) so the agent loop aborts the run.
	if ferr := fatal.Err(); ferr != nil {
		return "", ferr
	}
	if err != nil {
		// A script failure (syntax/runtime/timeout/rejection) is signaled as
		// sandbox.ErrScript with the full diagnostic already in out; hand that to the
		// model. Mark the audit outcome failed — but only when no inner call already
		// recorded a failure, so an uncaught inner http_request error (already counted
		// and propagated) is not double-counted toward the halt (issue #270).
		if f, ok := audit.FailureFrom(ctx); !ok || f.Count() == 0 {
			audit.MarkFailed(ctx)
		}
		if errors.Is(err, sandbox.ErrScript) {
			return out, nil
		}

		return fmt.Sprintf("Error executing code: %v", err), nil
	}

	return out, nil
}

// buildToolFuncs maps each inner tool to a sandbox function and a description
// entry, excluding code_execution itself.
func buildToolFuncs(
	inner []schema.InvokableTool,
	sink audit.Sink,
	newID func() string,
) (map[string]sandbox.ToolFunc, []toolDesc, error) {
	ctx := context.Background()
	funcs := make(map[string]sandbox.ToolFunc, len(inner))
	descs := make([]toolDesc, 0, len(inner))

	for _, it := range inner {
		info, err := it.Info(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("tools: read inner tool info: %w", err)
		}

		if info.Name == codeExecutionName {
			continue
		}

		funcs[info.Name] = loggingToolFunc(it, info.Name, sink, newID)
		descs = append(descs, toolDesc{name: info.Name, desc: info.Desc, params: info.Params})
	}

	return funcs, descs, nil
}

// innerResultDecision returns the audit decision to stamp on an inner result
// record: approved_session when the outer code_execution was approved via a
// standing session grant, and approved otherwise.
func innerResultDecision(ctx context.Context) string {
	if audit.SessionApproved(ctx) {
		return audit.DecisionApprovedSession
	}

	return audit.DecisionApproved
}

// loggingToolFunc wraps the base sandbox adapter so each inner tool call is
// audited (attempt before the action, result after). When sink is nil it returns
// the unwrapped adapter unchanged. A fatal audit-write error is latched on the
// context's Fatal so code_execution.Run can abort the whole run.
func loggingToolFunc(it schema.InvokableTool, name string, sink audit.Sink, newID func() string) sandbox.ToolFunc {
	base := invokerToToolFunc(it)
	if sink == nil {
		return base
	}

	return func(ctx context.Context, argsJSON string) (string, error) {
		scope, _ := audit.ScopeFrom(ctx)
		fatal, hasFatal := audit.FatalFrom(ctx)
		if hasFatal {
			if ferr := fatal.Err(); ferr != nil {
				return "", ferr // A sibling already latched a fatal audit failure; refuse to run.
			}
		}

		callID := newID()
		attempt := audit.Record{ //nolint:exhaustruct // attempt carries no decision/outcome/result.
			SessionID: scope.SessionID, RunID: scope.RunID, CallID: callID, Depth: scope.Depth,
			Phase: audit.PhaseAttempt, Via: audit.ViaCodeExecution, Tool: name,
			Arguments: audit.RawArgs(argsJSON), RedactArgs: true,
		}
		if err := sink.Log(attempt); err != nil {
			if hasFatal {
				fatal.Set(err)
			}

			return "", err // Attempt-write failed: do NOT run the inner action (fail-closed).
		}

		inner := runInnerCall(ctx, base, argsJSON)

		result := audit.Record{ //nolint:exhaustruct // remaining fields irrelevant for a result.
			SessionID: scope.SessionID, RunID: scope.RunID, CallID: callID, Depth: scope.Depth,
			Phase: audit.PhaseResult, Via: audit.ViaCodeExecution, Tool: name,
			Arguments: audit.RawArgs(argsJSON), Decision: innerResultDecision(ctx), RedactArgs: true,
			Outcome: inner.outcome, Result: inner.result,
		}
		if err := sink.Log(result); err != nil {
			if hasFatal {
				fatal.Set(err)
			}

			return "", err
		}

		return inner.out, inner.err
	}
}

// innerOutcome is one audited inner sandbox call's result: its output, error, and the
// classified audit outcome/result strings.
type innerOutcome struct {
	out     string
	err     error
	outcome string
	result  string
}

// runInnerCall executes one inner tool under its own failure recorder so a 4xx (a
// failure with no Go error) shows up in this call's audit outcome rather than "ok", then
// propagates that recorder's tallies to the outer code_execution recorder (a per-call
// recorder, not a shared-counter delta, so concurrent siblings do not race) and
// classifies the outcome.
func runInnerCall(ctx context.Context, base sandbox.ToolFunc, argsJSON string) innerOutcome {
	innerCtx, innerFail := audit.WithFailure(ctx)
	out, rerr := base(innerCtx, argsJSON)
	for range innerFail.Count() {
		audit.MarkFailed(ctx)
	}
	for range innerFail.Progress() {
		audit.MarkProgress(ctx)
	}

	switch {
	case rerr != nil:
		return innerOutcome{out: out, err: rerr, outcome: audit.OutcomeError, result: rerr.Error()}
	case innerFail.Failed():
		// A rejected response (4xx/5xx) — the body is still the result.
		return innerOutcome{out: out, err: nil, outcome: audit.OutcomeError, result: out}
	default:
		return innerOutcome{out: out, err: nil, outcome: audit.OutcomeOK, result: out}
	}
}

// invokerToToolFunc adapts an InvokableTool to a sandbox.ToolFunc. When the tool
// also implements StructuredRunner, the sandbox-facing call uses the structured
// (JSON) result so the script receives an object; the tool's direct Run output is
// unchanged.
func invokerToToolFunc(it schema.InvokableTool) sandbox.ToolFunc {
	if sr, ok := it.(schema.StructuredRunner); ok {
		return func(ctx context.Context, argsJSON string) (string, error) {
			return sr.StructuredRun(ctx, argsJSON)
		}
	}

	return func(ctx context.Context, argsJSON string) (string, error) {
		return it.Run(ctx, argsJSON)
	}
}

// schemaJSON renders a parameter schema to a compact JSON string, or "{}".
func schemaJSON(p *jsonschema.Schema, marshal func(any) ([]byte, error)) string {
	if p == nil {
		return emptyObject
	}

	b, err := marshal(p)
	if err != nil {
		return emptyObject
	}

	return string(b)
}

// clampCodeTimeout bounds the requested timeout, falling back to the default.
func clampCodeTimeout(seconds int) time.Duration {
	if seconds < minCodeTimeoutSeconds || seconds > maxCodeTimeoutSeconds {
		seconds = defaultCodeTimeoutSeconds
	}

	return time.Duration(seconds) * time.Second
}

// codeDescription builds the tool description from the exposed functions.
func codeDescription(descs []toolDesc, marshal func(any) ([]byte, error)) string {
	var b strings.Builder

	b.WriteString(codeExecPreamble)

	for _, d := range descs {
		fmt.Fprintf(
			&b,
			"\n- %s(args): %s\n  args JSON schema: %s\n",
			d.name,
			d.desc,
			schemaJSON(d.params, marshal),
		)
	}

	return b.String()
}

const codeExecPreamble = "Run JavaScript in a sandbox — the only way to execute code here. Use it to (1) compute and " +
	"shape data: math, date/time calculations, parsing, transforming, filtering, aggregating, formatting; and " +
	"(2) drive the host tools below programmatically — call them in a loop, filter and chain their results, and " +
	"do many dependent calls in one script without a round-trip per call (feed list/describe results straight " +
	"into the follow-up calls). Answer directly when you already know the answer (well-known facts, trivial " +
	"arithmetic); use this tool to compute or transform values you don't have (the current date/time, " +
	"non-trivial or precision-sensitive math, parsing/reshaping data) and to orchestrate multi-step or " +
	"multi-call work — but for a single host-tool request with no computation, call that tool directly instead " +
	"of wrapping it in a script. Only what you console.log(...) is returned; a tool result that is JSON " +
	"arrives as an object, otherwise a string.\n\n" +
	"Runtime: the sobek engine — ECMAScript 5.1 plus most of ES2015 (ES6); arrow functions, let/const, " +
	"template strings, async/await, Promises, and top-level await all work. It is NOT Node or a browser: no " +
	"fetch, require, filesystem, timers, URLSearchParams, or Buffer — build query strings with " +
	"encodeURIComponent and use the tool functions for all I/O.\n" +
	"- Tool functions are ASYNC — await them. Run independent calls concurrently with mapConcurrent (below) " +
	"or await Promise.all([...]) for a small fixed set.\n" +
	"- http_request resolves to {status, statusText, headers, body, truncated}: body is the raw string — " +
	"JSON.parse(resp.body) for JSON, xml.parse(resp.body) for XML (AWS query APIs, SOAP, SAML). If truncated, " +
	"body was cut at max_response_body_size (default 32768, max 10485760 bytes); raise it to fetch more. " +
	"Redirects are not followed — a 3xx resolves normally; follow headers.Location[0] with a new http_request " +
	"if the target host is authorized.\n" +
	"- xml.parse(str) → object (SYNC; throws on bad input). Leaf text is always a STRING (<n>5</n> → " +
	"{n:\"5\"}, coerce with Number(...)); attributes use the -name key, text #text. A repeated tag is an " +
	"ARRAY but a single occurrence is an OBJECT — normalize, e.g. [].concat(parent.member ?? []).\n" +
	"- jmespath.search(data, expr) → value or null (SYNC; throws on bad input). Same language as aws --query; " +
	"e.g. jmespath.search(JSON.parse(resp.body), 'items[].name').\n" +
	"- mapConcurrent(items, fn, limit) → Promise of results in input order (ASYNC; await it). Runs " +
	"fn(item, index) with at most limit concurrent calls (omit limit for the host cap); stops launching after " +
	"the first failure and rethrows. Prefer it for fanning out over many resources.\n" +
	"- State persists across code_execution calls ONLY via globalThis.x = …; top-level let/const/var/function " +
	"are scoped to a single call.\n\n" +
	"Available functions (call as JS functions; each takes one arguments object and returns a Promise):\n"
