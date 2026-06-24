package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/sandbox"
	"github.com/cynative/cynative/internal/schema"
)

// probeArgs is the schema for the fake inner tool used in these tests.
type probeArgs struct {
	X int `json:"x" jsonschema_description:"a number"`
}

// fakeInnerTool is a stand-in InvokableTool.
type fakeInnerTool struct {
	name    string
	desc    string
	infoErr error
	runOut  string
}

func (f *fakeInnerTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	if f.infoErr != nil {
		return nil, f.infoErr
	}

	params, err := schema.ReflectParams[probeArgs]()
	if err != nil {
		return nil, err
	}

	return &schema.ToolInfo{
		Name:   f.name,
		Desc:   f.desc,
		Params: params,
	}, nil
}

func (f *fakeInnerTool) Run(_ context.Context, _ string) (string, error) {
	return f.runOut, nil
}

// structuredFake implements both InvokableTool and StructuredRunner, so
// invokerToToolFunc should prefer StructuredRun over Run.
type structuredFake struct{}

func (structuredFake) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "fake"}, nil //nolint:exhaustruct // minimal
}

func (structuredFake) Run(_ context.Context, _ string) (string, error) {
	return "DUMP", nil
}

func (structuredFake) StructuredRun(_ context.Context, _ string) (string, error) {
	return `{"structured":true}`, nil
}

func TestInvokerToToolFunc_PrefersStructured(t *testing.T) {
	t.Parallel()

	it := structuredFake{}

	fn := invokerToToolFunc(it)

	out, err := fn(context.Background(), `{"x":1}`)
	if err != nil {
		t.Fatalf("fn: %v", err)
	}

	if out != `{"structured":true}` {
		t.Errorf("out = %q, want structured result", out)
	}
}

func TestNewCodeExecutionTool_Info(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}

	tl, err := NewCodeExecutionToolWithOpts(
		[]schema.InvokableTool{&fakeInnerTool{name: "probe", desc: "a probe"}},
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	info, err := tl.Info(context.Background())
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	if info.Name != codeExecutionName {
		t.Errorf("name = %q", info.Name)
	}

	for _, want := range []string{
		"probe(args)", "a probe", "await", "globalThis", `"x"`,
		"mapConcurrent(items, fn, limit)",
		"Run JavaScript",          // general-purpose lead (recognition fix)
		"compute and shape data",  // general-compute framing, not only tool-calling
		"call that tool directly", // single I/O goes direct, not wrapped in a script (approval granularity)
	} {
		if !strings.Contains(info.Desc, want) {
			t.Errorf("description missing %q; got: %s", want, info.Desc)
		}
	}

	// The general-purpose lead must precede the host-tools framing, so a model
	// scanning the description sees "run general JS" before "call host tools".
	if lead, host := strings.Index(info.Desc, "Run JavaScript"),
		strings.Index(info.Desc, "host tools"); lead < 0 || host < 0 || lead > host {
		t.Errorf("description must lead with general JS before host tools: lead=%d host=%d", lead, host)
	}

	if info.Params == nil {
		t.Fatal("expected parameter schema")
	}
}

func TestNewCodeExecutionTool_SelfExclusion(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}

	tl, err := NewCodeExecutionToolWithOpts(
		[]schema.InvokableTool{&fakeInnerTool{name: codeExecutionName, desc: "self"}},
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	info, _ := tl.Info(context.Background())
	if strings.Contains(info.Desc, codeExecutionName+"(args)") {
		t.Errorf("code_execution should not be exposed inside itself: %s", info.Desc)
	}
}

func TestNewCodeExecutionTool_InfoError(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}

	//nolint:exhaustruct // only infoErr matters
	inner := []schema.InvokableTool{&fakeInnerTool{infoErr: errors.New("boom")}}

	_, err := NewCodeExecutionToolWithOpts(
		inner,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)
	if err == nil {
		t.Fatal("expected inner Info error")
	}
}

func TestNewCodeExecutionTool_SchemaError(t *testing.T) {
	t.Parallel()

	_, err := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeArgsSchema(func() (*jsonschema.Schema, error) { return nil, errors.New("schema boom") }),
	)
	if err == nil {
		t.Fatal("expected schema error")
	}
}

func TestNewCodeExecutionTool_SandboxError(t *testing.T) {
	t.Parallel()

	_, err := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return nil, errors.New("sandbox boom")
		}),
	)
	if err == nil {
		t.Fatal("expected sandbox error")
	}
}

func TestRun_Success(t *testing.T) {
	t.Parallel()

	var gotCode string

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, code string, _ time.Duration) (string, error) {
			gotCode = code
			return "OUTPUT", nil
		},
	}

	tl, _ := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)

	out, err := tl.Run(context.Background(), `{"code":"x()"}`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if out != "OUTPUT" || gotCode != "x()" {
		t.Errorf("out=%q gotCode=%q", out, gotCode)
	}
}

func TestRun_BadJSON(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}

	tl, _ := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)

	out, err := tl.Run(context.Background(), "not-json")
	if err != nil {
		t.Fatalf("should return result, not Go error: %v", err)
	}

	if !strings.Contains(out, "invalid code_execution arguments") {
		t.Errorf("got %q", out)
	}
}

func TestRun_RunnerError(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) {
			return "", errors.New("explode")
		},
	}

	tl, _ := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)

	out, err := tl.Run(context.Background(), `{"code":"x()"}`)
	if err != nil {
		t.Fatalf("should return result, not Go error: %v", err)
	}

	if !strings.Contains(out, "Error executing code") {
		t.Errorf("got %q", out)
	}
}

func TestRun_TimeoutClamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		secs int
		want time.Duration
	}{
		{"zero -> default", 0, defaultCodeTimeoutSeconds * time.Second},
		{"negative -> default", -1, defaultCodeTimeoutSeconds * time.Second},
		{"too large -> default", 9999, defaultCodeTimeoutSeconds * time.Second},
		{"min boundary -> as given", 1, 1 * time.Second},
		{"max boundary -> as given", 600, 600 * time.Second},
		{"valid -> as given", 30, 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotTO time.Duration

			mock := &codeRunnerMock{ //nolint:exhaustruct // captures timeout only
				RunFunc: func(_ context.Context, _ string, timeout time.Duration) (string, error) {
					gotTO = timeout
					return "", nil
				},
			}

			tl, _ := NewCodeExecutionToolWithOpts(
				nil,
				nil,
				sandbox.DefaultMaxConcurrency,
				WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
					return mock, nil
				}),
			)

			args := `{"code":"x","timeout_seconds":` + strconv.Itoa(tt.secs) + `}`
			if _, err := tl.Run(context.Background(), args); err != nil {
				t.Fatalf("run: %v", err)
			}

			if gotTO != tt.want {
				t.Errorf("timeout = %s, want %s", gotTO, tt.want)
			}
		})
	}
}

func TestSchemaJSON_Nil(t *testing.T) {
	t.Parallel()

	if got := schemaJSON(nil, json.Marshal); got != emptyObject {
		t.Errorf("got %q", got)
	}
}

func TestSchemaJSON_MarshalError(t *testing.T) {
	t.Parallel()

	params, _ := schema.ReflectParams[probeArgs]()

	errMarshal := func(any) ([]byte, error) { return nil, errors.New("boom") }

	if got := schemaJSON(params, errMarshal); got != emptyObject {
		t.Errorf("got %q", got)
	}
}

func TestCodeExecution_Integration(t *testing.T) {
	t.Parallel()

	// No stub: exercise the real sandbox, reflection, and dispatch end to end.
	//nolint:exhaustruct // optional fields unset
	inner := []schema.InvokableTool{&fakeInnerTool{name: "probe", runOut: "CANNED"}}

	tl, err := NewCodeExecutionTool(inner, nil, sandbox.DefaultMaxConcurrency, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	out, err := tl.Run(context.Background(), `{"code":"console.log(await probe({x:1}))"}`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(out, "CANNED") {
		t.Errorf("expected dispatched tool output, got %q", out)
	}
}

func TestNewCodeExecutionTool_ThreadsMaxConcurrency(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}

	var got int

	_, err := NewCodeExecutionToolWithOpts(
		nil,
		nil,
		42,
		WithCodeSandboxFactory(
			func(_ map[string]sandbox.ToolFunc, _ io.Writer, maxConcurrency int) (codeRunner, error) {
				got = maxConcurrency

				return mock, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if got != 42 {
		t.Errorf("maxConcurrency at the sandbox factory = %d, want 42", got)
	}
}

// secretTool returns a github-token-shaped value the production redactor catches.
type secretTool struct{}

func (secretTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "leak", Desc: "returns a secret", Params: nil}, nil
}

func (secretTool) Run(context.Context, string) (string, error) {
	return `{"token":"ghp_` + strings.Repeat("a", 36) + `"}`, nil
}

func TestCodeExecution_RedactsToolOutputEndToEnd(t *testing.T) {
	t.Parallel()

	tool, err := NewCodeExecutionTool([]schema.InvokableTool{secretTool{}}, nil, 1, nil)
	if err != nil {
		t.Fatalf("NewCodeExecutionTool: %v", err)
	}

	args := `{"code":"const r = await leak({}); console.log(r.token);"}`
	out, err := tool.Run(context.Background(), args)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out, "ghp_") {
		t.Fatalf("raw github token reached the script output: %q", out)
	}
	// Assert redaction occurred without pinning the exact label: the ghp_ token sits
	// in a "token" field, so the credential-field rule may relabel it.
	if !strings.Contains(out, "[REDACTED:") {
		t.Fatalf("expected a redaction placeholder, got %q", out)
	}
}

// TestCodeExecution_AuditResultIsRedacted pins the F6 resolution: even though
// loggingToolFunc captures the raw tool output into the audit Record *before*
// Layer 1 redacts, audit.Logger.Log redacts Record.Result itself (audit.go:140),
// so the persisted audit log never holds the raw token.
func TestCodeExecution_AuditResultIsRedacted(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	sink := audit.New(&buf, audit.WithActor("test"))

	tool, err := NewCodeExecutionTool([]schema.InvokableTool{secretTool{}}, nil, 1, sink)
	if err != nil {
		t.Fatalf("NewCodeExecutionTool: %v", err)
	}

	args := `{"code":"const r = await leak({}); console.log(r.token);"}`
	if _, runErr := tool.Run(context.Background(), args); runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}

	if got := buf.String(); strings.Contains(got, "ghp_") {
		t.Fatalf("raw github token persisted to the audit log: %q", got)
	}
	if !strings.Contains(buf.String(), "[REDACTED:") {
		t.Fatalf("expected a redaction placeholder in audit log, got %q", buf.String())
	}
}

func TestNewCodeExecutionTool_OptionalTimeout(t *testing.T) {
	t.Parallel()

	mock := &codeRunnerMock{ //nolint:exhaustruct // only RunFunc matters
		RunFunc: func(_ context.Context, _ string, _ time.Duration) (string, error) { return "", nil },
	}
	tl, err := NewCodeExecutionToolWithOpts(
		[]schema.InvokableTool{&fakeInnerTool{name: "probe", desc: "a probe"}},
		nil,
		sandbox.DefaultMaxConcurrency,
		WithCodeSandboxFactory(func(_ map[string]sandbox.ToolFunc, _ io.Writer, _ int) (codeRunner, error) {
			return mock, nil
		}),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	info, err := tl.Info(context.Background())
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	// Only `code` is required; `timeout_seconds` has a runtime default and must be optional.
	if got := info.Params.Required; len(got) != 1 || got[0] != "code" {
		t.Errorf("required = %v, want [code]", got)
	}
}
