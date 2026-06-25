package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/interrupt"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/ui"
)

// fakeChatModel is a scripted schema.ChatModel for cli tests. It returns the
// scripted responses (or errs) in order from Generate; once both slices are
// exhausted it returns a benign final answer. The Generate counter persists on
// the receiver, so it survives across Generate calls and accumulates across
// interactive turns (the same instance is reused for the whole run).
type fakeChatModel struct {
	responses []*schema.Message
	errs      []error
	calls     int
}

var _ schema.ChatModel = (*fakeChatModel)(nil)

func (f *fakeChatModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	i := f.calls
	f.calls++

	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}

	if i < len(f.responses) {
		return f.responses[i], nil
	}

	return schema.AssistantMessage("done", nil), nil
}

func (f *fakeChatModel) Shutdown() {}

// ctxAwareModel always returns the context's error (for the cancellation test).
type ctxAwareModel struct{}

var _ schema.ChatModel = (*ctxAwareModel)(nil)

func (c *ctxAwareModel) Generate(
	ctx context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return schema.AssistantMessage("x", nil), nil
}

func (c *ctxAwareModel) Shutdown() {}

// footerRec records one RenderFooter call: its scope label and the stats rendered.
type footerRec struct {
	label string
	stats metrics.Stats
}

// fakeUI is a scripted researchUI that needs no terminal. PromptUserInput replays
// inputs in order (returning ("", false) — an EOF — once exhausted); the approval
// prompts always approve and RenderMessage writes the message text. promptCalls
// records how many times PromptUserInput was invoked.
type fakeUI struct {
	inputs         []string
	idx            int
	promptCalls    int
	lastPrompt     string
	footers        []footerRec
	bannerCalls    int
	connectorViews []ui.ConnectorView
	renderMsgCalls int
	llmStatuses    []ui.LLMStatus
	primeCalls     int
	order          []string
}

func (u *fakeUI) PromptToolApproval(_, _, _ string, _ bool) tools.Decision { return tools.ApproveOnce }

// RenderFooter records each footer call (label + stats) in order so tests can assert
// per-turn ("turn") vs once-per-session ("session") rendering.
func (u *fakeUI) RenderFooter(s metrics.Stats, label string) {
	u.footers = append(u.footers, footerRec{label: label, stats: s})
}

// footersByLabel returns, in order, the stats of every recorded footer with the label.
func (u *fakeUI) footersByLabel(label string) []metrics.Stats {
	var out []metrics.Stats
	for _, f := range u.footers {
		if f.label == label {
			out = append(out, f.stats)
		}
	}

	return out
}

func (u *fakeUI) RenderBanner(_ io.Writer) { u.bannerCalls++ }

func (u *fakeUI) RenderConnector(_ io.Writer, v ui.ConnectorView) {
	u.connectorViews = append(u.connectorViews, v)
}

func (u *fakeUI) RenderLLM(_ io.Writer, s ui.LLMStatus) {
	u.llmStatuses = append(u.llmStatuses, s)
}

func (u *fakeUI) PrimeBackground(_ string) {
	u.primeCalls++
	u.order = append(u.order, "prime")
}

func (u *fakeUI) AutoApproveToolCall(_, _, _ string, _ bool) tools.Decision { return tools.ApproveOnce }

func (u *fakeUI) PromptUserInput(prompt string) (string, bool) {
	u.promptCalls++
	u.lastPrompt = prompt

	if u.idx >= len(u.inputs) {
		return "", false
	}

	in := u.inputs[u.idx]
	u.idx++

	return in, true
}

// RenderMessage writes the message text to w so output-asserting tests can
// inspect what the agent rendered. The real glamour renderer does more, but the
// text is what these tests assert on.
func (u *fakeUI) RenderMessage(msg *schema.Message, _ string, w io.Writer) {
	u.order = append(u.order, "render")
	u.renderMsgCalls++
	_, _ = io.WriteString(w, msg.Text())
}

// assistantMsg returns an assistant message with the given text.
func assistantMsg(text string) *schema.Message {
	return schema.AssistantMessage(text, nil)
}

// validCfg returns a Config suitable for exercising runResearch.
func validCfg() config.Config {
	return config.Config{ //nolint:exhaustruct // only fields under test populated
		RenderStyle:           "dark",
		MaxIterations:         32,
		MaxSubagentIterations: 10,
		SandboxMaxConcurrency: 16,
		LLM: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
			Provider: "openai",
			Model:    "test-model",
			Keys: []schemas.Key{{ //nolint:exhaustruct // optional fields intentionally omitted
				ID:     "k",
				Name:   "k",
				Value:  schemas.SecretVar{Val: "test-key"},
				Models: schemas.WhiteList{"*"},
				Weight: 1.0,
			}},
		},
	}
}

// testDeps builds a *deps wired with deterministic fakes. Each test builds its own
// and overrides only the field it exercises, so no state is shared across tests.
// The chat model defaults to a benign scripted model; the http_request and
// code_execution tools and the agent are the real constructors.
func testDeps() *deps {
	d := &deps{
		loadConfig: func(string) (config.Config, error) { return validCfg(), nil },
		run:        nil, // set below to runResearch bound to the returned deps.
		getProviders: func(auth.HardeningConfig, bool, func(auth.ConnectorStatus)) []auth.Provider {
			return nil
		},
		newChatModel: func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
			return &fakeChatModel{}, nil //nolint:exhaustruct // benign default; tests override per case
		},
		newHTTPRequestTool: func(providers []auth.Provider) (schema.InvokableTool, error) {
			return tools.NewHTTPRequestTool(providers)
		},
		newCodeExecutionTool: tools.NewCodeExecutionTool,
		newAuditSink: func(config.Config) (audit.Sink, func() error, error) {
			return nil, func() error { return nil }, nil
		},
		newAgent:    agent.New,
		ui:          &fakeUI{}, //nolint:exhaustruct // empty script: PromptUserInput EOFs immediately
		out:         io.Discard,
		errOut:      io.Discard,
		cfg:         validCfg(),
		stdinIsTTY:  true,
		hasTerminal: true,
		readStdin:   func() (string, bool, error) { return "", false, nil },
		version:     "cynative 9.9.9\n  commit:   deadbeefcafe",
	}
	d.run = d.runResearch

	return d
}

func TestRunResearch(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("Hello World")},
		}, nil
	}
	d.out = &buf

	err := d.runResearch(
		context.Background(),
		"test task",
		validCfg(),
		researchFlags{}, //nolint:exhaustruct // defaults
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Hello") {
		t.Errorf("expected output to contain 'Hello', got: %q", buf.String())
	}
}

// captureHardening rewires d.getProviders to record the bundled HardeningConfig
// and the verbose flag it is called with, returning no providers/statuses.
func captureHardening(d *deps) *struct {
	cfg     auth.HardeningConfig
	verbose bool
} {
	rec := &struct {
		cfg     auth.HardeningConfig
		verbose bool
	}{} //nolint:exhaustruct // zero-init.
	d.getProviders = func(hc auth.HardeningConfig, verbose bool, _ func(auth.ConnectorStatus)) []auth.Provider {
		rec.cfg, rec.verbose = hc, verbose

		return nil
	}

	return rec
}

func TestStatusToView(t *testing.T) {
	t.Parallel()

	if v := statusToView(
		auth.ConnectorStatus{Name: "azure", Reason: "boom"},
	); v.State != ui.ConnectorError ||
		v.Posture != "boom" { //nolint:exhaustruct // skip.
		t.Errorf("error mapping wrong: %+v", v)
	}
	if v := statusToView(
		auth.ConnectorStatus{Name: "github", Available: true, Warn: true, Posture: "default=write", Identity: "@me"},
	); v.State != ui.ConnectorWarn { //nolint:exhaustruct // ok.
		t.Errorf("warn mapping wrong: %+v", v)
	}
	if v := statusToView(
		auth.ConnectorStatus{Name: "aws", Available: true, Posture: "SecurityAudit", Identity: "x"},
	); v.State != ui.ConnectorOK { //nolint:exhaustruct // ok.
		t.Errorf("ok mapping wrong: %+v", v)
	}
}

func TestRunResearch_PassesHardeningConfig(t *testing.T) {
	t.Parallel()

	d := testDeps()
	rec := captureHardening(d)
	cfg := validCfg()
	cfg.Cache.Dir = "/c"
	cfg.Connectors.AWS.Policy = "arn:aws:iam::aws:policy/SecurityAudit"
	cfg.Connectors.GCP.Role = "roles/viewer"
	cfg.Connectors.Azure.RoleDefinition = "Reader"
	cfg.Connectors.EKS.ClusterRole = "view"
	cfg.Connectors.Github.Permissions = map[string]string{"issues": "write"}

	if err := d.runResearch(
		context.Background(),
		"task",
		cfg,
		researchFlags{verbose: true},
	); err != nil { //nolint:exhaustruct // flags.
		t.Fatalf("runResearch: %v", err)
	}
	switch {
	case rec.cfg.AWS.PolicyARN != "arn:aws:iam::aws:policy/SecurityAudit":
		t.Errorf("AWS policy not threaded: %q", rec.cfg.AWS.PolicyARN)
	case rec.cfg.GCP.Role != "roles/viewer":
		t.Errorf("GCP role not threaded: %q", rec.cfg.GCP.Role)
	case rec.cfg.Azure.RoleDefinition != "Reader":
		t.Errorf("Azure role not threaded: %q", rec.cfg.Azure.RoleDefinition)
	case rec.cfg.EKS.ClusterRole != "view":
		t.Errorf("EKS cluster_role not threaded: %q", rec.cfg.EKS.ClusterRole)
	case !reflect.DeepEqual(rec.cfg.Github.Permissions, map[string]string{"issues": "write"}):
		t.Errorf("github permissions not threaded: %+v", rec.cfg.Github.Permissions)
	case !strings.HasSuffix(rec.cfg.Github.Config.Dir, "/github"):
		t.Errorf("github cache dir not namespaced: %q", rec.cfg.Github.Config.Dir)
	case !rec.verbose:
		t.Errorf("verbose not threaded")
	case !strings.HasSuffix(rec.cfg.AWS.Config.Dir, "/aws"):
		t.Errorf("aws cache dir not namespaced: %q", rec.cfg.AWS.Config.Dir)
	}
}

func TestRunResearch_StreamsConnectorViews(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		onStatus(
			auth.ConnectorStatus{
				Name:      "github",
				Available: true,
				Warn:      true,
				Posture:   "default=write",
				Identity:  "@me",
			},
		) //nolint:exhaustruct // display.
		onStatus(
			auth.ConnectorStatus{Name: "azure", Reason: "no usable credentials"},
		) //nolint:exhaustruct // skip.

		return nil
	}
	if err := d.runResearch(
		context.Background(),
		"task",
		validCfg(),
		researchFlags{},
	); err != nil { //nolint:exhaustruct // defaults.
		t.Fatalf("runResearch: %v", err)
	}
	if len(u.connectorViews) != 2 || u.connectorViews[0].State != ui.ConnectorWarn ||
		u.connectorViews[1].State != ui.ConnectorError {
		t.Fatalf("views=%+v, want [warn, error]", u.connectorViews)
	}
}

func TestNewResearchCmd_AutoApprove(t *testing.T) {
	t.Parallel()

	var gotFlags researchFlags

	d := testDeps()
	d.run = func(_ context.Context, _ string, _ config.Config, flags researchFlags) error {
		gotFlags = flags

		return nil
	}

	rootCmd := NewRootCmd(d)
	rootCmd.SetArgs([]string{"-p", "--auto-approve", "test task"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !gotFlags.autoApprove {
		t.Error("expected auto-approve flag to be set")
	}
}

func TestRunResearch_AutoApprove(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("Auto OK")},
		}, nil
	}
	d.out = &buf

	err := d.runResearch(
		context.Background(),
		"test",
		validCfg(),
		researchFlags{autoApprove: true}, //nolint:exhaustruct // only autoApprove under test
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Auto") {
		t.Errorf("expected 'Auto' in output, got: %q", buf.String())
	}
}

func TestRunResearch_VerboseFlag(t *testing.T) {
	t.Parallel()

	// Smoke test: verify that enabling --verbose doesn't break normal output.
	// The actual verbose tool-output writing is covered by the agent package.
	var buf bytes.Buffer

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("Verbose OK")},
		}, nil
	}
	d.out = &buf

	err := d.runResearch(
		context.Background(),
		"test",
		validCfg(),
		researchFlags{verbose: true}, //nolint:exhaustruct // only verbose under test
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Verbose") {
		t.Errorf("expected 'Verbose' in output, got: %q", buf.String())
	}
}

func TestRunResearch_HTTPToolError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newHTTPRequestTool = func([]auth.Provider) (schema.InvokableTool, error) {
		return nil, errors.New("schema boom")
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if err == nil {
		t.Fatal("expected error from http_request tool build")
	}

	if !strings.Contains(err.Error(), "build http_request tool") {
		t.Errorf("expected 'build http_request tool' in error, got: %v", err)
	}
}

func TestIsExitCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"exit", true},
		{"Exit", true},
		{"EXIT", true},
		{"quit", true},
		{"Quit", true},
		{"QUIT", true},
		{"", false},
		{"hello", false},
		{"exiting", false},
	}

	for _, tt := range tests {
		if got := isExitCommand(tt.input); got != tt.want {
			t.Errorf("isExitCommand(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestInteractiveLoop_ExitImmediately(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{inputs: []string{"exit"}} //nolint:exhaustruct // counters/lastPrompt start at zero

	d := testDeps()
	d.ui = ui

	// interactiveLoop should return nil immediately on "exit".
	err := d.interactiveLoop(context.Background(), nil, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The follow-up prompt must be the bare "> " prompt.
	if ui.lastPrompt != "\n> " {
		t.Errorf("follow-up prompt = %q, want %q", ui.lastPrompt, "\n> ")
	}
}

func TestInteractiveLoop_EOF(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.ui = &fakeUI{} //nolint:exhaustruct // empty script: PromptUserInput returns ("", false) = EOF

	err := d.interactiveLoop(context.Background(), nil, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInteractiveLoop_EmptyInputSkipped(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{inputs: []string{"", "quit"}} //nolint:exhaustruct // idx/promptCalls start at zero

	d := testDeps()
	d.ui = ui

	err := d.interactiveLoop(context.Background(), nil, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ui.promptCalls != 2 {
		t.Errorf("expected 2 calls to PromptUserInput, got %d", ui.promptCalls)
	}
}

func TestRunResearch_Interactive(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.ui = &fakeUI{inputs: []string{"exit"}} //nolint:exhaustruct // idx/promptCalls start at zero
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("Response")},
		}, nil
	}

	err := d.runResearch(
		context.Background(),
		"initial task",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunResearch_InteractiveMultiTurn(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{inputs: []string{"follow-up question", "exit"}} //nolint:exhaustruct // counters start at zero

	d := testDeps()
	d.ui = ui
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{
				assistantMsg("Turn 1"),
				assistantMsg("Turn 2"),
			},
		}, nil
	}

	err := d.runResearch(
		context.Background(),
		"initial task",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ui.promptCalls != 2 {
		t.Errorf("expected 2 input prompts (follow-up + exit), got %d", ui.promptCalls)
	}
}

func TestRunResearch_InteractiveInitialError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // responses unused
			errs: []error{errors.New("upstream failure")},
		}, nil
	}

	err := d.runResearch(
		context.Background(),
		"task",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test
	)
	if err == nil {
		t.Fatal("expected error from initial Run")
	}

	if !strings.Contains(err.Error(), "research run failed") {
		t.Errorf("expected 'research run failed' in error, got: %v", err)
	}
}

func TestRunResearch_ChatModelInitError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	fu := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return nil, errors.New("init failed")
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("chat-model init failure must return ErrLLMUnavailable, got: %v", err)
	}
	// The ✗ LLM status block must have been rendered.
	if len(fu.llmStatuses) != 1 || fu.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("expected one ✗ LLM status, got %#v", fu.llmStatuses)
	}
}

func TestInteractiveLoop_RunError_LogsAndContinues(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{inputs: []string{"follow-up", "exit"}} //nolint:exhaustruct // counters start at zero

	// The model errors on the first call; the loop should log and continue.
	a := newTestAgent(t, &fakeChatModel{ //nolint:exhaustruct // responses unused; only errs needed
		errs: []error{errors.New("transient fail")},
	})

	d := testDeps()
	d.ui = ui

	// The loop should log the error and continue, exiting cleanly.
	// established=true: the session was already live before this turn errored.
	err := d.interactiveLoop(context.Background(), a, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err != nil {
		t.Fatalf("expected nil error (log-and-continue), got: %v", err)
	}

	if ui.promptCalls != 2 {
		t.Errorf("expected 2 input prompts (error + exit), got %d", ui.promptCalls)
	}
}

func TestInteractiveLoop_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately.

	// Construct the agent with a live context so New succeeds, then drive the
	// loop with the cancelled context so a.Run observes the cancellation.
	a := newTestAgent(t, &ctxAwareModel{})

	d := testDeps()
	d.ui = &fakeUI{inputs: []string{"follow-up"}} //nolint:exhaustruct // counters start at zero

	err := d.interactiveLoop(ctx, a, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// newTestAgent builds a real agent backed by the given model for loop tests.
func newTestAgent(t *testing.T, m schema.ChatModel) *agent.Agent {
	t.Helper()

	a, err := agent.New(context.Background(), agent.Config{
		Model:         m,
		Cfg:           validCfg(),
		Tools:         nil,
		Providers:     nil,
		Renderer:      (&fakeUI{}).RenderMessage, //nolint:exhaustruct // no-op renderer
		VerboseWriter: nil,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	return a
}

func TestNewChatModel(t *testing.T) {
	t.Parallel()

	// Exercises the production chat-model factory wired by newDeps. Bifrost init
	// defers network work, so construction succeeds offline.
	cm, err := newDeps().newChatModel(context.Background(), validCfg(), func(schema.Usage) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Cleanup(cm.Shutdown)
}

func TestRunResearch_AgentInitError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // only the success path is needed here
			responses: []*schema.Message{assistantMsg("x")},
		}, nil
	}
	d.newAgent = func(context.Context, agent.Config, ...agent.Option) (*agent.Agent, error) {
		return nil, errors.New("agent boom")
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if err == nil {
		t.Fatal("expected error from agent init")
	}

	if !strings.Contains(err.Error(), "initialize agent") {
		t.Errorf("expected 'initialize agent' in error, got: %v", err)
	}
}

func TestRunResearch_CodeToolError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newCodeExecutionTool = func([]schema.InvokableTool, io.Writer, int, audit.Sink) (schema.InvokableTool, error) {
		return nil, errors.New("code boom")
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if err == nil {
		t.Fatal("expected error from code_execution tool build")
	}

	if !strings.Contains(err.Error(), "build code_execution tool") {
		t.Errorf("expected 'build code_execution tool' in error, got: %v", err)
	}
}

func TestRunResearch_ThreadsSandboxMaxConcurrency(t *testing.T) {
	t.Parallel()

	var got int

	d := testDeps()
	d.newCodeExecutionTool = func(
		primitives []schema.InvokableTool,
		verbose io.Writer,
		maxConcurrency int,
		sink audit.Sink,
	) (schema.InvokableTool, error) {
		got = maxConcurrency

		return tools.NewCodeExecutionTool(primitives, verbose, maxConcurrency, sink)
	}

	cfg := validCfg()
	cfg.SandboxMaxConcurrency = 5

	err := d.runResearch(context.Background(), "task", cfg, researchFlags{}) //nolint:exhaustruct // defaults
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	if got != 5 {
		t.Errorf("maxConcurrency passed to newCodeExecutionTool = %d, want 5", got)
	}
}

func TestJoinTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arg       string
		stdin     string
		truncated bool
		want      string
	}{
		{"arg only", "audit s3", "", false, "audit s3"},
		{"stdin only (unframed task)", "", "find leaks", false, "find leaks"},
		{"both framed", "review this", "data", false, "review this\n\n<piped_input>\ndata\n</piped_input>"},
		{
			"arg trimmed, piped context verbatim", "  review  ", "  data  ", false,
			"review\n\n<piped_input>\n  data  \n</piped_input>",
		},
		{"neither", "", "", false, ""},
		{"whitespace trims to empty", "   ", "  ", false, ""},
		{
			"truncated marker outside fence", "review", "big", true,
			"review\n\n<piped_input>\nbig\n</piped_input>\n[stdin truncated at 1 MiB]",
		},
		{"truncated but empty stdin -> no marker", "arg", "", true, "arg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := joinTask(tt.arg, tt.stdin, tt.truncated); got != tt.want {
				t.Errorf("joinTask(%q,%q,%v) = %q, want %q", tt.arg, tt.stdin, tt.truncated, got, tt.want)
			}
		})
	}
}

func TestResolveInvocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        invocationInputs
		wantTask  string
		wantInter bool
		wantErr   error
	}{
		{
			name:      "bare TTY -> interactive no seed",
			in:        invocationInputs{stdinIsTTY: true, hasTerminal: true}, //nolint:exhaustruct // sparse
			wantInter: true,
		},
		{
			name: "TTY + arg -> seeded interactive",
			in: invocationInputs{
				arg:         "task",
				stdinIsTTY:  true,
				hasTerminal: true,
			}, //nolint:exhaustruct // sparse
			wantTask:  "task",
			wantInter: true,
		},
		{
			name: "-p + arg -> one-shot",
			in: invocationInputs{ //nolint:exhaustruct // sparse
				printMode: true, arg: "task", stdinIsTTY: true, hasTerminal: true,
			},
			wantTask: "task",
		},
		{
			name: "-p + piped stdin -> one-shot",
			in: invocationInputs{
				printMode:   true,
				stdinData:   "task",
				hasTerminal: true,
			}, //nolint:exhaustruct // sparse
			wantTask: "task",
		},
		{
			name: "-p + arg + piped -> framed one-shot",
			in: invocationInputs{ //nolint:exhaustruct // sparse
				printMode: true, arg: "i", stdinData: "d", hasTerminal: true,
			},
			wantTask: "i\n\n<piped_input>\nd\n</piped_input>",
		},
		{
			name:     "piped no -p -> one-shot",
			in:       invocationInputs{stdinData: "task", hasTerminal: true}, //nolint:exhaustruct // sparse
			wantTask: "task",
		},
		{
			name: "-p no task -> ErrNoTask",
			in: invocationInputs{
				printMode:   true,
				stdinIsTTY:  true,
				hasTerminal: true,
			}, //nolint:exhaustruct // sparse
			wantErr: ErrNoTask,
		},
		{
			name:    "no task no terminal still ErrNoTask first",
			in:      invocationInputs{printMode: true}, //nolint:exhaustruct // sparse
			wantErr: ErrNoTask,
		},
		{
			name:    "task but no terminal -> ErrNoApprovalTerminal",
			in:      invocationInputs{printMode: true, arg: "task"}, //nolint:exhaustruct // sparse
			wantErr: ErrNoApprovalTerminal,
		},
		{
			name:     "task no terminal but auto-approve -> ok",
			in:       invocationInputs{printMode: true, arg: "task", autoApprove: true}, //nolint:exhaustruct // sparse
			wantTask: "task",
		},
		{
			name:    "interactive but no terminal -> ErrNoApprovalTerminal",
			in:      invocationInputs{stdinIsTTY: true}, //nolint:exhaustruct // sparse
			wantErr: ErrNoApprovalTerminal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveInvocation(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && (got.task != tt.wantTask || got.interactive != tt.wantInter) {
				t.Errorf("got {task:%q interactive:%v}, want {task:%q interactive:%v}",
					got.task, got.interactive, tt.wantTask, tt.wantInter)
			}
		})
	}
}

func TestRunResearch_BareInteractiveSkipsSeed(t *testing.T) {
	t.Parallel()

	// fakeChatModel.calls counts Generate invocations (defined in this test file).
	model := &fakeChatModel{} //nolint:exhaustruct // empty: only the calls counter is read
	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return model, nil
	}
	d.ui = &fakeUI{} //nolint:exhaustruct // empty script: PromptUserInput EOFs immediately -> loop exits

	err := d.runResearch(context.Background(), "", validCfg(),
		researchFlags{interactive: true}) //nolint:exhaustruct // autoApprove/verbose default false
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if model.calls != 0 {
		t.Errorf("expected no model calls for an empty-seed interactive run, got %d", model.calls)
	}
}

func TestRunResearch_PassesK8sClusterRoles(t *testing.T) {
	t.Parallel()

	d := testDeps()
	rec := captureHardening(d)

	cfg := validCfg()
	cfg.Connectors.EKS = config.ClusterRoleConfig{ClusterRole: "eks-reader"}
	cfg.Connectors.GKE = config.ClusterRoleConfig{ClusterRole: "gke-reader"}
	cfg.Connectors.AKS = config.ClusterRoleConfig{ClusterRole: "aks-reader"}
	cfg.Connectors.Kubernetes = config.ClusterRoleConfig{ClusterRole: "k8s-reader"}

	if err := d.runResearch(
		context.Background(),
		"task",
		cfg,
		researchFlags{},
	); err != nil { //nolint:exhaustruct // defaults.
		t.Fatalf("runResearch: %v", err)
	}

	switch {
	case rec.cfg.EKS.ClusterRole != "eks-reader":
		t.Errorf("EKS cluster_role not threaded: %q", rec.cfg.EKS.ClusterRole)
	case rec.cfg.GKE.ClusterRole != "gke-reader":
		t.Errorf("GKE cluster_role not threaded: %q", rec.cfg.GKE.ClusterRole)
	case rec.cfg.AKS.ClusterRole != "aks-reader":
		t.Errorf("AKS cluster_role not threaded: %q", rec.cfg.AKS.ClusterRole)
	case !reflect.DeepEqual(rec.cfg.Kubernetes, auth.KubernetesHardeningConfig{ClusterRole: "k8s-reader"}):
		t.Errorf("kubernetes config not threaded: %+v", rec.cfg.Kubernetes)
	}
}

func TestRunResearch_RendersFooter(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{} //nolint:exhaustruct // empty script: counters start at zero
	d := testDeps()
	d.ui = ui
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("answer")},
		}, nil
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	sessions := ui.footersByLabel("session")
	if len(sessions) != 1 {
		t.Fatalf("session footers = %d, want 1 (one-shot renders only a session footer)", len(sessions))
	}
	if got := ui.footersByLabel("turn"); len(got) != 0 {
		t.Errorf("turn footers = %d, want 0 for a one-shot run", len(got))
	}
	// The real agent ran one tool-call-free turn → exactly one round-trip recorded.
	if sessions[0].RoundTrips != 1 {
		t.Errorf("session footer round-trips = %d, want 1", sessions[0].RoundTrips)
	}
	if sessions[0].Provider != "openai" || sessions[0].Model != "test-model" {
		t.Errorf("footer provider/model = %q/%q", sessions[0].Provider, sessions[0].Model)
	}
}

func TestRunResearch_RendersFooterOnError(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{} //nolint:exhaustruct // empty script: counters start at zero
	d := testDeps()
	d.ui = ui
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // first call errors; responses unused
			errs: []error{errors.New("boom")},
		}, nil
	}

	err := d.runResearch(context.Background(), "task", validCfg(), researchFlags{}) //nolint:exhaustruct // defaults
	if err == nil {
		t.Fatal("expected error from runResearch")
	}
	sessions := ui.footersByLabel("session")
	if len(sessions) != 1 {
		t.Fatalf("session footers = %d, want 1 (rendered even on error)", len(sessions))
	}
	// The failed Generate attempt is still counted as a round-trip, so the gate passes.
	if sessions[0].RoundTrips != 1 {
		t.Errorf("session footer round-trips on error = %d, want 1", sessions[0].RoundTrips)
	}
}

func TestRunResearch_RendersFooterEachInteractiveTurn(t *testing.T) {
	t.Parallel()

	ui := &fakeUI{inputs: []string{"follow up", "exit"}} //nolint:exhaustruct // counters start at zero
	d := testDeps()
	d.ui = ui
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		// Each Generate returns a final answer, so every turn is one round-trip.
		return &fakeChatModel{}, nil //nolint:exhaustruct // benign default
	}

	if err := d.runResearch(
		context.Background(), "task", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test
	); err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	// Interactive: one "turn" footer per turn (seed "task" + "follow up") and exactly
	// one "session" footer at loop exit. The seeded run skips the welcome, so the
	// session covers two single-round-trip turns.
	turns := ui.footersByLabel("turn")
	if len(turns) != 2 {
		t.Fatalf("turn footers = %d, want 2 (seed + follow-up)", len(turns))
	}
	sessions := ui.footersByLabel("session")
	if len(sessions) != 1 {
		t.Fatalf("session footers = %d, want 1 (once at session end)", len(sessions))
	}
	// Per-turn footers are deltas: the second turn shows a single round-trip.
	if turns[1].RoundTrips != 1 {
		t.Errorf("second turn footer round-trips = %d, want 1 (per-turn delta)", turns[1].RoundTrips)
	}
	// The session footer is cumulative across both turns.
	if sessions[0].RoundTrips != 2 {
		t.Errorf("session footer round-trips = %d, want 2 (cumulative)", sessions[0].RoundTrips)
	}
}

// TestRunResearch_NoSessionFooterWhenNothingRan: a bare interactive session
// (no seed task) whose only input is "exit" — and with no connectors, so the
// welcome greeting is skipped — records zero round-trips, so the RoundTrips>0 gate
// suppresses the session footer entirely.
func TestRunResearch_NoSessionFooterWhenNothingRan(t *testing.T) {
	t.Parallel()

	u := &fakeUI{inputs: []string{"exit"}} //nolint:exhaustruct // counters zero.
	d := testDeps()                        // getProviders returns nil → welcome skipped → no round-trips.
	d.ui = u

	if err := d.runResearch(
		context.Background(), "", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	if n := len(u.footers); n != 0 {
		t.Errorf("footers = %d, want 0 (nothing ran → no summary)", n)
	}
}

// TestRunResearch_InteractiveSeedError_TurnFooterNoSession: an interactive seeded
// run whose seed errors (non-interrupt) returns the error before the follow-up loop
// is entered, so the seed's "turn" footer renders but the session-summary defer (in
// interactiveLoop) never runs — the documented "errors before loop" relabel edge.
func TestRunResearch_InteractiveSeedError_TurnFooterNoSession(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // counters zero; no follow-up inputs needed.
	d := testDeps()
	d.ui = u
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // first call errors; responses unused.
			errs: []error{errors.New("boom")},
		}, nil
	}

	err := d.runResearch(
		context.Background(), "task", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	if err == nil {
		t.Fatal("expected error from seeded interactive run")
	}
	if n := len(u.footersByLabel("turn")); n != 1 {
		t.Errorf("turn footers = %d, want 1 (seed turn)", n)
	}
	if n := len(u.footersByLabel("session")); n != 0 {
		t.Errorf("session footers = %d, want 0 (returned before the loop)", n)
	}
}

// TestRunResearch_InteractiveSeedInterruptBeforeGenerate_NoSessionFooter: a seed
// interrupted before its first Generate records zero round-trips; ErrInterrupted
// falls through into the loop, an immediate "exit" returns nil, and the gate
// (RoundTrips==0) correctly suppresses the session footer.
func TestRunResearch_InteractiveSeedInterruptBeforeGenerate_NoSessionFooter(t *testing.T) {
	t.Parallel()

	u := &fakeUI{inputs: []string{"exit"}} //nolint:exhaustruct // counters zero.
	d := testDeps()
	d.ui = u
	d.interrupter = trippedInterrupter{} // seed Run interrupts before first Generate → RoundTrips 0.

	if err := d.runResearch(
		context.Background(), "task", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	); err != nil {
		t.Fatalf("runResearch: %v (interrupt should fall through to loop; exit returns nil)", err)
	}
	if n := len(u.footersByLabel("turn")); n != 1 {
		t.Errorf("turn footers = %d, want 1 (interrupted seed still renders a turn footer)", n)
	}
	if n := len(u.footersByLabel("session")); n != 0 {
		t.Errorf("session footers = %d, want 0 (RoundTrips==0 gate suppresses it)", n)
	}
}

// TestInteractiveLoop_CancelledWithActivity_RendersSessionFooter: the spec
// invariant "interactive fatal-error/cancellation exit WITH activity → session
// footer still rendered." The cancelled turn records one round-trip (AddRoundTrip
// fires unconditionally after Generate, loop.go:95), the loop returns the error
// (ctx.Err()!=nil), and the deferred session footer renders because RoundTrips>0.
// The agent must be wired to the SAME acc so the round-trip lands where the gate
// reads it.
func TestInteractiveLoop_CancelledWithActivity_RendersSessionFooter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately; the turn's Generate observes it.

	acc := metrics.NewAccumulator("p", "m")
	a := newTestAgentWithMetrics(t, &ctxAwareModel{}, acc)

	u := &fakeUI{inputs: []string{"follow-up"}} //nolint:exhaustruct // counters zero.
	d := testDeps()
	d.ui = u

	err := d.interactiveLoop(ctx, a, acc, validCfg(), true)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	sessions := u.footersByLabel("session")
	if len(sessions) != 1 {
		t.Fatalf("session footers = %d, want 1 (rendered on fatal exit with activity)", len(sessions))
	}
	if sessions[0].RoundTrips != 1 {
		t.Errorf("session footer round-trips = %d, want 1", sessions[0].RoundTrips)
	}
	if n := len(u.footersByLabel("turn")); n != 1 {
		t.Errorf("turn footers = %d, want 1 (per-turn footer renders before the fatal return)", n)
	}
}

// newTestAgentWithMetrics mirrors newTestAgent but wires acc into Config.Metrics so
// loop tests can assert metrics-gated rendering (the agent records round-trips into acc).
func newTestAgentWithMetrics(t *testing.T, m schema.ChatModel, acc *metrics.Accumulator) *agent.Agent {
	t.Helper()

	a, err := agent.New(context.Background(), agent.Config{
		Model:         m,
		Cfg:           validCfg(),
		Tools:         nil,
		Providers:     nil,
		Renderer:      (&fakeUI{}).RenderMessage, //nolint:exhaustruct // no-op renderer.
		VerboseWriter: nil,
		Metrics:       acc,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	return a
}

func TestRunResearch_RendersBanner(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // counters zero.
	d := testDeps()
	d.ui = u
	err := d.runResearch(
		context.Background(), "task", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults.
	)
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	if u.bannerCalls != 1 {
		t.Errorf("RenderBanner called %d times, want 1", u.bannerCalls)
	}
}

// welcomeMarker is the unique text the welcome greeting carries so a test can
// tell the welcome render (to d.out) apart from the task answer.
const welcomeMarker = "WELCOME: try: list s3 buckets"

// welcomeDiscModel answers the welcome call with welcomeMarker and every other
// call (the seed task, interactive turns) with "task answer". It discriminates
// the welcome from the task by the last user message: the seed task's text is
// "task", so any other final user message is treated as the welcome. This keeps
// the marker out of output whenever the welcome is gated off, regardless of call
// order. failWelcome makes the welcome call error instead (welcome then skips).
type welcomeDiscModel struct {
	failWelcome bool
}

var _ schema.ChatModel = (*welcomeDiscModel)(nil)

func (m *welcomeDiscModel) Generate(
	_ context.Context,
	msgs []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	isWelcome := len(msgs) > 0 && msgs[len(msgs)-1].Text() != "task"
	if isWelcome {
		if m.failWelcome {
			return nil, errors.New("boom")
		}

		return assistantMsg(welcomeMarker), nil
	}

	return assistantMsg("task answer"), nil
}

func (m *welcomeDiscModel) Shutdown() {}

// loopbackProviders fires one available connector status whose name matches the
// returned provider, so the agent gets both a non-empty providers slice (the
// welcome gate) and a connector view (the meta map).
func loopbackProviders(onStatus func(auth.ConnectorStatus)) []auth.Provider {
	onStatus(auth.ConnectorStatus{ //nolint:exhaustruct // display fields only.
		Name: "loopback", Available: true, Posture: "read-only", Identity: "@octocat",
	})

	return []auth.Provider{&authtest.LoopbackProvider{}} //nolint:exhaustruct // defaults to "loopback".
}

func TestRunResearch_Welcome(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		model       chatModel
		providers   func(func(auth.ConnectorStatus)) []auth.Provider
		task        string
		interactive bool
		budget      bool
		wantInOut   bool
		wantErr     error
	}{
		{
			"rendered when bare interactive + connectors",
			&welcomeDiscModel{failWelcome: false}, loopbackProviders, "", true, false, true, nil,
		},
		{
			// A welcome generate error now drives ErrLLMUnavailable (abort), so the
			// greeting is never rendered — wantInOut false and wantErr ErrLLMUnavailable.
			"aborts on generate error",
			&welcomeDiscModel{failWelcome: true}, loopbackProviders, "", true, false, false, ErrLLMUnavailable,
		},
		{
			"skipped when non-interactive",
			&welcomeDiscModel{failWelcome: false}, loopbackProviders, "task", false, false, false, nil,
		},
		{
			// task "task" is the disc model's seed-task sentinel → the task turn
			// answers "task answer" (no marker); the welcome is gated off by task != "".
			"skipped when interactive but a seed task is supplied",
			&welcomeDiscModel{failWelcome: false}, loopbackProviders, "task", true, false, false, nil,
		},
		{
			"skipped when budget configured",
			&welcomeDiscModel{failWelcome: false}, loopbackProviders, "", true, true, false, nil,
		},
		{
			"skipped when zero connectors",
			&welcomeDiscModel{failWelcome: false},
			func(func(auth.ConnectorStatus)) []auth.Provider { return nil },
			"", true, false, false, nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := &fakeUI{} //nolint:exhaustruct // empty script: PromptUserInput EOFs immediately.
			var outBuf bytes.Buffer
			d := testDeps()
			d.ui = u
			d.out = &outBuf
			d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
				return tc.model, nil
			}
			d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
				return tc.providers(onStatus)
			}
			cfg := validCfg()
			if tc.budget {
				cfg.MaxTotalTokens = 1000
			}
			err := d.runResearch( //nolint:exhaustruct // only interactive under test.
				context.Background(), tc.task, cfg, researchFlags{interactive: tc.interactive},
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("runResearch err = %v, want %v", err, tc.wantErr)
			}
			got := strings.Contains(outBuf.String(), welcomeMarker)
			if got != tc.wantInOut {
				t.Errorf("welcome in out = %v, want %v (out=%q)", got, tc.wantInOut, outBuf.String())
			}
		})
	}
}

// trippedInterrupter satisfies agent.Interrupter and immediately reports an
// interrupt so a.Run returns agent.ErrInterrupted without contacting the model.
type trippedInterrupter struct{}

func (trippedInterrupter) Interrupted() bool { return true }
func (trippedInterrupter) BeginTurn()        {}
func (trippedInterrupter) EndTurn()          {}

// newInterruptedAgent builds a real agent whose interrupter is already tripped,
// so a.Run returns agent.ErrInterrupted on every call.
func newInterruptedAgent(t *testing.T) *agent.Agent {
	t.Helper()

	a, err := agent.New(context.Background(), agent.Config{
		Model:         &fakeChatModel{}, //nolint:exhaustruct // model never called
		Cfg:           validCfg(),
		Tools:         nil,
		Providers:     nil,
		Renderer:      (&fakeUI{}).RenderMessage, //nolint:exhaustruct // no-op renderer
		VerboseWriter: nil,
		Interrupter:   trippedInterrupter{},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	return a
}

// TestExitCodeFor verifies that ExitCodeFor maps nil→0, ErrInterrupted→130, and
// any other error→1.
func TestExitCodeFor(t *testing.T) {
	t.Parallel()

	if got := ExitCodeFor(nil); got != 0 {
		t.Errorf("nil → %d, want 0", got)
	}

	if got := ExitCodeFor(agent.ErrInterrupted); got != 130 {
		t.Errorf("ErrInterrupted → %d, want 130", got)
	}

	if got := ExitCodeFor(errors.New("other")); got != 1 {
		t.Errorf("other error → %d, want 1", got)
	}
}

// TestInteractiveLoop_InterruptContinues verifies that agent.ErrInterrupted from
// a.Run is treated as non-fatal: the loop continues to the next prompt rather than
// returning, so the operator can keep the session going after a Ctrl-C.
func TestInteractiveLoop_InterruptContinues(t *testing.T) {
	t.Parallel()

	// First input triggers a.Run → ErrInterrupted; second input exits the loop.
	u := &fakeUI{inputs: []string{"interrupted turn", "exit"}} //nolint:exhaustruct // counters zero.
	a := newInterruptedAgent(t)

	d := testDeps()
	d.ui = u

	err := d.interactiveLoop(context.Background(), a, metrics.NewAccumulator("p", "m"), validCfg(), true)
	if err != nil {
		t.Fatalf("interactiveLoop must return nil on interrupt (loop continues): got %v", err)
	}
	// Both prompts must have been served: the interrupted turn + the exit prompt.
	if u.promptCalls != 2 {
		t.Errorf("expected 2 promptCalls (interrupt + exit), got %d", u.promptCalls)
	}
}

// TestRunResearch_NonInteractiveInterruptPropagates verifies that a one-shot
// (-p / non-interactive) seed run that returns ErrInterrupted propagates it
// through runResearch so the caller can map it to exit code 130.
func TestRunResearch_NonInteractiveInterruptPropagates(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.interrupter = trippedInterrupter{}

	err := d.runResearch(
		context.Background(),
		"task",
		validCfg(),
		researchFlags{interactive: false}, //nolint:exhaustruct // non-interactive one-shot
	)
	if err == nil {
		t.Fatal("expected error when a non-interactive seed run is interrupted")
	}

	if !errors.Is(err, agent.ErrInterrupted) {
		t.Errorf("expected errors.Is(err, agent.ErrInterrupted), got: %v", err)
	}
}

// TestRunResearch_InteractiveInterruptFallsThrough verifies that an interrupted
// interactive seed run does NOT abort runResearch — it falls through to the
// interactive loop so the operator can keep the session going.
func TestRunResearch_InteractiveInterruptFallsThrough(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // empty script: PromptUserInput EOFs immediately.
	d := testDeps()
	d.ui = u
	d.interrupter = trippedInterrupter{}

	err := d.runResearch(
		context.Background(),
		"task",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // seeded interactive
	)
	// runResearch must not surface ErrInterrupted when interactive — it falls
	// through to the loop which then exits on EOF with nil.
	if err != nil {
		t.Fatalf("runResearch must return nil when interactive seed is interrupted: got %v", err)
	}
	// The interactive loop must have been entered: PromptUserInput is called at
	// least once (returning EOF immediately) to confirm the loop ran.
	if u.promptCalls < 1 {
		t.Errorf("expected at least 1 PromptUserInput call (interactive loop entered), got %d", u.promptCalls)
	}
}

func TestRunResearch_PassesInterrupterToAgent(t *testing.T) {
	t.Parallel()

	var gotCfg agent.Config

	d := testDeps()
	d.interrupter = &interrupt.State{}
	d.newAgent = func(_ context.Context, cfg agent.Config, _ ...agent.Option) (*agent.Agent, error) {
		gotCfg = cfg

		return agent.New(context.Background(), cfg)
	}

	_ = d.runResearch(t.Context(), "task", d.cfg, researchFlags{})
	if gotCfg.Interrupter == nil {
		t.Errorf("runResearch must pass deps.interrupter as agent.Config.Interrupter")
	}
}

func TestStatusToView_CopiesManaged(t *testing.T) {
	t.Parallel()

	v := statusToView(auth.ConnectorStatus{
		Name: "aws", Available: true, Warn: false, Posture: "SecurityAudit",
		Identity: "123 · arn", Reason: "", Managed: "eks",
	})
	if v.Managed != "eks" {
		t.Errorf("statusToView Managed = %q, want %q", v.Managed, "eks")
	}
}

func TestRunResearch_NoConnectorsNote(t *testing.T) {
	t.Parallel()

	var errBuf bytes.Buffer
	d := testDeps()
	d.errOut = &errBuf
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{assistantMsg("ok")},
		}, nil
	}

	if err := d.runResearch(
		context.Background(), "task", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults
	); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	if !strings.Contains(errBuf.String(), "(no connectors detected)") {
		t.Errorf("missing empty-connectors note; stderr:\n%s", errBuf.String())
	}
}

func TestRunResearch_PassesAboutToAgent(t *testing.T) {
	t.Parallel()

	var gotCfg agent.Config
	d := testDeps()
	d.newAgent = func(_ context.Context, cfg agent.Config, _ ...agent.Option) (*agent.Agent, error) {
		gotCfg = cfg

		return agent.New(context.Background(), cfg)
	}

	_ = d.runResearch(t.Context(), "task", d.cfg, researchFlags{})
	if !strings.Contains(gotCfg.About, "Cynative runs frontier models") {
		t.Errorf("runResearch must pass cynative.About() as agent.Config.About; got %q", gotCfg.About)
	}
}

func TestRunResearch_WelcomeCtxCancel_ExitsCleanly(t *testing.T) {
	t.Parallel()

	// ≥1 connector so the welcome branch runs; context cancelled before Welcome
	// fires → werr != nil && ctx.Err() != nil → (false, nil) quiet exit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the run so Generate observes it immediately.

	d := testDeps()
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		onStatus(auth.ConnectorStatus{Name: "loopback", Available: true}) //nolint:exhaustruct // display only.
		return []auth.Provider{&authtest.LoopbackProvider{}}              //nolint:exhaustruct // any non-empty list.
	}
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &ctxAwareModel{}, nil
	}

	err := d.runResearch(
		ctx, "", validCfg(), researchFlags{interactive: true}, //nolint:exhaustruct // only interactive
	)
	// Context cancel in the welcome is treated as a graceful exit (nil), NOT an LLM failure.
	if err != nil {
		t.Fatalf("welcome ctx-cancel must exit cleanly (nil), got: %v", err)
	}
}

func TestRunResearch_NotConfigured_Aborts(t *testing.T) {
	t.Parallel()

	d := testDeps()
	fu := &fakeUI{} //nolint:exhaustruct // recorder only; no script fields needed.
	d.ui = fu
	cfg := validCfg()
	cfg.LLM.Provider = ""
	cfg.LLM.Model = ""

	err := d.runResearch(
		context.Background(), "", cfg, researchFlags{interactive: true}, //nolint:exhaustruct // only interactive
	)
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(fu.llmStatuses) != 1 || !fu.llmStatuses[0].NotConfigured {
		t.Errorf("expected one NotConfigured LLM status, got %#v", fu.llmStatuses)
	}
	if fu.promptCalls != 0 {
		t.Error("must NOT open the REPL when not configured")
	}
}

func TestRunResearch_BadKey_FirstTurn_Aborts(t *testing.T) {
	t.Parallel()

	d := testDeps()
	fu := &fakeUI{} //nolint:exhaustruct // recorder only; no script fields needed.
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // only errs slice needed.
			errs: []error{&llm.GenerateError{StatusCode: 401, Message: "bad"}}, //nolint:exhaustruct // no code.
		}, nil
	}

	err := d.runResearch(
		context.Background(), "audit my repos", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults
	)
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(fu.llmStatuses) != 1 || fu.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("expected one ✗ LLM status, got %#v", fu.llmStatuses)
	}
}

func TestRunResearch_AuditError_NotMislabeled(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{} //nolint:exhaustruct // recorder only; no script fields needed.
	d := testDeps()
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // only errs slice needed.
			errs: []error{fmt.Errorf("dispatch: %w", audit.ErrLog)},
		}, nil
	}

	err := d.runResearch(
		context.Background(), "task", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults
	)
	if errors.Is(err, ErrLLMUnavailable) {
		t.Fatal("an audit error must NOT be reframed as ErrLLMUnavailable")
	}
	if err == nil {
		t.Fatal("audit error should propagate as a run failure")
	}
	// The audit error must propagate intact (not relabeled as ErrLLMUnavailable or wrapped away).
	if !errors.Is(err, audit.ErrLog) {
		t.Errorf("expected errors.Is(err, audit.ErrLog); got: %v", err)
	}
	// No LLM status block must be rendered: the error is not an LLM failure.
	if len(fu.llmStatuses) != 0 {
		t.Errorf("audit error must render NO LLM status block, got %#v", fu.llmStatuses)
	}
}

// TestRunResearch_OneShotRendersLLMBlock confirms -p (non-interactive) now renders
// exactly one ✓ LLM block (to errOut, so stdout stays clean) — consistent placement
// with interactive modes.
func TestRunResearch_OneShotRendersLLMBlock(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	fu := &fakeUI{} //nolint:exhaustruct // non-interactive -p: no inputs.
	d := testDeps()
	d.ui = fu
	d.out = &out
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // calls/errs unused.
			responses: []*schema.Message{assistantMsg("the answer")},
		}, nil
	}

	err := d.runResearch(context.Background(), "a task", validCfg(),
		researchFlags{}) //nolint:exhaustruct // non-interactive defaults.
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	if len(fu.llmStatuses) != 1 || fu.llmStatuses[0].State != ui.ConnectorOK {
		t.Fatalf("-p must render exactly one ✓ LLM block, got %#v", fu.llmStatuses)
	}
	if !strings.Contains(out.String(), "the answer") {
		t.Errorf("stdout should carry the answer, got %q", out.String())
	}
}

func TestRunResearch_ChatModelInitFails_Aborts(t *testing.T) {
	t.Parallel()

	d := testDeps()
	fu := &fakeUI{} //nolint:exhaustruct // recorder only; no script fields needed.
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return nil, errors.New("bifrost init: boom")
	}

	err := d.runResearch(
		context.Background(), "task", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults
	)
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(fu.llmStatuses) != 1 || fu.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("init failure must render one ✗ LLM status, got %#v", fu.llmStatuses)
	}
}

func TestRunResearch_WelcomeSkipped_FirstTurnBadKey_Aborts(t *testing.T) {
	t.Parallel()

	// Zero connectors → welcome is skipped → liveness defers to the first loop turn
	// (established=false), which must abort on llm.ErrGenerate.
	d := testDeps()
	fu := &fakeUI{inputs: []string{"audit my repos"}} //nolint:exhaustruct // only inputs needed.
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // only errs slice needed.
			errs: []error{&llm.GenerateError{StatusCode: 401, Message: "bad"}}, //nolint:exhaustruct // no code.
		}, nil
	}

	err := d.runResearch(
		context.Background(), "", validCfg(), researchFlags{interactive: true}, //nolint:exhaustruct // only interactive
	)
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable (first loop turn is fatal)", err)
	}
}

func TestRunResearch_EstablishedThenTurnError_Continues(t *testing.T) {
	t.Parallel()

	// ≥1 connector so the welcome runs and establishes the session; the welcome
	// succeeds (call 0), the follow-up turn errors (call 1) — established=true, so
	// the loop prints the error and continues (no ErrLLMUnavailable).
	d := testDeps()
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		onStatus(auth.ConnectorStatus{Name: "github", Available: true}) //nolint:exhaustruct // display only.
		return []auth.Provider{&authtest.LoopbackProvider{}}            //nolint:exhaustruct // any non-empty list.
	}
	var errOut bytes.Buffer
	fu := &fakeUI{inputs: []string{"follow-up question"}} //nolint:exhaustruct // only inputs needed.
	d.ui = fu
	d.errOut = &errOut
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // responses + errs interleaved.
			responses: []*schema.Message{assistantMsg("hi! 1. ask X")},
			errs:      []error{nil, &llm.GenerateError{StatusCode: 500, Message: "x"}}, //nolint:exhaustruct // no code.
		}, nil
	}

	err := d.runResearch(
		context.Background(), "", validCfg(), researchFlags{interactive: true}, //nolint:exhaustruct // only interactive
	)
	if errors.Is(err, ErrLLMUnavailable) {
		t.Fatal("an error AFTER the session is established must NOT abort as ErrLLMUnavailable")
	}
	if !strings.Contains(errOut.String(), "Error") {
		t.Errorf("a post-established turn error should be printed, got %q", errOut.String())
	}
}

// TestRunResearch_InteractiveSeeded_RendersLLMOnce verifies that an interactive
// seeded run renders the ✓ LLM status exactly once after the seed task succeeds,
// and NOT again during the follow-up loop.
func TestRunResearch_InteractiveSeeded_RendersLLMOnce(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{inputs: []string{"a follow-up question"}} //nolint:exhaustruct // one follow-up turn, then EOF.
	d := testDeps()
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // benign default responses.
			responses: []*schema.Message{assistantMsg("seeded answer"), assistantMsg("loop answer")},
		}, nil
	}

	err := d.runResearch(
		context.Background(), "find my repos", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	// Exactly one ✓ status: rendered after the seeded task succeeds, and NOT again
	// during the follow-up loop turn (llmShown suppresses it).
	if len(fu.llmStatuses) != 1 {
		t.Fatalf("expected exactly 1 LLM status, got %d: %#v", len(fu.llmStatuses), fu.llmStatuses)
	}
	if fu.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("expected ✓ (ConnectorOK) status, got %#v", fu.llmStatuses[0])
	}
}

// TestRunResearch_SeededCanceledContext_QuietExit verifies that a seeded interactive
// run whose parent context is already canceled quiet-exits (nil) WITHOUT calling the
// model or rendering any LLM status — the runInitialPhase ctx guard short-circuits
// before runTask reaches a.Run.
func TestRunResearch_SeededCanceledContext_QuietExit(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{} //nolint:exhaustruct // no interaction expected on a quiet exit.
	d := testDeps()
	d.ui = fu
	fcm := &fakeChatModel{responses: []*schema.Message{assistantMsg("unused")}} //nolint:exhaustruct // never called.
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return fcm, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	//nolint:exhaustruct // only interactive under test.
	err := d.runResearch(ctx, "do a task", validCfg(), researchFlags{interactive: true})
	if err != nil {
		t.Fatalf("want nil (quiet exit on canceled ctx), got %v", err)
	}
	if fcm.calls != 0 {
		t.Errorf("model must NOT be called on a pre-canceled ctx, got %d calls", fcm.calls)
	}
	if len(fu.llmStatuses) != 0 {
		t.Errorf("no LLM status should render on a quiet exit, got %#v", fu.llmStatuses)
	}
}

// TestRunResearch_InteractiveWelcomeSkipped_RendersLLMAfterFirstTurn verifies that
// when the welcome is skipped (zero providers) and the user types the first question,
// the ✓ LLM status is rendered exactly once after the first successful loop turn.
func TestRunResearch_InteractiveWelcomeSkipped_RendersLLMAfterFirstTurn(t *testing.T) {
	t.Parallel()

	// getProviders returns nil → zero providers → welcome is skipped.
	fu := &fakeUI{inputs: []string{"what are my repos?"}} //nolint:exhaustruct // one question then EOF.
	d := testDeps()
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // benign default.
			responses: []*schema.Message{assistantMsg("here are your repos")},
		}, nil
	}

	err := d.runResearch(
		context.Background(), "", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	// The ✓ block must appear exactly once, rendered inside the loop on the first
	// successful turn (before the footer).
	if len(fu.llmStatuses) != 1 {
		t.Fatalf("expected exactly 1 LLM status, got %d: %#v", len(fu.llmStatuses), fu.llmStatuses)
	}
	if fu.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("expected ✓ (ConnectorOK) status, got %#v", fu.llmStatuses[0])
	}
}

// TestRunResearch_WelcomeSuccess_RendersLLMExactlyOnce verifies that a healthy
// bare-welcome interactive session renders the ✓ block exactly once (from
// runWelcome) and not a second time in the follow-up loop.
func TestRunResearch_WelcomeSuccess_RendersLLMExactlyOnce(t *testing.T) {
	t.Parallel()

	// ≥1 connector triggers the welcome path; one follow-up question exercises the loop.
	fu := &fakeUI{inputs: []string{"follow-up?"}} //nolint:exhaustruct // one input then EOF.
	d := testDeps()
	d.ui = fu
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		return loopbackProviders(onStatus)
	}
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // benign responses for welcome + loop turn.
			responses: []*schema.Message{assistantMsg(welcomeMarker), assistantMsg("loop answer")},
		}, nil
	}

	err := d.runResearch(
		context.Background(), "", validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	if err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	// runWelcome rendered ✓; llmShown=true suppresses a second render in the loop.
	if len(fu.llmStatuses) != 1 {
		t.Fatalf("expected exactly 1 LLM status (welcome renders it once), got %d: %#v",
			len(fu.llmStatuses), fu.llmStatuses)
	}
	if fu.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("expected ✓ (ConnectorOK) status, got %#v", fu.llmStatuses[0])
	}
}

// writeTodosMsg returns an assistant message that calls write_todos with a single
// pending todo. The agent dispatch will run write_todos (an orchestration tool),
// so the next Generate call starts a new iteration.
func writeTodosMsg() *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCallBlock{{
		ID:        "t1",
		Name:      "write_todos",
		Arguments: `{"todos":[{"content":"x","status":"pending"}]}`,
	}})
}

// generateErrOf builds an llm.ErrGenerate-wrapping error with a status code.
func generateErrOf(status int) error {
	return &llm.GenerateError{StatusCode: status, Message: "boom"} //nolint:exhaustruct // Code unused.
}

// TestRunResearch_SeededMidFailure_NotLLMUnavailable verifies that a one-shot (-p)
// run whose first turn calls write_todos (one successful round-trip) and then
// errors does NOT return ErrLLMUnavailable. The LLM was demonstrably live mid-turn.
func TestRunResearch_SeededMidFailure_NotLLMUnavailable(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // interleaved responses + errs.
			// Call 0: write_todos tool call (counts as one round-trip when dispatched).
			responses: []*schema.Message{writeTodosMsg()},
			// Call 1 (next Generate after tool dispatch): ErrGenerate.
			errs: []error{nil, generateErrOf(503)},
		}, nil
	}

	err := d.runResearch(
		context.Background(),
		"audit my repos",
		validCfg(),
		researchFlags{}, //nolint:exhaustruct // non-interactive one-shot
	)
	if errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("a mid-turn ErrGenerate after a successful round-trip must NOT return ErrLLMUnavailable, got %v", err)
	}
	// The error must still propagate (not swallowed).
	if err == nil {
		t.Fatal("expected a run-failure error, got nil")
	}
}

// TestRunResearch_WelcomeSkipped_FirstTurnMidFailure_NotFatal verifies that when
// the welcome is skipped (zero providers) and the first interactive turn makes at
// least one successful round-trip before erroring, runResearch does NOT abort
// with ErrLLMUnavailable and does NOT render a ✗ LLM status.
func TestRunResearch_WelcomeSkipped_FirstTurnMidFailure_NotFatal(t *testing.T) {
	t.Parallel()

	// Zero providers → welcome skipped; established=false entering the loop.
	fu := &fakeUI{inputs: []string{"do something", "q"}} //nolint:exhaustruct // only inputs/llmStatuses needed.
	d := testDeps()
	d.ui = fu
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // interleaved.
			// First Generate (call 0): write_todos (one round-trip, success).
			responses: []*schema.Message{writeTodosMsg()},
			// Second Generate (call 1): ErrGenerate — but after a live round-trip.
			errs: []error{nil, generateErrOf(503)},
		}, nil
	}

	err := d.runResearch(
		context.Background(),
		"",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	// Must NOT abort as ErrLLMUnavailable: the LLM was live during the turn.
	if errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("mid-turn failure must NOT abort as ErrLLMUnavailable, got %v", err)
	}
	// No ✗ LLM status block must be rendered.
	for _, s := range fu.llmStatuses {
		if s.State == ui.ConnectorError {
			t.Errorf("must render NO ✗ LLM status block, got %#v", s)
		}
	}
}

// TestRunResearch_WelcomeTimedOut_Proceeds verifies that when Welcome returns
// ErrWelcomeTimedOut the session proceeds cleanly: no ✗ LLM status, no abort.
// The first successful loop turn then renders the ✓ LLM status.
func TestRunResearch_WelcomeTimedOut_Proceeds(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{inputs: []string{"audit my repos"}} //nolint:exhaustruct // one input then EOF.
	d := testDeps()
	d.ui = fu
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		// ≥1 provider triggers the welcome path.
		return loopbackProviders(onStatus)
	}
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		// The model blocks on the first call (welcome) and succeeds on the second
		// (loop turn). The welcome timeout (1 ms) fires before the block resolves.
		return &seqBlockThenAnswerModel{answer: "here are your repos"}, nil
	}
	// Inject a very short welcome timeout via the production WithWelcomeTimeout option.
	d.newAgent = func(ctx context.Context, cfg agent.Config, opts ...agent.Option) (*agent.Agent, error) {
		opts = append(opts, agent.WithWelcomeTimeout(1*time.Millisecond))

		return agent.New(ctx, cfg, opts...)
	}

	err := d.runResearch(
		context.Background(),
		"",
		validCfg(),
		researchFlags{interactive: true}, //nolint:exhaustruct // only interactive under test.
	)
	if err != nil {
		t.Fatalf("welcome timeout must NOT abort the session; got %v", err)
	}
	// No ✗ LLM status rendered (welcome timeout is not a fatal failure).
	for _, s := range fu.llmStatuses {
		if s.State == ui.ConnectorError {
			t.Errorf("welcome timeout must NOT render a ✗ LLM status, got %#v", s)
		}
	}
	// A ✓ status was rendered after the successful loop turn.
	found := false
	for _, s := range fu.llmStatuses {
		if s.State == ui.ConnectorOK {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a ✓ LLM status after first successful loop turn, got none; statuses: %#v", fu.llmStatuses)
	}
}

// seqBlockThenAnswerModel blocks on the first Generate call (simulating a welcome
// that times out) and then returns a final answer on subsequent calls. The block
// is implemented by waiting for the context to be done.
type seqBlockThenAnswerModel struct {
	calls  int
	answer string
}

var _ chatModel = (*seqBlockThenAnswerModel)(nil)

func (m *seqBlockThenAnswerModel) Generate(
	ctx context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	m.calls++
	if m.calls == 1 {
		// First call: block until context expires (simulates welcome timeout).
		<-ctx.Done()

		return nil, ctx.Err()
	}

	return schema.AssistantMessage(m.answer, nil), nil
}

func (m *seqBlockThenAnswerModel) Shutdown() {}

// TestHandleTurnError_Interrupt verifies the liveness promotion on interrupt: an
// interrupt AFTER a model response marks the session established (so a later
// transient llm.ErrGenerate is a normal turn error, not a dead-LLM abort), while a
// pre-Generate interrupt (no response) leaves established unchanged.
func TestHandleTurnError_Interrupt(t *testing.T) {
	t.Parallel()

	t.Run("after a response → established", func(t *testing.T) {
		t.Parallel()

		d := testDeps()
		acc := metrics.NewAccumulator("p", "m")
		acc.AddResponse() // the turn got one model response before the interrupt.

		established, cont, err := d.handleTurnError(
			context.Background(), acc, validCfg(), agent.ErrInterrupted, false, 0,
		)
		if !established {
			t.Error("interrupt after a model response must mark the session established")
		}
		if !cont || err != nil {
			t.Errorf("interrupt must continue without terminating, got cont=%v err=%v", cont, err)
		}
	})

	t.Run("pre-Generate interrupt → established unchanged", func(t *testing.T) {
		t.Parallel()

		d := testDeps()
		acc := metrics.NewAccumulator("p", "m")
		// respBefore == current Responses ⇒ no response this turn (top-of-loop halt).
		established, cont, err := d.handleTurnError(
			context.Background(), acc, validCfg(), agent.ErrInterrupted, false, acc.Snapshot().Responses,
		)
		if established {
			t.Error("a pre-Generate interrupt must NOT mark the session established")
		}
		if !cont || err != nil {
			t.Errorf("interrupt must continue without terminating, got cont=%v err=%v", cont, err)
		}
	})
}

// TestModelResponded verifies the liveness helper: it reports true once the turn
// has completed at least one model response since respBefore, false otherwise.
func TestModelResponded(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m")
	if modelResponded(acc, 0) {
		t.Error("no response yet → want false")
	}
	acc.AddResponse()
	if !modelResponded(acc, 0) {
		t.Error("one response since respBefore=0 → want true")
	}
	if modelResponded(acc, acc.Snapshot().Responses) {
		t.Error("respBefore == current count (no new response this turn) → want false")
	}
}

// TestHandleTurnError_CanceledContextNotLLMFailure verifies that when the context
// is canceled and the error wraps llm.ErrGenerate, handleTurnError returns the
// error to terminate (not swallowed, not ErrLLMUnavailable) and renders NO LLM ✗
// block. A context cancellation is a graceful shutdown, not a dead-LLM event.
func TestHandleTurnError_CanceledContextNotLLMFailure(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{} //nolint:exhaustruct // only llmStatuses is checked.
	d := testDeps()
	d.ui = fu

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel the context first — mimics a SIGTERM mid-turn.

	acc := metrics.NewAccumulator("p", "m")
	// established=false: session not yet proven live (first turn).
	genErr := &llm.GenerateError{StatusCode: 499, Message: "canceled"} //nolint:exhaustruct // no Code.
	retErr := fmt.Errorf("agent: model generate: %w", genErr)

	retEstablished, cont, err := d.handleTurnError(ctx, acc, validCfg(), retErr, false, 0)
	// Must NOT render a ✗ LLM block — this is a context cancel, not a dead LLM.
	if len(fu.llmStatuses) != 0 {
		t.Errorf("canceled-ctx turn must render NO LLM status block, got %#v", fu.llmStatuses)
	}
	// Must NOT return ErrLLMUnavailable.
	if errors.Is(err, ErrLLMUnavailable) {
		t.Error("canceled-ctx error must NOT be reframed as ErrLLMUnavailable")
	}
	// Must propagate the original error so the caller can terminate.
	if err == nil {
		t.Error("canceled-ctx error must not be swallowed (err must be non-nil)")
	}
	// Must not signal loop-continue.
	if cont {
		t.Error("canceled-ctx must NOT continue the loop")
	}
	// established must be unchanged (false).
	if retEstablished {
		t.Error("canceled-ctx must not flip established to true")
	}
}

// TestRunTask_CanceledContext_QuietExit verifies that when the parent context is
// canceled and a.Run returns an error (not ErrInterrupted), runTask returns
// (false, nil) — a graceful quiet exit, not an LLM-failure abort. This covers
// the ctx.Err() guard inside runTask.
func TestRunTask_CanceledContext_QuietExit(t *testing.T) {
	t.Parallel()

	fu := &fakeUI{} //nolint:exhaustruct // only llmStatuses is checked.
	d := testDeps()
	d.ui = fu

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the run so the ctxAwareModel returns ctx.Err().

	// ctxAwareModel returns ctx.Err() when the context is already canceled.
	a := newTestAgent(t, &ctxAwareModel{})
	acc := metrics.NewAccumulator("p", "m")
	acc.StartTurn()

	established, err := d.runTask(ctx, a, acc, validCfg(), "task", false)
	// Must return nil — context cancel is a graceful exit, not an LLM failure.
	if err != nil {
		t.Fatalf("canceled-ctx runTask must return nil, got: %v", err)
	}
	if established {
		t.Error("canceled-ctx runTask must not mark the session established")
	}
	// Must NOT render a ✗ LLM block — this is not an LLM failure.
	if len(fu.llmStatuses) != 0 {
		t.Errorf("canceled-ctx runTask must render NO LLM status block, got %#v", fu.llmStatuses)
	}
}

// TestRunResearch_PrimesBackgroundBeforeFirstRender verifies that PrimeBackground
// is called exactly once before the first RenderMessage, so the OSC 11 terminal
// background probe cannot race the keystroke watcher.
func TestRunResearch_PrimesBackgroundBeforeFirstRender(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // counters/order zero.
	d := testDeps()
	d.ui = u
	if err := d.runResearch(
		context.Background(), "task", validCfg(), researchFlags{}, //nolint:exhaustruct // defaults.
	); err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	if u.primeCalls != 1 {
		t.Fatalf("PrimeBackground called %d times, want 1", u.primeCalls)
	}
	primeIdx := slices.Index(u.order, "prime")
	renderIdx := slices.Index(u.order, "render")
	if primeIdx < 0 {
		t.Fatalf("PrimeBackground not recorded: %v", u.order)
	}
	// Priming must precede the first adaptive render, else the lazy probe would race
	// the keystroke watcher.
	if renderIdx >= 0 && primeIdx > renderIdx {
		t.Errorf("prime (idx %d) must precede first render (idx %d): %v", primeIdx, renderIdx, u.order)
	}
}

// TestHandleTurnError_AuditErrTerminates verifies that an audit-write error in an
// interactive turn terminates the session (classifyTurnError path in handleTurnError).
func TestHandleTurnError_AuditErrTerminates(t *testing.T) {
	t.Parallel()

	d := testDeps()
	acc := metrics.NewAccumulator("p", "m")
	auditErr := fmt.Errorf("dispatch: %w", audit.ErrLog)

	established, cont, err := d.handleTurnError(
		context.Background(), acc, validCfg(), auditErr, true, 0,
	)
	// classifyTurnError returns true for audit errors → must terminate.
	if err == nil {
		t.Error("audit error must terminate the session (non-nil err)")
	}
	if !errors.Is(err, audit.ErrLog) {
		t.Errorf("audit error must propagate intact, got: %v", err)
	}
	if cont {
		t.Error("audit error must NOT continue the loop")
	}
	// established is returned as-is.
	if !established {
		t.Error("established must be preserved (true) on audit error")
	}
}
