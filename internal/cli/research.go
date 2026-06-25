package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/cynative/cynative"
	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/cache"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/ui"
)

var (
	// ErrNoTask is returned when a non-interactive invocation has no task to run.
	ErrNoTask = errors.New("no task provided; pass a task argument, pipe one via stdin, " +
		"or run cynative with no arguments for an interactive session")
	// ErrNoApprovalTerminal is returned when a run has no usable controlling
	// terminal to prompt for tool approval and --auto-approve was not given.
	ErrNoApprovalTerminal = errors.New("no usable controlling terminal for tool approval; " +
		"run in the foreground, or pass --auto-approve for an unattended run")
	// ErrLLMUnavailable is returned when the LLM is not configured, misconfigured,
	// or fails its first interaction. The LLM ✗ status block already explained the
	// cause, so the root command silences cobra's duplicate Error line; ExitCodeFor
	// maps it to 1.
	ErrLLMUnavailable = errors.New("llm unavailable")
)

// stdinTruncationMarker is appended (outside any <piped_input> fence) when piped
// stdin exceeded the read cap, so the model knows the data is partial.
const stdinTruncationMarker = "\n[stdin truncated at 1 MiB]"

// invocationInputs is the raw, environment-derived input to resolveInvocation.
type invocationInputs struct {
	printMode      bool
	autoApprove    bool
	arg            string
	stdinData      string
	stdinTruncated bool
	stdinIsTTY     bool
	hasTerminal    bool
}

// resolvedRun is the decision resolveInvocation produces.
type resolvedRun struct {
	task        string
	interactive bool
}

// joinTask assembles the agent task from the positional arg and piped stdin.
// When both are present the piped content is folded in as framed, untrusted
// context, passed through verbatim (only trimmed for the empty check) so
// whitespace-sensitive files (YAML, Python, heredocs) reach the model unchanged;
// bare piped stdin is the operator's task and is trimmed like a typed prompt. A
// truncation marker, when set, is appended outside any fence.
func joinTask(arg, stdin string, truncated bool) string {
	argTrimmed := strings.TrimSpace(arg)
	stdinTrimmed := strings.TrimSpace(stdin)

	var task string

	switch {
	case argTrimmed != "" && stdinTrimmed != "":
		task = argTrimmed + "\n\n" + agent.WrapPipedInput(stdin)
	case argTrimmed != "":
		task = argTrimmed
	default:
		task = stdinTrimmed
	}

	if truncated && stdinTrimmed != "" {
		task += stdinTruncationMarker
	}

	return task
}

// resolveInvocation maps the parsed CLI inputs to a resolved run or an error.
// Interactive REPL mode requires a TTY stdin and the absence of -p; piped data
// always implies one-shot. A non-interactive run with no task, or any run with
// no usable approval terminal and no --auto-approve, is a fail-closed error.
func resolveInvocation(in invocationInputs) (resolvedRun, error) {
	interactive := !in.printMode && in.stdinIsTTY
	task := joinTask(in.arg, in.stdinData, in.stdinTruncated)

	if !interactive && task == "" {
		return resolvedRun{}, ErrNoTask
	}

	if !in.autoApprove && !in.hasTerminal {
		return resolvedRun{}, ErrNoApprovalTerminal
	}

	return resolvedRun{task: task, interactive: interactive}, nil
}

// chatModel couples the chat model with a Shutdown for backend cleanup.
type chatModel interface {
	schema.ChatModel
	Shutdown()
}

// getProvidersFunc builds the auth providers from the bundled hardening config,
// streaming each visible ConnectorStatus to the callback as it resolves. A named
// type keeps the deps field and the test fakes within the 120-col limit.
type getProvidersFunc func(auth.HardeningConfig, bool, func(auth.ConnectorStatus)) []auth.Provider

// researchUI is the subset of *ui.UI that research orchestration needs. Keeping
// it an interface lets tests inject a scripted UI without a terminal.
type researchUI interface {
	PromptToolApproval(name, arguments, style string, alreadyGranted bool) tools.Decision
	AutoApproveToolCall(name, arguments, style string, alreadyGranted bool) tools.Decision
	PromptUserInput(prompt string) (string, bool)
	RenderMessage(msg *schema.Message, style string, w io.Writer)
	RenderFooter(s metrics.Stats, label string)
	RenderBanner(w io.Writer)
	RenderConnector(w io.Writer, v ui.ConnectorView)
	RenderLLM(w io.Writer, s ui.LLMStatus)
	PrimeBackground(style string)
}

// researchFlags carries the research command's boolean flags.
type researchFlags struct {
	autoApprove bool
	interactive bool
	verbose     bool
}

// deps holds the cli's injected collaborators. newDeps (wire_shell.go) wires the
// production implementations from the real environment; tests build a deps with
// fakes. cfg is populated by the root command's PersistentPreRunE before run.
type deps struct {
	loadConfig           func(cfgFile string) (config.Config, error)
	run                  func(ctx context.Context, task string, cfg config.Config, flags researchFlags) error
	getProviders         getProvidersFunc
	newChatModel         func(ctx context.Context, cfg config.Config, recordUsage func(schema.Usage)) (chatModel, error)
	newHTTPRequestTool   func(providers []auth.Provider) (schema.InvokableTool, error)
	newCodeExecutionTool func(primitives []schema.InvokableTool, verbose io.Writer, maxConcurrency int, sink audit.Sink) (schema.InvokableTool, error)
	newAuditSink         func(cfg config.Config) (audit.Sink, func() error, error)
	newAgent             func(ctx context.Context, cfg agent.Config, opts ...agent.Option) (*agent.Agent, error)
	ui                   researchUI
	out                  io.Writer
	errOut               io.Writer
	cfg                  config.Config
	stdinIsTTY           bool
	hasTerminal          bool
	readStdin            func() (data string, truncated bool, err error)
	interrupter          agent.Interrupter
	version              string // pre-rendered `--version` output; resolved in newDeps.
}

// runRoot reads any piped stdin, resolves the invocation, and dispatches to run.
// It is the root command's RunE body, factored out for direct testing.
func (d *deps) runRoot(ctx context.Context, args []string, printMode bool, flags researchFlags) error {
	arg := ""
	if len(args) == 1 {
		arg = args[0]
	}

	var (
		stdinData string
		truncated bool
	)

	if !d.stdinIsTTY {
		// Fail closed before draining stdin: with no usable terminal and no
		// --auto-approve, no tool can be approved, so a non-closing pipe (e.g.
		// tail -f) must not block us from returning ErrNoApprovalTerminal.
		if !flags.autoApprove && !d.hasTerminal {
			return ErrNoApprovalTerminal
		}

		s, t, err := d.readStdin()
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}

		stdinData, truncated = s, t
	}

	res, err := resolveInvocation(invocationInputs{
		printMode:      printMode,
		autoApprove:    flags.autoApprove,
		arg:            arg,
		stdinData:      stdinData,
		stdinTruncated: truncated,
		stdinIsTTY:     d.stdinIsTTY,
		hasTerminal:    d.hasTerminal,
	})
	if err != nil {
		return err
	}

	flags.interactive = res.interactive

	return d.run(ctx, res.task, d.cfg, flags)
}

// runResearch builds the tool set, chat model and agent from cfg, runs the task,
// and (when interactive) enters the follow-up loop. It is the default value of
// deps.run; tests can replace deps.run to exercise command plumbing in isolation.
func (d *deps) runResearch(ctx context.Context, task string, cfg config.Config, flags researchFlags) (err error) {
	var verboseWriter io.Writer
	if flags.verbose {
		verboseWriter = d.errOut
	}

	d.ui.RenderBanner(d.errOut)

	// buildProviders streams a connector-inventory line per resolved connector to
	// d.errOut; views are consumed by the welcome and system prompt below.
	providers, views := d.buildProviders(cfg, flags.verbose)

	if len(views) == 0 {
		fmt.Fprintln(d.errOut, "  (no connectors detected)")
	}

	// Structural LLM gate (local, no network): render the LLM block and abort
	// before building anything LLM-dependent. Connectors are already shown above.
	if verr := config.ValidateLLM(&cfg.LLM); verr != nil {
		d.ui.RenderLLM(d.errOut, llmConfigStatus(cfg, verr))

		return ErrLLMUnavailable
	}

	sink, closeAudit, err := d.newAuditSink(cfg)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() {
		// Fail-closed: a close/flush failure means the final audit records may not be
		// durable, so surface it as the command's error — without masking an earlier one.
		if cerr := closeAudit(); cerr != nil && err == nil {
			err = fmt.Errorf("audit log close: %w", cerr)
		}
	}()

	toolSet, err := d.buildToolSet(providers, cfg, flags, verboseWriter, sink)
	if err != nil {
		return err
	}

	acc := metrics.NewAccumulator(cfg.LLM.Provider, cfg.LLM.Model,
		metrics.WithBudget(cfg.MaxTotalTokens))

	cm, err := d.newChatModel(ctx, cfg, acc.AddUsage)
	if err != nil {
		// Chat-model init failure is part of the LLM status flow, not a bare error.
		d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, err))

		return ErrLLMUnavailable
	}
	defer cm.Shutdown()

	var llmShown bool

	a, err := d.newAgent(ctx, agent.Config{
		Model:            llm.NewRedactingChatModel(cm, redact.New()),
		Cfg:              cfg,
		Tools:            toolSet,
		Providers:        providers,
		Connectors:       connectorMeta(views),
		About:            cynative.About(),
		Renderer:         d.ui.RenderMessage,
		VerboseWriter:    verboseWriter,
		Metrics:          acc,
		DeniedToolResult: tools.DeniedMessage,
		Audit:            sink,
		Interrupter:      d.interrupter,
		OnFirstResponse:  d.showLLMOnce(cfg, &llmShown),
	})
	if err != nil {
		return fmt.Errorf("initialize agent: %w", err)
	}

	// Detect the terminal background once, before runInitialPhase / the interactive
	// loop start any turn's keystroke watcher — so the OSC 11/DA1 probe reply cannot
	// race the watcher and be misread as Esc. Placed after the LLM
	// abort-gates so a config/init failure (which runs no turn) skips the probe.
	d.ui.PrimeBackground(cfg.RenderStyle)

	established, initErr := d.runInitialPhase(ctx, a, acc, cfg, providers, task, &llmShown, flags)
	if initErr != nil {
		return initErr
	}

	if ctx.Err() != nil || !flags.interactive {
		// Parent context canceled or one-shot run — exit quietly; no REPL.
		return nil
	}

	return d.interactiveLoop(ctx, a, acc, cfg, established)
}

// runInitialPhase runs the welcome and/or seeded-task turns before the REPL. It
// returns (established, err): established is true when at least one LLM
// interaction succeeded; llmShown is mutated via its pointer whenever the ✓ block
// is rendered (so interactiveLoop's OnFirstResponse hook does not double-render);
// err is non-nil only when the session must abort. The ctx-cancel quiet-exit is
// checked by the caller.
func (d *deps) runInitialPhase(
	ctx context.Context, a *agent.Agent, acc *metrics.Accumulator,
	cfg config.Config, providers []auth.Provider, task string, llmShown *bool, flags researchFlags,
) (bool, error) {
	established := false

	// Interactive bare session opener: the welcome is the first real interaction.
	// Only for a BARE interactive session (no seed task, no budget, ≥1 connector).
	if flags.interactive && task == "" && !acc.HasBudget() && len(providers) > 0 {
		ok, werr := d.runWelcome(ctx, a, cfg, llmShown)
		if werr != nil {
			return false, werr
		}

		established = ok // runWelcome sets *llmShown=true on success via its own render.
	}

	if task == "" {
		return established, nil
	}

	if ctx.Err() != nil {
		// Parent context already canceled — don't run the seeded task; the
		// caller's guard turns this into a quiet exit.
		return established, nil //nolint:nilerr // context cancel is a graceful exit, not an error.
	}

	ok, runErr := d.runTask(ctx, a, acc, cfg, task, flags.interactive)
	if runErr != nil {
		return false, runErr
	}

	// The ✓ LLM block is rendered via the OnFirstResponse hook (showLLMOnce) the
	// moment the model's first response arrives — no post-run render is needed here.
	return established || ok, nil
}

// runWelcome drives the interactive session opener: a greeting + example questions.
// On success it renders the ✓ LLM block (setting *llmShown=true so the
// OnFirstResponse hook does not double-render on later turns) and the greeting to
// out; on a generate failure renders the ✗ block and returns ErrLLMUnavailable; on
// a parent-context cancellation returns (false, nil) so the caller exits quietly.
// Returns (established, err).
func (d *deps) runWelcome(ctx context.Context, a *agent.Agent, cfg config.Config, llmShown *bool) (bool, error) {
	// The greeting (content) is returned and rendered to out below, so the cli
	// controls the ✓-then-greeting order.
	greeting, werr := a.Welcome(ctx)
	switch {
	case werr != nil && ctx.Err() != nil:
		// Parent context canceled (shutdown/interrupt) — NOT an LLM failure; end
		// quietly and let the signal handler drive the exit code.
		return false, nil //nolint:nilerr // intentional: context cancel is a graceful exit, not an error.
	case errors.Is(werr, agent.ErrWelcomeTimedOut):
		// The welcome timed out but the session is still live — skip the greeting
		// and proceed; established remains false so the first loop turn still
		// validates liveness.
		return false, nil // timeout is a soft skip — session proceeds without a greeting.
	case werr != nil:
		d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, werr))

		return false, ErrLLMUnavailable
	}
	d.ui.RenderLLM(d.errOut, llmOKStatus(cfg))
	*llmShown = true // guard the hook: welcome already rendered ✓, no second render on later turns.
	if greeting != "" {
		d.ui.RenderMessage(schema.AssistantMessage(greeting, nil), cfg.RenderStyle, d.out)
	}

	return true, nil
}

// runTask runs the seeded task, renders the footer, and classifies the outcome.
// Returns (established, err): established=true when the run succeeded; err is
// non-nil only when the error must abort the session.
func (d *deps) runTask(
	ctx context.Context, a *agent.Agent, acc *metrics.Accumulator,
	cfg config.Config, task string, interactive bool,
) (bool, error) {
	respBefore := acc.Snapshot().Responses
	runErr := a.Run(ctx, task, d.out)
	if interactive {
		d.ui.RenderFooter(acc.TurnSnapshot(), "turn")
	} else {
		d.renderSessionFooter(acc)
	}

	if runErr == nil {
		return true, nil
	}
	// A context cancellation (e.g. SIGTERM or a parent cancel) wraps its error
	// via Bifrost as llm.ErrGenerate; check the context first so a canceled
	// first turn is treated as a graceful shutdown, not a dead-LLM startup failure.
	if ctx.Err() != nil {
		return false, nil //nolint:nilerr // context cancel is a graceful exit, not an error.
	}
	if errors.Is(runErr, llm.ErrGenerate) {
		// Only treat as a dead LLM when the model never responded this turn (no
		// successful Generate). If the model responded at least once, the LLM was
		// live; fall through to the generic run-failed error path.
		if !modelResponded(acc, respBefore) {
			d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, runErr))

			return false, ErrLLMUnavailable
		}
	}
	// An interactive interrupt falls through to the loop (notice already rendered).
	// Any other error — or a non-interactive interrupt — propagates.
	if !errors.Is(runErr, agent.ErrInterrupted) || !interactive {
		return false, fmt.Errorf("research run failed: %w", runErr)
	}

	// Preserve liveness: if the interrupted seed turn got a model response, the
	// LLM responded — mark the session established so the REPL's first transient
	// llm.ErrGenerate is not misread as a dead-LLM startup failure.
	return modelResponded(acc, respBefore), nil
}

// modelResponded reports whether the model returned a usable response since
// respBefore — i.e. Generate succeeded at least once this turn, proving liveness.
// Used to preserve the established flag across an interrupted or failed turn (seeded
// or in-loop) so a later transient error is handled normally rather than as a
// failed-startup abort.
func modelResponded(acc *metrics.Accumulator, respBefore int) bool {
	return acc.Snapshot().Responses-respBefore > 0
}

// statusToView maps a probed connector status to its renderable view.
//
// Invariant (spec §5.4): host-authored diagnostics — connector Reason/Identity,
// posture, and turn errors — are NOT redacted at any boundary, so they must never
// embed credential material. Provider probes already surface sanitized status
// (ShortenError, "token expired", ARNs, request IDs), not tokens. Never
// interpolate a raw token/secret into a diagnostic string.
func statusToView(s auth.ConnectorStatus) ui.ConnectorView {
	switch {
	case !s.Available:
		return ui.ConnectorView{State: ui.ConnectorError, Name: s.Name, Posture: s.Reason, Identity: "", Managed: ""}
	case s.Warn:
		return ui.ConnectorView{
			State: ui.ConnectorWarn, Name: s.Name, Posture: s.Posture, Identity: s.Identity, Managed: s.Managed,
		}
	default:
		return ui.ConnectorView{
			State: ui.ConnectorOK, Name: s.Name, Posture: s.Posture, Identity: s.Identity, Managed: s.Managed,
		}
	}
}

// buildProviders probes the environment and assembles the auth.Provider list
// from cfg's per-connector hardening settings, streaming a connector-inventory
// line per resolved connector to d.errOut and returning the collected views.
func (d *deps) buildProviders(cfg config.Config, verbose bool) ([]auth.Provider, []ui.ConnectorView) {
	hc := auth.HardeningConfig{
		Github: auth.GithubHardeningConfig{
			Permissions: cfg.Connectors.Github.Permissions,
			Config: cache.Config{
				Dir:   filepath.Join(cfg.Cache.Dir, "github"),
				TTL:   cfg.Cache.TTL,
				Clock: time.Now,
			},
		},
		GitLab: auth.GitLabHardeningConfig{
			Host:                cfg.Connectors.GitLab.Host,
			APIHost:             cfg.Connectors.GitLab.APIHost,
			AllowPrivateNetwork: cfg.Connectors.GitLab.AllowPrivateNetwork,
			CACertPath:          cfg.Connectors.GitLab.CACert,
			Permissions:         cfg.Connectors.GitLab.Permissions,
			Config: cache.Config{
				Dir:   filepath.Join(cfg.Cache.Dir, "gitlab"),
				TTL:   cfg.Cache.TTL,
				Clock: time.Now,
			},
		},
		AWS: auth.AWSHardeningConfig{
			PolicyARN: cfg.Connectors.AWS.Policy,
			Config:    cache.Config{Dir: filepath.Join(cfg.Cache.Dir, "aws"), TTL: cfg.Cache.TTL, Clock: time.Now},
		},
		EKS: auth.EKSHardeningConfig{ClusterRole: cfg.Connectors.EKS.ClusterRole},
		GCP: auth.GCPHardeningConfig{
			Role:   cfg.Connectors.GCP.Role,
			Config: cache.Config{Dir: filepath.Join(cfg.Cache.Dir, "gcp"), TTL: cfg.Cache.TTL, Clock: time.Now},
		},
		GKE: auth.GKEHardeningConfig{ClusterRole: cfg.Connectors.GKE.ClusterRole},
		Azure: auth.AzureHardeningConfig{
			RoleDefinition: cfg.Connectors.Azure.RoleDefinition,
			Cloud:          cfg.Connectors.Azure.Cloud,
			Config: cache.Config{
				Dir:   filepath.Join(cfg.Cache.Dir, "azure"),
				TTL:   cfg.Cache.TTL,
				Clock: time.Now,
			},
		},
		AKS:        auth.AKSHardeningConfig{ClusterRole: cfg.Connectors.AKS.ClusterRole},
		Kubernetes: auth.KubernetesHardeningConfig{ClusterRole: cfg.Connectors.Kubernetes.ClusterRole},
	}

	var views []ui.ConnectorView
	providers := d.getProviders(hc, verbose, func(s auth.ConnectorStatus) {
		v := statusToView(s)
		views = append(views, v)
		d.ui.RenderConnector(d.errOut, v)
	})

	return providers, views
}

// buildToolSet builds the approval-wrapped tool set (http_request + code_execution)
// from the given providers, config, flags, verbose writer, and audit sink.
func (d *deps) buildToolSet(
	providers []auth.Provider,
	cfg config.Config,
	flags researchFlags,
	verboseWriter io.Writer,
	sink audit.Sink,
) ([]schema.InvokableTool, error) {
	httpTool, err := d.newHTTPRequestTool(providers)
	if err != nil {
		return nil, fmt.Errorf("build http_request tool: %w", err)
	}

	// Primitives are exposed (raw) inside the sandbox; the code tool wraps them.
	primitives := []schema.InvokableTool{httpTool}

	codeTool, err := d.newCodeExecutionTool(primitives, verboseWriter, cfg.SandboxMaxConcurrency, sink)
	if err != nil {
		return nil, fmt.Errorf("build code_execution tool: %w", err)
	}

	prompter := d.ui.PromptToolApproval
	if flags.autoApprove {
		prompter = d.ui.AutoApproveToolCall
	}

	// Approval-wrap every primitive plus the code tool. With --auto-approve the
	// prompter prints and approves each call without pausing.
	toolSet := make([]schema.InvokableTool, 0, len(primitives)+1)
	for _, p := range primitives {
		toolSet = append(toolSet, tools.NewApprovalTool(p, prompter, cfg.RenderStyle))
	}

	return append(toolSet, tools.NewApprovalTool(codeTool, prompter, cfg.RenderStyle)), nil
}

// interactiveLoop runs the follow-up prompt loop until the user exits or EOF.
// Until the session is established (no welcome / no successful first turn yet),
// the FIRST turn's LLM-generation failure aborts cleanly (ErrLLMUnavailable);
// once a turn has succeeded, transient turn errors print and the loop continues.
// The ✓ LLM block is rendered by the agent's OnFirstResponse hook (showLLMOnce)
// and does not need a separate parameter here. The session summary footer renders
// once on exit (deferred), gated on RoundTrips > 0.
func (d *deps) interactiveLoop(
	ctx context.Context, a *agent.Agent, acc *metrics.Accumulator,
	cfg config.Config, established bool,
) error {
	defer d.renderSessionFooter(acc)

	for {
		input, ok := d.ui.PromptUserInput("\n> ")
		if !ok || isExitCommand(input) {
			return nil
		}

		if input == "" {
			continue
		}

		respBefore := acc.Snapshot().Responses
		err := a.Run(ctx, input, d.out)
		d.ui.RenderFooter(acc.TurnSnapshot(), "turn")
		if err == nil {
			established = true

			continue
		}

		origErr := err
		var cont bool
		established, cont, err = d.handleTurnError(ctx, acc, cfg, origErr, established, respBefore)
		if cont {
			continue
		}

		if err != nil {
			return err
		}

		fmt.Fprintf(d.errOut, "\n⚠️  Error: %v\n", origErr)
	}
}

// handleTurnError classifies an interactive-turn error and decides how to
// proceed. It returns the (potentially updated) established flag, whether the
// loop should continue to the next prompt (cont=true), and a non-nil error when
// the session must terminate. A nil error + cont=false means the error should be
// printed and the loop continues.
func (d *deps) handleTurnError(
	ctx context.Context, acc *metrics.Accumulator, cfg config.Config,
	err error, established bool, respBefore int,
) (bool, bool, error) {
	if errors.Is(err, agent.ErrInterrupted) {
		// The interrupt notice was already rendered inside Run; resume the loop.
		// Promote to established ONLY if the model actually responded this turn:
		// an interrupt after the LLM started responding proves liveness, so a
		// later transient llm.ErrGenerate is a normal turn error rather than a
		// failed-startup abort. A pre-Generate interrupt (no response) proves
		// nothing, so established is left unchanged.
		if modelResponded(acc, respBefore) {
			established = true
		}

		return established, true, nil
	}

	// A context cancellation (e.g. SIGTERM or a parent cancel) wraps its error
	// via Bifrost as llm.ErrGenerate; check the context before classifying so a
	// canceled first turn is treated as a graceful shutdown, not a dead-LLM abort.
	if ctx.Err() != nil {
		return established, false, err
	}

	if !established && errors.Is(err, llm.ErrGenerate) {
		// Only abort as a dead LLM when the model never responded this turn
		// (no successful Generate). If it responded at least once, the LLM was
		// live; treat the error as transient and set established = true so
		// subsequent turns are handled by the normal log-and-continue path.
		if !modelResponded(acc, respBefore) {
			d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, err))

			return established, false, ErrLLMUnavailable
		}

		established = true
	}

	if classifyTurnError(err) {
		return established, false, err
	}

	// Transient error: print and continue; nil termErr signals print-and-continue.
	return established, false, nil
}

// renderSessionFooter renders the once-per-session summary footer, gated on the
// session having done at least one model round-trip — so a session that ran nothing
// (e.g. an immediate exit with no welcome) prints no summary, while a session whose
// only activity was the welcome greeting still reports that cost.
func (d *deps) renderSessionFooter(acc *metrics.Accumulator) {
	if s := acc.Snapshot(); s.RoundTrips > 0 {
		d.ui.RenderFooter(s, "session")
	}
}

// showLLMOnce returns the OnFirstResponse hook: it renders the ✓ LLM status block
// to errOut exactly once per session (across the welcome, the seeded turn, and the
// loop). Routed to errOut — never out — so a -p one-shot keeps stdout clean while
// still showing the block, giving consistent placement (right after Connectors,
// before the model response) in every mode.
func (d *deps) showLLMOnce(cfg config.Config, llmShown *bool) func() {
	return func() {
		if *llmShown {
			return
		}
		*llmShown = true
		d.ui.RenderLLM(d.errOut, llmOKStatus(cfg))
	}
}

// classifyTurnError reports whether a turn error must end the interactive
// session. An audit-write failure (fail-closed) terminates; other (transient)
// errors are printed and the loop continues.
func classifyTurnError(err error) bool {
	return errors.Is(err, audit.ErrLog)
}

const (
	exitCommand = "exit"
	quitCommand = "quit"
)

// isExitCommand returns true when the user wants to end the interactive session.
func isExitCommand(input string) bool {
	lower := strings.ToLower(input)

	return lower == exitCommand || lower == quitCommand
}
