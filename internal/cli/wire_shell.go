package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/cynative/cynative"
	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/agentcatalog"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/interrupt"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/ui"
)

// maxStdinBytes caps piped stdin folded into the task (1 MiB) so an unbounded or
// huge stream cannot exhaust memory before the agent's token budget applies.
const maxStdinBytes = 1 << 20

// editorTarget carries a controlling terminal capable of raw-mode line editing.
// It is nil when no editor-capable TTY exists (non-unix, or no /dev/tty).
type editorTarget struct {
	rw io.ReadWriter
	fd int
}

// newUI builds the production UI: the raw-mode editor (plus the cbreak controller
// for single-key approval) when an editor-capable TTY exists, else the cooked
// scanner over the resolved reader/writer.
func newUI(
	inR io.Reader, promptW io.Writer, editor *editorTarget, ctrl *ui.TerminalController, interrupted func() bool,
) *ui.UI {
	if editor != nil {
		opts := []ui.Option{ui.WithTerminalEditor(editor.rw, editor.fd), ui.WithInterruptCheck(interrupted)}
		if ctrl != nil { // a typed-nil *TerminalController would satisfy the Controller interface and panic on first approval.
			opts = append(opts, ui.WithController(ctrl))
		}

		return ui.New(opts...)
	}

	return ui.New(ui.WithInput(inR), ui.WithPromptWriter(promptW), ui.WithInterruptCheck(interrupted))
}

// readStdin drains [os.Stdin] up to the cap, repairs invalid UTF-8, and reports
// whether the input was truncated. Only called when stdin is not a TTY.
func readStdin() (string, bool, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("read stdin: %w", err)
	}

	truncated := len(data) > maxStdinBytes
	if truncated {
		data = data[:maxStdinBytes]
	}

	return strings.ToValidUTF8(string(data), ""), truncated, nil
}

// buildController constructs the cbreak terminal controller for an editor-capable
// TTY, binding the shared interrupt state. It returns nil when no editor exists or
// the controller cannot be built (then the signal-only interrupter is used). Shell:
// [ui.NewTerminalController] calls [term.GetState], which is untestable I/O.
func buildController(editor *editorTarget, state *interrupt.State) *ui.TerminalController {
	if editor == nil {
		return nil
	}

	ctrl, err := ui.NewTerminalController(editor.fd, state)
	if err != nil || ctrl == nil {
		return nil
	}

	return ctrl
}

// newAuditSinkShell opens the audit log and stamps it with the actor and, when
// an agent framed the run, its provenance.
//
// It is a named function rather than an inline closure in newDeps because
// gocyclo/gocognit attribute a closure's branches to its enclosing function,
// and newDeps already carries the controller branches; inlining this pushes it
// past the complexity-6 shell budget.
func newAuditSinkShell(cfg config.Config, prov *audit.AgentProvenance) (audit.Sink, func() error, error) {
	if !cfg.Audit.Enabled {
		return nil, func() error { return nil }, nil
	}

	w, err := audit.Open(audit.FileConfig{
		Path:          cfg.Audit.Path,
		MaxSizeMB:     cfg.Audit.MaxSizeMB,
		RetentionDays: cfg.Audit.RetentionDays,
		Compress:      cfg.Audit.Compress,
	})
	if err != nil {
		return nil, nil, err // runResearch wraps with "open audit log:".
	}

	opts := []audit.Option{audit.WithActor(cfg.LLM.Provider + "/" + cfg.LLM.Model)}
	if prov != nil {
		opts = append(opts, audit.WithAgent(*prov))
	}

	return audit.New(w, opts...), w.Close, nil
}

// openAgentCatalogShell builds the production agent catalog from the operator's
// home directory and the embedded built-ins.
//
// The working directory is deliberately not consulted: agents are
// operator-authored configuration, so a checkout must not be able to supply the
// prompt for a run.
func openAgentCatalogShell() (*agentcatalog.Catalog, func(), error) {
	home, err := resolveHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve home directory: %w", err)
	}

	return agentcatalog.OpenSources(home, cynative.BuiltinAgents())
}

// resolveDir returns get()'s directory with symlinks resolved.
func resolveDir(get func() (string, error)) (string, error) {
	dir, err := get()
	if err != nil {
		return "", err
	}

	return filepath.EvalSymlinks(dir)
}

// resolveHomeDir resolves the home directory, tolerating one that does not
// exist.
//
// A minimal container can set an absolute $HOME that was never created. Failing
// here would abort the whole catalog, so even `cynative agents list` could not
// inspect the built-in tier. An unresolvable home is returned cleaned-and-
// absolute instead: OpenSources then finds no user agents directory and skips
// that tier.
func resolveHomeDir() (string, error) {
	home, err := resolveDir(os.UserHomeDir)
	if err == nil {
		return home, nil
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	raw, rerr := os.UserHomeDir()
	if rerr != nil {
		return "", rerr
	}

	return filepath.Clean(raw), nil
}

// newDeps wires the production collaborators for the cli. It is the composition
// root: the only place that reads the real environment — [os.LookupEnv] (via the
// config loader), the auth providers, stdio, and the glamour-backed UI — so it
// lives in the shell, excluded from the coverage gate.
func newDeps() *deps {
	stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
	inR, promptW, hasTerminal, editor := resolveInteraction()

	state := &interrupt.State{}               //nolint:exhaustruct // mutex/bools zero-value start.
	var interrupter agent.Interrupter = state // non-editor: signal-only two-stage.
	var restore func()
	ctrl := buildController(editor, state)
	if ctrl != nil {
		interrupter = ctrl     // editor TTY: the controller IS the interrupter (cbreak + watcher).
		restore = ctrl.Restore // the signal handler restores the tty via the controller.
	}
	installSignalHandler(state, restore)

	d := &deps{
		loadConfig: func(cfgFile string) (config.Config, error) {
			return config.NewLoader(os.LookupEnv).Load(cfgFile)
		},
		run:          nil, // set below to the runResearch method bound to d.
		getProviders: auth.GetProviders,
		newChatModel: func(ctx context.Context, cfg config.Config, recordUsage func(schema.Usage)) (chatModel, error) {
			return llm.NewBifrostChatModel(
				ctx,
				&llm.FileAccount{Entry: cfg.LLM},
				llm.WithUsageRecorder(recordUsage),
			)
		},
		newHTTPRequestTool:   tools.NewHTTPRequestTool,
		newCodeExecutionTool: tools.NewCodeExecutionTool,
		newAuditSink:         newAuditSinkShell,
		openAgentCatalog:     openAgentCatalogShell,
		newAgent:             agent.New,
		ui:                   newUI(inR, promptW, editor, ctrl, state.Interrupted),
		out:                  os.Stdout,
		errOut:               os.Stderr,
		cfg:                  config.Config{}, //nolint:exhaustruct // populated by PersistentPreRunE.
		stdinIsTTY:           stdinIsTTY,
		hasTerminal:          hasTerminal,
		readStdin:            readStdin,
		interrupter:          interrupter,
		version:              versionString(),
		newDoctorProbeNonce:  doctorProbeNonce,
	}
	d.run = d.runResearch

	return d
}
