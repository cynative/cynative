package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/interrupt"
	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/ui"
	"github.com/cynative/cynative/internal/version"
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

// newDeps wires the production collaborators for the cli. It is the composition
// root: the only place that reads the real environment — [os.LookupEnv] (via the
// config loader), the auth providers, stdio, and the glamour-backed UI — so it
// lives in the shell, excluded from the coverage gate.
func newDeps() *deps {
	//nolint:gosec // Fd() returns a uintptr that is always a valid small int.
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
		newHTTPRequestTool: func(providers []auth.Provider) (schema.InvokableTool, error) {
			return tools.NewHTTPRequestTool(providers)
		},
		newCodeExecutionTool: tools.NewCodeExecutionTool,
		newAuditSink: func(cfg config.Config) (audit.Sink, func() error, error) {
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

			return audit.New(w, audit.WithActor(cfg.LLM.Provider+"/"+cfg.LLM.Model)), w.Close, nil
		},
		newAgent:    agent.New,
		ui:          newUI(inR, promptW, editor, ctrl, state.Interrupted),
		out:         os.Stdout,
		errOut:      os.Stderr,
		cfg:         config.Config{}, //nolint:exhaustruct // populated by PersistentPreRunE.
		stdinIsTTY:  stdinIsTTY,
		hasTerminal: hasTerminal,
		readStdin:   readStdin,
		interrupter: interrupter,
		version:     version.Get().String(),
	}
	d.run = d.runResearch

	return d
}
