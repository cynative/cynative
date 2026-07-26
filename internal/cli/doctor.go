package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/ui"
)

// doctorProbePromptFmt is the tool-less live probe (same spirit as
// test/llm.smoke.test.sh): the model must echo the nonce.
const doctorProbePromptFmt = "Reply with exactly this token and nothing else: %s"

// newDoctorCmd returns the `cynative doctor` subcommand. Config is loaded by the
// root PersistentPreRunE before RunE; without --live-llm, doctor never constructs
// a chat model or runs tools — it only prints the startup inventory and
// structural LLM status. With --live-llm it additionally performs one tool-less
// Generate after ValidateLLM passes.
func newDoctorCmd(d *deps) *cobra.Command {
	var verbose, liveLLM bool

	cmd := &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:   "doctor",
		Short: "Validate configuration and connector readiness",
		Long: `Validate configuration and connector readiness without starting a research session.

Prints the same stderr startup inventory as a normal run (banner, connectors,
LLM structural status). Connector checks may perform live read-only network
calls. The LLM check is configuration-only unless --live-llm is set. Does not
open an interactive session or run tools.

Exit 0 when the LLM block is valid (and, with --live-llm, reachable) and no
actionable connector failures are present. Exit 1 on config-load failure,
ValidateLLM failure, a failed --live-llm probe (ErrLLMUnavailable), or an
actionable connector readiness failure. Ambient "no credentials" skips shown
only under --verbose do not change the result.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return silenceGracefulStop(cmd, d.runDoctor(cmd.Context(), d.cfg, verbose, liveLLM))
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Show skipped connectors; with --live-llm, also print redacted probe errors")
	cmd.Flags().BoolVar(&liveLLM, "live-llm", false,
		"Probe the configured LLM with a live tool-less round-trip after structural validation")

	return cmd
}

// connectorHealth summarizes inventory outcomes for doctor readiness. Actionable
// failures are independent of --verbose: ambient absences stay non-actionable
// even when verbose surfaces them.
type connectorHealth struct {
	actionableFailures []string
}

func connectorHealthFromViews(views []ui.ConnectorView) connectorHealth {
	var h connectorHealth
	for _, v := range views {
		if v.State == ui.ConnectorError && v.Actionable {
			h.actionableFailures = append(h.actionableFailures, v.Name)
		}
	}

	return h
}

func (h connectorHealth) ok() bool {
	return len(h.actionableFailures) == 0
}

// llmDoctorOKStatus is the doctor ✓ line: structural config valid, no live probe.
func llmDoctorOKStatus(cfg config.Config) ui.LLMStatus {
	return ui.LLMStatus{ //nolint:exhaustruct // doctor OK: no hint/onboarding fields.
		State:    ui.ConnectorOK,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
		Reason:   "configuration valid; connectivity not tested",
	}
}

// llmDoctorLiveOKStatus is the doctor ✓ line after a successful --live-llm probe.
func llmDoctorLiveOKStatus(cfg config.Config) ui.LLMStatus {
	return ui.LLMStatus{ //nolint:exhaustruct // doctor OK: no hint/onboarding fields.
		State:    ui.ConnectorOK,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
		Reason:   "configuration valid; connectivity verified",
	}
}

// llmDoctorProbeMismatchStatus is the ✗ line when Generate succeeds but the
// response does not echo the probe nonce (not a GenerateError, so llmRuntimeStatus
// would mis-bucket it as a connectivity failure).
func llmDoctorProbeMismatchStatus(cfg config.Config) ui.LLMStatus {
	return ui.LLMStatus{ //nolint:exhaustruct // mismatch: Reason/Hint only.
		State:    ui.ConnectorError,
		Provider: cfg.LLM.Provider,
		Model:    cfg.LLM.Model,
		Reason:   "live probe response mismatch",
		Hint:     "The model answered but did not echo the probe token. Check llm.model and retry.",
	}
}

// runDoctor prints banner → connector inventory → LLM status and returns
// ErrLLMUnavailable or ErrDoctorNotReady when health checks fail.
// Ambient connector absences (verbose-only) do not fail the command.
// With liveLLM, a tool-less Generate runs only after ValidateLLM passes.
func (d *deps) runDoctor(ctx context.Context, cfg config.Config, verbose, liveLLM bool) error {
	d.ui.RenderBanner(d.errOut)

	_, views := d.buildProviders(cfg, verbose)
	if len(views) == 0 {
		fmt.Fprintln(d.errOut, "  (no connectors detected)")
	}
	health := connectorHealthFromViews(views)

	if verr := config.ValidateLLM(&cfg.LLM); verr != nil {
		d.ui.RenderLLM(d.errOut, llmConfigStatus(cfg, verr))
		fmt.Fprintln(d.errOut, "Doctor: not ready")
		fmt.Fprintln(d.errOut, "  Connector checks may perform live read-only network calls.")

		return ErrLLMUnavailable
	}

	if liveLLM {
		if err := d.probeLiveLLM(ctx, cfg, verbose); err != nil {
			fmt.Fprintln(d.errOut, "Doctor: not ready")
			fmt.Fprintln(d.errOut, "  Connector checks may perform live read-only network calls.")

			return ErrLLMUnavailable
		}
		d.ui.RenderLLM(d.errOut, llmDoctorLiveOKStatus(cfg))
	} else {
		d.ui.RenderLLM(d.errOut, llmDoctorOKStatus(cfg))
	}

	fmt.Fprintln(d.errOut, "  Connector checks may perform live read-only network calls.")

	if !health.ok() {
		fmt.Fprintf(d.errOut, "Doctor: not ready (connector failures: %s)\n",
			strings.Join(health.actionableFailures, ", "))

		return ErrDoctorNotReady
	}

	fmt.Fprintln(d.errOut, "Doctor: ready")

	return nil
}

// probeLiveLLM constructs the chat model, sends a tool-less nonce-echo prompt,
// and requires the nonce in the assistant text (case-insensitive). On failure it
// renders an LLM ✗ status; when verbose is set it also prints a redacted details
// line so the "-v for details" hint from llmRuntimeStatus is actionable. The
// caller returns ErrLLMUnavailable.
func (d *deps) probeLiveLLM(ctx context.Context, cfg config.Config, verbose bool) error {
	cm, err := d.newChatModel(ctx, cfg, func(schema.Usage) {})
	if err != nil {
		d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, err))
		d.printDoctorProbeDetails(verbose, err)

		return err
	}
	defer cm.Shutdown()

	nonce := d.newDoctorProbeNonce()
	msg, err := cm.Generate(ctx, []*schema.Message{
		schema.UserMessage(fmt.Sprintf(doctorProbePromptFmt, nonce)),
	}, nil)
	if err != nil {
		d.ui.RenderLLM(d.errOut, llmRuntimeStatus(cfg, err))
		d.printDoctorProbeDetails(verbose, err)

		return err
	}
	// Case-insensitive: some models normalize token casing in the echo.
	if msg == nil || !strings.Contains(strings.ToLower(msg.Text()), strings.ToLower(nonce)) {
		d.ui.RenderLLM(d.errOut, llmDoctorProbeMismatchStatus(cfg))

		return fmt.Errorf("%w: live probe response mismatch", ErrLLMUnavailable)
	}

	return nil
}

// printDoctorProbeDetails writes a redacted provider error when -v is set.
// Doctor does not wrap the probe model in RedactingChatModel, so this is the
// boundary that keeps credential-shaped text off stderr.
func (d *deps) printDoctorProbeDetails(verbose bool, err error) {
	if !verbose || err == nil {
		return
	}
	fmt.Fprintf(d.errOut, "  details: %s\n", redact.New().Redact(err.Error()))
}
