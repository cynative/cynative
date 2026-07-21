package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/ui"
)

// newDoctorCmd returns the `cynative doctor` subcommand. Config is loaded by the
// root PersistentPreRunE before RunE; doctor never constructs a chat model or
// runs tools — it only prints the startup inventory and structural LLM status.
func newDoctorCmd(d *deps) *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:   "doctor",
		Short: "Validate configuration and connector readiness",
		Long: `Validate configuration and connector readiness without starting a research session.

Prints the same stderr startup inventory as a normal run (banner, connectors,
LLM structural status). Connector checks may perform live read-only network
calls. The LLM check is configuration-only (connectivity is not tested). Does
not call the LLM, open an interactive session, or run tools.

Exit 0 when the LLM block is valid and no actionable connector failures are
present. Exit 1 on config-load failure, ValidateLLM failure, or an actionable
connector readiness failure (structural errors and explicitly configured
connectors that failed live checks). Ambient "no credentials" skips shown only
under --verbose do not change the result.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return silenceGracefulStop(cmd, d.runDoctor(d.cfg, verbose))
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Show skipped connectors that are normally hidden (does not change readiness)")

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

// runDoctor prints banner → connector inventory → LLM structural status and
// returns ErrLLMUnavailable or ErrDoctorNotReady when health checks fail.
// Ambient connector absences (verbose-only) do not fail the command.
func (d *deps) runDoctor(cfg config.Config, verbose bool) error {
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

	d.ui.RenderLLM(d.errOut, llmDoctorOKStatus(cfg))
	fmt.Fprintln(d.errOut, "  Connector checks may perform live read-only network calls.")

	if !health.ok() {
		fmt.Fprintf(d.errOut, "Doctor: not ready (connector failures: %s)\n",
			strings.Join(health.actionableFailures, ", "))

		return ErrDoctorNotReady
	}

	fmt.Fprintln(d.errOut, "Doctor: ready")

	return nil
}
