package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/config"
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
LLM structural status). Does not call the LLM, open an interactive session, or
run tools. Exit 0 when the LLM block is valid; exit 1 on config-load or
ValidateLLM failure.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return silenceGracefulStop(cmd, d.runDoctor(d.cfg, verbose))
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Show skipped connectors that are normally hidden")

	return cmd
}

// runDoctor prints banner → connector inventory → LLM structural status and
// returns ErrLLMUnavailable when ValidateLLM fails. Connector absence is
// informational and does not fail the command.
func (d *deps) runDoctor(cfg config.Config, verbose bool) error {
	d.ui.RenderBanner(d.errOut)

	_, views := d.buildProviders(cfg, verbose)
	if len(views) == 0 {
		fmt.Fprintln(d.errOut, "  (no connectors detected)")
	}

	if verr := config.ValidateLLM(&cfg.LLM); verr != nil {
		d.ui.RenderLLM(d.errOut, llmConfigStatus(cfg, verr))

		return ErrLLMUnavailable
	}

	d.ui.RenderLLM(d.errOut, llmOKStatus(cfg))
	fmt.Fprintln(d.errOut, "Doctor: ready")

	return nil
}
