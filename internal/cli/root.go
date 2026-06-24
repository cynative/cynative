package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/agent"
)

// NewRootCmd creates the root cobra.Command bound to d. The root is itself the
// run command: `cynative -p "task"` runs once, bare `cynative` opens an
// interactive session. Config is loaded in PersistentPreRunE and stored on d.
func NewRootCmd(d *deps) *cobra.Command {
	var (
		cfgFile   string
		printMode bool
		flags     researchFlags
	)

	rootCmd := &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:          "cynative [flags] [task]",
		Short:        "Agentic Security Research",
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
		Long: `Agentic security research tool that lives in your terminal.
Understands your codebase and infrastructure, identifies vulnerabilities and misconfigurations.
Reasons about exploit paths, and drafts remediations.

Run "cynative" with no arguments to start an interactive session, or pass a task
to seed it. Use -p/--print to run a single task non-interactively and exit
(pipe input with "cat file | cynative -p \"...\"").`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := d.loadConfig(cfgFile)
			if err != nil {
				return err
			}
			d.cfg = cfg

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return silenceGracefulStop(cmd, d.runRoot(cmd.Context(), args, printMode, flags))
		},
	}

	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cynative/config.yaml)")
	rootCmd.Flags().
		BoolVarP(&printMode, "print", "p", false, "Run a single task non-interactively and print the result")
	rootCmd.Flags().BoolVar(&flags.autoApprove, "auto-approve", false, "Skip interactive approval for tool calls")
	rootCmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Print tool call outputs to stderr")

	return rootCmd
}

// silenceGracefulStop suppresses Cobra's duplicate "Error: ..." line for a graceful
// operator interrupt — the agent already rendered the stop notice — while still
// returning the error so ExitCodeFor maps it to 130. Any other error prints as usual.
func silenceGracefulStop(cmd *cobra.Command, err error) error {
	if errors.Is(err, agent.ErrInterrupted) || errors.Is(err, ErrLLMUnavailable) {
		cmd.SilenceErrors = true
	}

	return err
}

// Execute wires the production dependencies and runs the root command.
func Execute() error {
	rootCmd := NewRootCmd(newDeps())

	err := rootCmd.Execute()
	if err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
