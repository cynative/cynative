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
(pipe input with "cat file | cynative -p \"...\"").

Shell completions: "cynative completion bash|zsh|fish|powershell" prints a script
(no config required; see each subcommand's --help for install instructions).

Use "cynative doctor" to validate configuration and connector readiness without
starting a research session.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// completion / __complete must work on a fresh install before any
			// config exists — same short-circuit spirit as --version/--help.
			if skipsConfigLoad(cmd) {
				return nil
			}

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

	// Version enables cobra's built-in --version flag, which short-circuits in
	// Execute() before ValidateArgs/PersistentPreRunE — so `cynative --version`
	// prints and exits without loading config or credentials. We registered
	// --verbose/-v above, so by the time cobra's InitDefaultVersionFlag runs (at
	// Execute) the -v shorthand is taken and --version gets none (we add no -V).
	rootCmd.Version = d.version
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	rootCmd.AddCommand(newDoctorCmd(d))

	return rootCmd
}

// silenceGracefulStop suppresses Cobra's duplicate "Error: ..." line for a graceful
// operator interrupt — the agent already rendered the stop notice — while still
// returning the error so ExitCodeFor maps it to 130. Any other error prints as usual.
func silenceGracefulStop(cmd *cobra.Command, err error) error {
	if errors.Is(err, agent.ErrInterrupted) || errors.Is(err, ErrLLMUnavailable) ||
		errors.Is(err, ErrDoctorNotReady) {
		cmd.SilenceErrors = true
	}

	return err
}

// skipsConfigLoad reports whether cmd is under Cobra's completion tree
// (`completion` or the hidden `__complete` / `__completeNoDesc` request
// commands). Those paths must not touch config or credentials.
func skipsConfigLoad(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return true
		}
	}

	return false
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
