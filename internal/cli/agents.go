package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/agentcatalog"
)

// agentsCmdName is the parent command name; skipsConfigLoad matches on it, so
// both leaves inherit the skip through cobra's parent chain.
const agentsCmdName = "agents"

// newAgentsCmd returns the `cynative agents` command group. Neither leaf loads
// config or touches credentials: `agents list` must work on a fresh install
// before anything is configured.
func newAgentsCmd(d *deps) *cobra.Command {
	cmd := &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:   agentsCmdName,
		Short: "Inspect the named agents available to this machine",
		Long: `Inspect the named agents available to this machine.

Agents are markdown files supplying the prompt for a run. They are searched in
three sources, first match wins: .cynative/agents/ (nearest walking up from the
working directory, bounded by the repository root), ~/.cynative/agents/, and the
agents built into the binary.

Cynative never creates these directories. To add your own, run
"mkdir -p ~/.cynative/agents" and write a markdown file there.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newAgentsListCmd(d), newAgentsShowCmd(d))

	return cmd
}

// newAgentsListCmd returns `cynative agents list`.
func newAgentsListCmd(d *deps) *cobra.Command {
	return &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:   "list",
		Short: "List every available agent, marking shadowed and unusable ones",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return d.runAgentsList()
		},
	}
}

// newAgentsShowCmd returns `cynative agents show <name>`.
func newAgentsShowCmd(d *deps) *cobra.Command {
	return &cobra.Command{ //nolint:exhaustruct // optional cobra fields intentionally omitted
		Use:               "show <name>",
		Short:             "Print the agent file that --agent <name> would run",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: d.completeAgentNames,
		RunE: func(_ *cobra.Command, args []string) error {
			return d.runAgentsShow(args[0])
		},
	}
}

// runAgentsList prints the catalog table. A per-file problem is reported as a
// row; only a source that cannot be enumerated at all fails the command, since
// that makes the precedence view itself untrustworthy.
func (d *deps) runAgentsList() error {
	catalog, cleanup, err := d.openAgentCatalog()
	if err != nil {
		return sanitizeErr(fmt.Errorf("open agent sources: %w", err))
	}

	defer cleanup()

	entries, err := catalog.List()
	if err != nil {
		return sanitizeErr(fmt.Errorf("list agents: %w", err))
	}

	table := formatAgentList(entries)

	n, err := io.WriteString(d.out, table)
	if err != nil {
		return fmt.Errorf("write agent list: %w", err)
	}
	// io.Writer requires a non-nil error when n < len, but a non-compliant
	// writer must not be allowed to truncate the listing and still exit zero.
	if n < len(table) {
		return fmt.Errorf("write agent list: %w", io.ErrShortWrite)
	}

	return nil
}

// runAgentsShow writes the exact raw file bytes to stdout and the sanitized
// source path to stderr, so `cynative agents show x > x.md` round-trips.
func (d *deps) runAgentsShow(name string) error {
	if err := agentcatalog.ValidName(name); err != nil {
		return err
	}

	catalog, cleanup, err := d.openAgentCatalog()
	if err != nil {
		return sanitizeErr(fmt.Errorf("open agent sources: %w", err))
	}

	defer cleanup()

	def, err := catalog.Resolve(name)
	if err != nil {
		return sanitizeErr(annotateResolveError(err, catalog))
	}

	fmt.Fprintf(d.errOut, "source: %s (%s)\n", sanitizeInline(def.Path), sanitizeInline(def.Source.String()))

	// The bytes are written verbatim: this is the round-trip contract, so no
	// sanitizing here. A short or failed write must be an error, or
	// `cynative agents show x > x.md` could exit zero having truncated the file.
	n, err := d.out.Write(def.Raw)
	if err != nil {
		return fmt.Errorf("write agent file: %w", err)
	}
	if n < len(def.Raw) {
		return fmt.Errorf("write agent file: %w", io.ErrShortWrite)
	}

	return nil
}

// formatAgentList renders the catalog table. SOURCE is the tier word alone: no
// filesystem paths are printed, so there is nothing path-shaped to sanitize
// here. `agents show` is where a path is surfaced.
func formatAgentList(entries []agentcatalog.Entry) string {
	if len(entries) == 0 {
		return "No agents found. Add one at ~/.cynative/agents/<name>.md " +
			"(cynative does not create the directory).\n"
	}

	// listPadding is the gap tabwriter leaves between columns.
	const listPadding = 2

	var b strings.Builder

	w := tabwriter.NewWriter(&b, 0, 0, listPadding, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tSOURCE\tSTATUS")

	// The claimant is the row that is NOT shadowed, which is authoritative
	// however the rows happen to be ordered. Taking "the first row for this
	// name" instead would be wrong: List sorts ties by the Source enum, while
	// Catalog.New takes caller-supplied root order, so the two disagree the
	// moment roots are registered in a non-canonical order.
	claimant := claimantsOf(entries)

	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			sanitizeInline(e.Name),
			sanitizeInline(e.Description),
			e.Source,
			agentStatus(e, claimant[e.Name]),
		)
	}

	// Flushing into a strings.Builder cannot fail: Builder.Write never errors.
	_ = w.Flush()

	return b.String()
}

// claimantsOf maps each name to the source that claimed it: the one row for
// that name which is not shadowed. Every other row for the name lost to it,
// whether it won outright or blocked as invalid.
func claimantsOf(entries []agentcatalog.Entry) map[string]agentcatalog.Source {
	out := make(map[string]agentcatalog.Source, len(entries))

	for _, e := range entries {
		if !e.Shadowed {
			out[e.Name] = e.Source
		}
	}

	return out
}

// agentStatus renders one entry's STATUS cell. by is the source that claimed
// this name, which for a shadowed row is always a higher-precedence one.
//
// A blocking claimant produces no active winner for its name, which is the
// listing's rendering of the fail-closed resolution rule rather than a separate
// policy. A shadowed entry that is itself invalid says both, so a stack of
// broken files is visible instead of collapsing into one line.
func agentStatus(e agentcatalog.Entry, by agentcatalog.Source) string {
	switch {
	case e.Shadowed && e.Err != nil:
		return fmt.Sprintf("shadowed by %s, invalid", by)
	case e.Shadowed:
		return fmt.Sprintf("shadowed by %s", by)
	case e.Err != nil:
		return "invalid (blocking)"
	default:
		return "active"
	}
}
