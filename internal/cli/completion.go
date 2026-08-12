package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// completeAgentNames completes --agent values and `agents show` arguments.
//
// It enumerates filenames only: no body is parsed, no directory is created, no
// config is loaded, no connector is probed and no audit log is opened, so it
// stays inside the no-config, no-credentials completion invariant that lets a
// fresh install complete before it is configured.
//
// It fails quietly. A filesystem error during completion must emit nothing
// rather than leak an error string into the shell's completion protocol. A name
// whose highest-precedence claimant is unusable is still offered: hiding it
// would conceal the name the operator has to fix.
func (d *deps) completeAgentNames(_ *cobra.Command, _ []string, toComplete string) (
	[]string, cobra.ShellCompDirective,
) {
	catalog, cleanup, err := d.openAgentCatalog()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	defer cleanup()

	names, err := catalog.Names()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var out []string

	for _, n := range names {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}

	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeAgentArg completes the single positional argument of
// `agents show <name>`.
//
// It is separate from completeAgentNames because the same names are offered in
// two places with different arity. The root command takes a positional task
// ALONGSIDE --agent, so cobra passes that task through the flag callback's args;
// an arity guard shared with the flag would silently stop offering agents for
// `cynative "audit prod" --agent <TAB>`. Only `show` is single-argument.
func (d *deps) completeAgentArg(cmd *cobra.Command, args []string, toComplete string) (
	[]string, cobra.ShellCompDirective,
) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return d.completeAgentNames(cmd, args, toComplete)
}
