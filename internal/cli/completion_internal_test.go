package cli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/agentcatalog"
	"github.com/cynative/cynative/internal/config"
)

func agentFS() fstest.MapFS {
	src := []byte("---\ndescription: d\n---\nbody\n")
	file := &fstest.MapFile{Data: src} //nolint:exhaustruct // Mode defaults.

	return fstest.MapFS{"alpha.md": file, "beta.md": file, "alps.md": file}
}

func TestCompleteAgentNames_PrefixFiltered(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.openAgentCatalog = catalogOver(agentFS())

	got, directive := d.completeAgentNames(nil, nil, "al")

	if want := []string{"alpha", "alps"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("completeAgentNames() = %v, want %v", got, want)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want NoFileComp", directive)
	}
}

// `agents show <name>` takes exactly one argument, so a second positional must
// offer nothing rather than a name the command would then reject.
func TestCompleteAgentArg_NoSecondPositional(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.openAgentCatalog = catalogOver(agentFS())

	got, directive := d.completeAgentArg(nil, []string{"alpha"}, "")

	if len(got) != 0 {
		t.Fatalf("completeAgentArg() = %v, want no second positional candidate", got)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want NoFileComp", directive)
	}
}

// The FLAG callback must not inherit that arity guard. The root command takes a
// positional task alongside --agent, and cobra passes that task through the flag
// callback's args, so a shared guard would silently stop offering agents for
// `cynative "audit prod" --agent <TAB>`.
func TestCompleteAgentNames_UnaffectedByPositionalTask(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.openAgentCatalog = catalogOver(agentFS())

	got, directive := d.completeAgentNames(nil, []string{"audit prod"}, "al")

	if want := []string{"alpha", "alps"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("completeAgentNames() = %v, want %v with a task already present", got, want)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want NoFileComp", directive)
	}
}

// A completion-time failure must emit nothing rather than leaking an error
// string into the shell protocol.
func TestCompleteAgentNames_FailsQuietly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(d *deps)
	}{
		{
			name: "catalog cannot be opened",
			setup: func(d *deps) {
				d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
					return nil, nil, errors.New("boom")
				}
			},
		},
		{
			name: "names cannot be enumerated",
			setup: func(d *deps) {
				d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
					return agentcatalog.New(agentcatalog.Root{
						Source: agentcatalog.SourceProject, FS: failReadDirFS{}, DisplayPath: "/p",
					}), func() {}, nil
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := testDeps()
			tc.setup(d)

			got, directive := d.completeAgentNames(nil, nil, "")

			if len(got) != 0 {
				t.Fatalf("completeAgentNames() = %v, want none", got)
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Fatalf("directive = %v, want NoFileComp", directive)
			}
		})
	}
}

// A name whose only file is unusable must still be offered: completion does not
// parse bodies, and hiding the name an operator has to fix would be worse.
func TestCompleteAgentNames_OffersInvalidClaimant(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{"broken.md": {Data: []byte("no frontmatter")}} //nolint:exhaustruct // Mode defaults.

	d := testDeps()
	d.openAgentCatalog = catalogOver(fsys)

	got, _ := d.completeAgentNames(nil, nil, "")
	if len(got) != 1 || got[0] != "broken" {
		t.Fatalf("completeAgentNames() = %v, want [broken]: completion must not parse bodies", got)
	}
}

// The completion path must produce real candidates AND never read config or
// credentials: a fresh install has to be able to complete before it is
// configured.
//
// This asserts the actual __complete OUTPUT. Checking only that loadConfig went
// uncalled would pass even if no completion callback were registered at all,
// which is the failure mode most worth catching here.
func TestCompletion_EmitsCandidatesWithoutLoadingConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"flag completion", []string{cobra.ShellCompRequestCmd, "--agent", "al"}},
		{"flag completion after a task", []string{cobra.ShellCompRequestCmd, "audit prod", "--agent", "al"}},
		{"agents show argument completion", []string{cobra.ShellCompRequestCmd, "agents", "show", "al"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loaded := false

			// A malformed file with a matching prefix: completion must still
			// offer it, proving bodies are not parsed.
			fsys := agentFS()
			fsys["albroken.md"] = &fstest.MapFile{Data: []byte("no frontmatter")} //nolint:exhaustruct // Mode defaults.

			d := testDeps()
			d.loadConfig = func(string) (config.Config, error) {
				loaded = true

				return validCfg(), nil
			}
			d.openAgentCatalog = catalogOver(fsys)

			var out bytes.Buffer

			root := NewRootCmd(d)
			root.SetArgs(tc.args)
			root.SetOut(&out)

			if err := root.Execute(); err != nil {
				t.Fatalf("__complete = %v", err)
			}
			if loaded {
				t.Fatal("shell completion must never load config")
			}

			got := out.String()
			for _, want := range []string{"alpha", "alps", "albroken"} {
				if !strings.Contains(got, want) {
					t.Errorf("__complete output %q missing candidate %q", got, want)
				}
			}
			if strings.Contains(got, "beta") {
				t.Errorf("__complete output %q was not prefix-filtered", got)
			}
			if !strings.Contains(got, ":4") {
				t.Errorf("__complete output %q missing the NoFileComp directive", got)
			}
		})
	}
}
