package cli

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/cynative/cynative"
	"github.com/cynative/cynative/internal/agentcatalog"
)

// failWriter fails every write, so the short/failed-write paths are reachable.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// shortWriter reports fewer bytes than it was given WITHOUT an error, which the
// [io.Writer] contract forbids but a non-compliant writer can still do.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestFormatAgentList(t *testing.T) {
	t.Parallel()

	// Sorted by name then precedence, exactly as List returns them.
	entries := []agentcatalog.Entry{
		// a@user wins outright; a@builtin is shadowed by it.
		{Name: "a", Description: "first", Source: agentcatalog.SourceUser, Path: "/home/u/a.md"},
		{Name: "a", Description: "shadowed one", Source: agentcatalog.SourceBuiltin, Shadowed: true},
		// b@user claims the name but is unusable, so no b row is active. Its
		// built-in copy is BOTH shadowed and itself broken, which is the case
		// that must render as two facts rather than collapsing into one.
		{Name: "b", Source: agentcatalog.SourceUser, Err: agentcatalog.ErrAgentInvalid},
		{Name: "b", Source: agentcatalog.SourceBuiltin, Shadowed: true, Err: agentcatalog.ErrAgentInvalid},
	}

	out := formatAgentList(entries)

	if !strings.Contains(out, "active") {
		t.Error("the winning entry should be marked active")
	}
	if !strings.Contains(out, "shadowed by user") {
		t.Error("a shadowed entry should name the source that claimed it")
	}
	if !strings.Contains(out, "invalid (blocking)") {
		t.Error("an unusable claimant should be marked invalid (blocking)")
	}
	if !strings.Contains(out, "shadowed by user, invalid") {
		t.Error("a shadowed entry that is itself invalid should say both")
	}
	if strings.Contains(out, "/home/u/a.md") {
		t.Error("list must not print filesystem paths; SOURCE is the tier word alone")
	}
}

// The claimant is derived from the non-shadowed row, so a catalog whose roots
// were registered in a non-canonical order still names the right source.
func TestFormatAgentList_ClaimantIndependentOfSortOrder(t *testing.T) {
	t.Parallel()

	entries := []agentcatalog.Entry{
		{Name: "a", Source: agentcatalog.SourceUser, Shadowed: true},
		{Name: "a", Description: "winner", Source: agentcatalog.SourceBuiltin},
	}

	if out := formatAgentList(entries); !strings.Contains(out, "shadowed by builtin") {
		t.Fatalf("list = %q, want the shadowed row to name the actual claimant", out)
	}
}

func TestFormatAgentList_SanitizesDescriptions(t *testing.T) {
	t.Parallel()

	entries := []agentcatalog.Entry{
		{Name: "a", Description: "evil\x1b[31m", Source: agentcatalog.SourceUser},
	}

	if out := formatAgentList(entries); strings.Contains(out, "\x1b") {
		t.Fatalf("list output carries a terminal escape: %q", out)
	}
}

func TestFormatAgentList_Empty(t *testing.T) {
	t.Parallel()

	out := formatAgentList(nil)
	if !strings.Contains(out, "No agents") {
		t.Fatalf("empty list = %q, want a helpful message naming where to put agents", out)
	}
}

func TestSkipsConfigLoad_CoversAgents(t *testing.T) {
	t.Parallel()

	root := NewRootCmd(testDeps())

	agents, _, err := root.Find([]string{"agents", "list"})
	if err != nil {
		t.Fatalf("Find(agents list) = %v", err)
	}
	if !skipsConfigLoad(agents) {
		t.Fatal("agents list must not load config: it needs no config and no credentials")
	}

	// The completion tree must still short-circuit. Cobra creates its default
	// completion command lazily, so without this call Find resolves to the root
	// and the arm asserts nothing.
	root.InitDefaultCompletionCmd()

	comp, _, err := root.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("Find(completion) = %v", err)
	}
	if comp.Name() != "completion" {
		t.Fatalf("Find(completion) resolved to %q, not the completion command", comp.Name())
	}
	if !skipsConfigLoad(comp) {
		t.Fatal("the completion tree must still skip config loading")
	}

	// An ordinary command must still load config.
	doctor, _, err := root.Find([]string{"doctor"})
	if err != nil {
		t.Fatalf("Find(doctor) = %v", err)
	}
	if skipsConfigLoad(doctor) {
		t.Fatal("doctor genuinely needs config and must not be skipped")
	}
}

// The commands are driven through the root so their RunE closures are exercised
// rather than only the methods behind them.
func TestAgentsCommands_Execute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStdout string
		wantStderr string
	}{
		{"list", []string{"agents", "list"}, "alpha", ""},
		{"show", []string{"agents", "show", "alpha"}, "description: first", "source:"},
		{"parent prints help", []string{"agents"}, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out, errOut bytes.Buffer

			d := testDeps()
			d.out = &out
			d.errOut = &errOut
			d.openAgentCatalog = catalogOver(agentMapFS("alpha", "first", "body"))

			root := NewRootCmd(d)
			root.SetArgs(tc.args)
			root.SetOut(&out)

			if err := root.Execute(); err != nil {
				t.Fatalf("Execute(%v) = %v", tc.args, err)
			}
			if tc.wantStdout != "" && !strings.Contains(out.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tc.wantStdout)
			}
			if tc.wantStderr != "" && !strings.Contains(errOut.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", errOut.String(), tc.wantStderr)
			}
		})
	}
}

// show writes the exact file bytes, so redirecting stdout round-trips.
func TestRunAgentsShow_RoundTripsExactBytes(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	fsys := agentMapFS("alpha", "first", "body")

	d := testDeps()
	d.out = &out
	d.errOut = io.Discard
	d.openAgentCatalog = catalogOver(fsys)

	if err := d.runAgentsShow("alpha"); err != nil {
		t.Fatalf("runAgentsShow() = %v", err)
	}
	if got, want := out.String(), string(fsys["alpha.md"].Data); got != want {
		t.Fatalf("stdout = %q, want the exact file bytes %q", got, want)
	}
}

func TestAgentsCommands_Failures(t *testing.T) {
	t.Parallel()

	boom := func() (*agentcatalog.Catalog, func(), error) { return nil, nil, errors.New("boom") }

	tests := []struct {
		name string
		run  func(d *deps) error
		set  func(d *deps)
	}{
		{
			name: "list cannot open sources",
			run:  func(d *deps) error { return d.runAgentsList() },
			set:  func(d *deps) { d.openAgentCatalog = boom },
		},
		{
			name: "show cannot open sources",
			run:  func(d *deps) error { return d.runAgentsShow("alpha") },
			set:  func(d *deps) { d.openAgentCatalog = boom },
		},
		{
			name: "show rejects an invalid name",
			run:  func(d *deps) error { return d.runAgentsShow("../escape") },
			set:  func(*deps) {},
		},
		{
			name: "show cannot resolve",
			run:  func(d *deps) error { return d.runAgentsShow("missing") },
			set:  func(d *deps) { d.openAgentCatalog = catalogOver(agentMapFS("alpha", "d", "b")) },
		},
		{
			name: "list cannot enumerate a source",
			run:  func(d *deps) error { return d.runAgentsList() },
			set: func(d *deps) {
				d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
					return agentcatalog.New(agentcatalog.Root{
						Source: agentcatalog.SourceUser, FS: failReadDirFS{}, DisplayPath: "/home/u/.cynative/agents",
					}), func() {}, nil
				}
			},
		},
		{
			name: "list cannot write",
			run:  func(d *deps) error { return d.runAgentsList() },
			set: func(d *deps) {
				d.out = failWriter{}
				d.openAgentCatalog = catalogOver(agentMapFS("alpha", "d", "b"))
			},
		},
		{
			name: "list short write",
			run:  func(d *deps) error { return d.runAgentsList() },
			set: func(d *deps) {
				d.out = shortWriter{}
				d.openAgentCatalog = catalogOver(agentMapFS("alpha", "d", "b"))
			},
		},
		{
			name: "show cannot write",
			run:  func(d *deps) error { return d.runAgentsShow("alpha") },
			set: func(d *deps) {
				d.out = failWriter{}
				d.errOut = io.Discard
				d.openAgentCatalog = catalogOver(agentMapFS("alpha", "d", "b"))
			},
		},
		{
			name: "show short write",
			run:  func(d *deps) error { return d.runAgentsShow("alpha") },
			set: func(d *deps) {
				d.out = shortWriter{}
				d.errOut = io.Discard
				d.openAgentCatalog = catalogOver(agentMapFS("alpha", "d", "b"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := testDeps()
			d.out = io.Discard
			d.errOut = io.Discard
			tc.set(d)

			if err := tc.run(d); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// Every committed built-in must be reachable AND parseable. A built-in with an
// invalid stem would be silently unreachable via --agent, and one with malformed
// frontmatter would ship and fail at the operator's first use. This passes
// vacuously while agents/ holds only .keep, and starts guarding the moment a
// built-in lands.
func TestBuiltinAgents_AllValid(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(cynative.BuiltinAgents(), "agents")
	if err != nil {
		t.Fatalf("fs.Sub() = %v", err)
	}

	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		t.Fatalf("ReadDir() = %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}

		stem := strings.TrimSuffix(e.Name(), ".md")
		if verr := agentcatalog.ValidName(stem); verr != nil {
			t.Errorf("built-in %s has an unusable name: %v", e.Name(), verr)

			continue
		}

		data, rerr := fs.ReadFile(sub, e.Name())
		if rerr != nil {
			t.Errorf("ReadFile(%s) = %v", e.Name(), rerr)

			continue
		}
		if _, perr := agentcatalog.Parse(stem, data); perr != nil {
			t.Errorf("built-in %s does not parse: %v", e.Name(), perr)
		}
	}
}

// The listing must stay one row per agent even when a description carries a
// Unicode line separator, which is the concrete harm the single-line rule and
// the sanitizer exist to prevent.
func TestFormatAgentList_NoRowSplittingSeparators(t *testing.T) {
	t.Parallel()

	entries := []agentcatalog.Entry{
		{Name: "a", Description: "real\u2028forged  fake  user  active", Source: agentcatalog.SourceUser},
	}

	out := formatAgentList(entries)

	// One header line plus exactly one data row.
	if got := strings.Count(strings.TrimRight(out, "\n"), "\n"); got != 1 {
		t.Fatalf("list has %d newlines, want 1 (header + one row):\n%q", got, out)
	}
	if strings.ContainsAny(out, "\u2028\u2029") {
		t.Fatalf("list output still carries a line separator: %q", out)
	}
}
