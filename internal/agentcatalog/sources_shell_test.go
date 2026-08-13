package agentcatalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

const validAgent = "---\ndescription: d\n---\nbody\n"

// writeAgent creates dir/<name>.md with valid contents.
func writeAgent(t *testing.T, dir, name string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%s) = %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".md"), []byte(validAgent), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}
}

// realPath resolves symlinks the way OpenSources' callers must.
func realPath(t *testing.T, p string) string {
	t.Helper()

	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s) = %v", p, err)
	}

	return resolved
}

func TestOpenSources_ResolvesUserTier(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "user-agent")

	c, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	def, err := c.Resolve("user-agent")
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if def.Source != agentcatalog.SourceUser {
		t.Errorf("Source = %v, want SourceUser", def.Source)
	}
}

// An agents directory in the WORKING DIRECTORY is not a source. Agents are
// operator-authored configuration, so a checkout must not be able to supply the
// prompt for a run.
func TestOpenSources_IgnoresWorkingDirectoryAgents(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(proj, ".cynative", "agents"), "checkout-agent")

	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	if _, rerr := c.Resolve("checkout-agent"); rerr == nil {
		t.Fatal("Resolve() succeeded: a repository must not be able to supply an agent")
	}

	names, err := c.Names()
	if err != nil {
		t.Fatalf("Names() = %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("Names() = %v, want none: only ~/.cynative/agents and built-ins are sources", names)
	}
}

// An ESCAPING directory symlink must be refused, and OpenSources itself must
// FAIL. Asserting only that Resolve errors would pass for the wrong reason:
// silently skipping the source also yields not-found, so that weaker assertion
// cannot tell "escape refused" from "source quietly dropped".
func TestOpenSources_RefusesEscapingSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "outside")

	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(outside, "agents"), "leaked")

	if err := os.Symlink(outside, filepath.Join(home, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err == nil {
		cleanup()
		t.Fatal("OpenSources() = nil error, want a claimed-but-unopenable tier to fail closed")
	}
}

// A CONTAINED directory symlink is permitted by design, so an operator can point
// ~/.cynative at a dotfiles directory. Without this positive case an
// implementation that refuses all directory symlinks would pass the negative
// test above while breaking the supported layout.
func TestOpenSources_AllowsContainedSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	writeAgent(t, filepath.Join(home, "dotfiles", "agents"), "shared-agent")

	if err := os.Symlink("dotfiles", filepath.Join(home, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	if _, rerr := c.Resolve("shared-agent"); rerr != nil {
		t.Fatalf("Resolve() = %v, want a contained symlink to resolve normally", rerr)
	}
}

// A symlinked agent FILE is refused even inside the root: its bytes go straight
// into the prompt, so file-level indirection is not accepted.
func TestOpenSources_RefusesSymlinkedAgentFile(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	agents := filepath.Join(home, ".cynative", "agents")

	writeAgent(t, agents, "real")

	if err := os.Symlink("real.md", filepath.Join(agents, "linked.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	if _, rerr := c.Resolve("linked"); rerr == nil {
		t.Fatal("Resolve() = nil error, want a symlinked agent file refused")
	}
	if _, rerr := c.Resolve("real"); rerr != nil {
		t.Fatalf("Resolve(real) = %v, want the regular file to still resolve", rerr)
	}
}

// A dangling ~/.cynative/agents is broken, not absent: treating it as absent
// would hide it from `agents list` and silently resolve a same-named built-in.
func TestOpenSources_RefusesDanglingSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(filepath.Join(home, ".cynative"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}

	if err := os.Symlink("nonexistent-target", filepath.Join(home, ".cynative", "agents")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err == nil {
		cleanup()
		t.Fatal("OpenSources() = nil error, want a dangling source to fail closed")
	}
}

// A .cynative symlink to a REAL directory that happens to hold no agents/ is
// not a claimed source, so it is skipped cleanly rather than failing.
func TestOpenSources_ContainedSymlinkWithoutAgentsIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(filepath.Join(home, "other"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}

	if err := os.Symlink("other", filepath.Join(home, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a .cynative without agents/ to be skipped", err)
	}

	cleanup()
}

// A stray regular FILE named .cynative is an absent source, not a claimed-but-
// broken one. A file cannot contain an agents entry, so treating it as claimed
// made the child lookup fail with ENOTDIR and aborted the catalog entirely,
// taking the built-in tier down with it.
func TestOpenSources_StrayFileNamedCynativeIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cynative"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a stray .cynative file to be skipped", err)
	}

	cleanup()
}

// A stray FILE at .cynative/agents is likewise junk, not a claimed source.
func TestOpenSources_StrayFileAtAgentsPathIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(filepath.Join(home, ".cynative"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cynative", "agents"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a stray file to be ignored", err)
	}

	cleanup()
}

// A genuinely absent user tier is a clean skip, and the built-ins still load.
func TestOpenSources_AbsentUserTierIsNotAnError(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want an absent user tier to be skipped", err)
	}
	defer cleanup()

	names, err := c.Names()
	if err != nil {
		t.Fatalf("Names() = %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("Names() = %v, want none", names)
	}
}
