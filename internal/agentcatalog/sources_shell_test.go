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

func TestOpenSources_ResolvesProjectTier(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(proj, ".cynative", "agents"), "proj-agent")

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	def, err := c.Resolve("proj-agent")
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if def.Source != agentcatalog.SourceProject {
		t.Errorf("Source = %v, want SourceProject", def.Source)
	}
}

// An ESCAPING directory symlink must be refused, and OpenSources itself must
// FAIL. Asserting only that Resolve errors would pass for the wrong reason:
// silently skipping the project source also yields not-found, so that weaker
// assertion cannot tell "escape refused" from "source quietly dropped".
func TestOpenSources_RefusesEscapingProjectSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")
	outside := filepath.Join(base, "outside")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(outside, "agents"), "leaked")

	if err := os.Symlink(outside, filepath.Join(proj, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err == nil {
		cleanup()
		t.Fatal("OpenSources() = nil error, want a claimed-but-unopenable project tier to fail closed")
	}
}

// A CONTAINED directory symlink is permitted by design, so a monorepo can share
// one agents directory. Without this positive case an implementation that
// refuses all directory symlinks would pass the negative test above while
// breaking the supported layout.
func TestOpenSources_AllowsContainedProjectSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(proj, "shared", "agents"), "shared-agent")

	if err := os.Symlink("shared", filepath.Join(proj, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
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
	proj := filepath.Join(home, "proj")
	agents := filepath.Join(proj, ".cynative", "agents")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, agents, "real")

	if err := os.Symlink("real.md", filepath.Join(agents, "linked.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
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

func TestOpenSources_ResolvesUserTierAndSkipsMissingSources(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(proj, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "user-agent")

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
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

// The project search is bounded by the repository root, and home is never a
// project source: from $HOME itself there are no project candidates at all, so
// ~/.cynative/agents resolves as the USER tier rather than collapsing into the
// project tier.
func TestOpenSources_HomeIsNeverTheProjectTier(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	// A dotfiles repository: .git lives in $HOME itself.
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "dotfile-agent")

	c, cleanup, err := agentcatalog.OpenSources(home, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	def, err := c.Resolve("dotfile-agent")
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if def.Source != agentcatalog.SourceUser {
		t.Fatalf("Source = %v, want SourceUser: home must never be the project tier", def.Source)
	}
}

// The NEAREST project directory wins, and a .cynative further up is invisible.
func TestOpenSources_NearestProjectDirWins(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	outer := filepath.Join(home, "outer")
	inner := filepath.Join(outer, "inner")

	if err := os.MkdirAll(filepath.Join(outer, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.MkdirAll(inner, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(outer, ".cynative", "agents"), "outer-agent")
	writeAgent(t, filepath.Join(inner, ".cynative", "agents"), "inner-agent")

	c, cleanup, err := agentcatalog.OpenSources(inner, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
	}
	defer cleanup()

	if _, rerr := c.Resolve("inner-agent"); rerr != nil {
		t.Errorf("Resolve(inner-agent) = %v, want the nearest project dir to win", rerr)
	}
	if _, rerr := c.Resolve("outer-agent"); rerr == nil {
		t.Error("Resolve(outer-agent) succeeded: only the NEAREST project dir is a source")
	}
}

func TestOpenSources_NoSourcesIsUsable(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")

	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(home, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v", err)
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

// A non-canonical cwd is rejected rather than silently searched, since the home
// boundary cannot be enforced against a path spelled differently.
func TestOpenSources_RejectsNonCanonicalInput(t *testing.T) {
	base := realPath(t, t.TempDir())

	if _, _, err := agentcatalog.OpenSources("relative/path", base, os.DirFS(base)); err == nil {
		t.Fatal("OpenSources() = nil error, want a non-absolute cwd rejected")
	}
}

// A .cynative/agents symlink whose target is MISSING claims the project source
// but cannot be opened, so it must fail closed.
//
// [os.Stat] follows the final symlink and reports ErrNotExist here, which read as
// "no project source" and silently handed the name to a lower tier. Lstat is
// what distinguishes "nothing is claimed" from "something is claimed and
// broken".
func TestOpenSources_RefusesDanglingProjectSymlink(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	// A same-named USER agent: if the dangling project source were skipped,
	// this is what would silently run instead.
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "shared-name")

	if err := os.Symlink("nonexistent-target", filepath.Join(proj, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err == nil {
		cleanup()
		t.Fatal("OpenSources() = nil error, want a dangling project symlink to fail closed")
	}
}

// A stray FILE at .cynative/agents is not a claimed source: it is junk, not a
// broken agents directory, so the search moves on rather than failing.
func TestOpenSources_StrayFileAtAgentsPathIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, ".cynative"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".cynative", "agents"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "user-agent")

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a stray file to be ignored", err)
	}
	defer cleanup()

	def, rerr := c.Resolve("user-agent")
	if rerr != nil {
		t.Fatalf("Resolve() = %v", rerr)
	}
	if def.Source != agentcatalog.SourceUser {
		t.Fatalf("Source = %v, want SourceUser", def.Source)
	}
}

// A .cynative symlink to a REAL directory that happens to hold no agents/ is
// not a claimed source, so the search moves on cleanly.
//
// This is the false positive the dangling-symlink fix could have introduced:
// treating any symlinked .cynative as claimed would hard-fail every --agent run
// in a project that uses .cynative for something else.
func TestOpenSources_ContainedSymlinkWithoutAgentsIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(filepath.Join(proj, "other"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "user-agent")

	if err := os.Symlink("other", filepath.Join(proj, ".cynative")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a .cynative without agents/ to be skipped", err)
	}
	defer cleanup()

	def, rerr := c.Resolve("user-agent")
	if rerr != nil {
		t.Fatalf("Resolve() = %v", rerr)
	}
	if def.Source != agentcatalog.SourceUser {
		t.Fatalf("Source = %v, want SourceUser", def.Source)
	}
}

// A stray regular FILE named .cynative is an absent project source, not a
// claimed-but-broken one.
//
// A file cannot contain an agents entry, so treating it as claimed made the
// child lookup fail with ENOTDIR, which aborted opening the catalog entirely
// and took the user and built-in tiers down with it. One stray file anywhere in
// the search path disabled agents completely.
func TestOpenSources_StrayFileNamedCynativeIsNotClaimed(t *testing.T) {
	base := realPath(t, t.TempDir())
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "proj")

	if err := os.MkdirAll(proj, 0o750); err != nil {
		t.Fatalf("MkdirAll = %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".cynative"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}
	writeAgent(t, filepath.Join(home, ".cynative", "agents"), "user-agent")

	c, cleanup, err := agentcatalog.OpenSources(proj, home, os.DirFS(base))
	if err != nil {
		t.Fatalf("OpenSources() = %v, want a stray .cynative file to be skipped", err)
	}
	defer cleanup()

	def, rerr := c.Resolve("user-agent")
	if rerr != nil {
		t.Fatalf("Resolve() = %v, want the user tier to remain reachable", rerr)
	}
	if def.Source != agentcatalog.SourceUser {
		t.Fatalf("Source = %v, want SourceUser", def.Source)
	}
}
