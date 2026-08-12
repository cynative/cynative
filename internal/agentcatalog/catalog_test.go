package agentcatalog_test

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/cynative/cynative/internal/agentcatalog"
)

func agentFile(desc, body string) *fstest.MapFile {
	src := "---\ndescription: " + desc + "\n---\n" + body + "\n"

	return &fstest.MapFile{Data: []byte(src)} //nolint:exhaustruct // Mode/ModTime default.
}

// brokenFile is a file with a valid agent name but unusable content.
func brokenFile() *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("no frontmatter")} //nolint:exhaustruct // Mode/ModTime default.
}

func projectRoot(fsys fs.FS) agentcatalog.Root {
	return agentcatalog.Root{Source: agentcatalog.SourceProject, FS: fsys, DisplayPath: "/proj/.cynative/agents"}
}

func userRoot(fsys fs.FS) agentcatalog.Root {
	return agentcatalog.Root{Source: agentcatalog.SourceUser, FS: fsys, DisplayPath: "/home/u/.cynative/agents"}
}

func builtinRoot(fsys fs.FS) agentcatalog.Root {
	return agentcatalog.Root{Source: agentcatalog.SourceBuiltin, FS: fsys, DisplayPath: "built-in"}
}

func TestResolve_FirstMatchWins(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(
		projectRoot(fstest.MapFS{"a.md": agentFile("project copy", "P")}),
		userRoot(fstest.MapFS{"a.md": agentFile("user copy", "U")}),
		builtinRoot(fstest.MapFS{"a.md": agentFile("builtin copy", "B")}),
	)

	def, err := c.Resolve("a")
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if def.Description != "project copy" {
		t.Errorf("Description = %q, want the project copy", def.Description)
	}
	if def.Source != agentcatalog.SourceProject {
		t.Errorf("Source = %v, want SourceProject", def.Source)
	}
	if def.Path != "/proj/.cynative/agents/a.md" {
		t.Errorf("Path = %q", def.Path)
	}
}

func TestResolve_FallsThroughMissingNameAndMissingDir(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(
		projectRoot(fstest.MapFS{}),
		userRoot(fstest.MapFS{"other.md": agentFile("d", "b")}),
		builtinRoot(fstest.MapFS{"a.md": agentFile("builtin copy", "B")}),
	)

	def, err := c.Resolve("a")
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if def.Source != agentcatalog.SourceBuiltin {
		t.Errorf("Source = %v, want SourceBuiltin", def.Source)
	}
}

func TestResolve_NotFoundIsSentinel(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(projectRoot(fstest.MapFS{}))

	_, err := c.Resolve("nope")
	if !errors.Is(err, agentcatalog.ErrAgentNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrAgentNotFound", err)
	}
}

func TestResolve_RejectsBadNameBeforeAnyFilesystemAccess(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // only ReadDir fails.
	fsys := faultFS{failReadDir: errors.New("ReadDir must not be reached for an invalid name")}
	c := agentcatalog.New(projectRoot(fsys))

	if _, err := c.Resolve("../etc/passwd"); !errors.Is(err, agentcatalog.ErrAgentName) {
		t.Fatalf("Resolve() error = %v, want ErrAgentName", err)
	}
}

// A malformed higher-precedence file must NOT fall through to a valid lower
// one: a typo in a project agent has to fail loudly, not silently run a
// different agent.
func TestResolve_MalformedWinnerBlocks(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(
		projectRoot(fstest.MapFS{"a.md": brokenFile()}),
		builtinRoot(fstest.MapFS{"a.md": agentFile("builtin copy", "B")}),
	)

	_, err := c.Resolve("a")
	if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
		t.Fatalf("Resolve() error = %v, want ErrAgentInvalid", err)
	}
}

func TestResolve_RejectsSymlinkAndNonRegular(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode fs.FileMode
	}{
		{"symlink", fs.ModeSymlink},
		{"device", fs.ModeDevice},
		{"directory entry named like an agent", fs.ModeDir},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fsys := fstest.MapFS{"a.md": &fstest.MapFile{ //nolint:exhaustruct // ModTime/Sys default.
				Data: []byte("---\ndescription: d\n---\nbody\n"),
				Mode: tc.mode,
			}}

			_, err := agentcatalog.New(projectRoot(fsys)).Resolve("a")
			if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
				t.Fatalf("Resolve() error = %v, want ErrAgentInvalid", err)
			}
		})
	}
}

func TestResolve_RejectsOversizedFile(t *testing.T) {
	t.Parallel()

	big := make([]byte, (64<<10)+1)
	for i := range big {
		big[i] = 'a'
	}
	fsys := fstest.MapFS{"a.md": {Data: big}} //nolint:exhaustruct // Mode defaults.

	_, err := agentcatalog.New(projectRoot(fsys)).Resolve("a")
	if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
		t.Fatalf("Resolve() error = %v, want ErrAgentInvalid", err)
	}
}

func TestResolve_PropagatesFilesystemFailures(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	good := fstest.MapFS{"a.md": agentFile("d", "b")}

	tests := []struct {
		name string
		fsys fs.FS
		// candidateInvalid distinguishes a per-file failure (which must wrap
		// ErrAgentInvalid so a claimed-but-unreadable file fails closed) from a
		// whole-source enumeration failure (which says nothing about any
		// particular candidate and must NOT claim one is invalid).
		candidateInvalid bool
	}{
		{"readdir", faultFS{MapFS: good, failReadDir: boom}, false}, //nolint:exhaustruct // one fault each.
		{"lstat", faultFS{MapFS: good, failLstat: boom}, true},      //nolint:exhaustruct // one fault each.
		{"open", faultFS{MapFS: good, failOpen: boom}, true},        //nolint:exhaustruct // one fault each.
		{"read", faultFS{MapFS: good, failRead: boom}, true},        //nolint:exhaustruct // one fault each.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := agentcatalog.New(projectRoot(tc.fsys)).Resolve("a")
			if err == nil {
				t.Fatal("Resolve() = nil error, want the filesystem failure surfaced")
			}
			if !errors.Is(err, boom) {
				t.Errorf("error %v does not wrap the underlying cause", err)
			}
			if got := errors.Is(err, agentcatalog.ErrAgentInvalid); got != tc.candidateInvalid {
				t.Errorf("errors.Is(err, ErrAgentInvalid) = %v, want %v", got, tc.candidateInvalid)
			}
		})
	}
}

// A missing agents directory is not a failure: that source simply does not
// exist on this machine, so resolution falls through to the next one.
func TestResolve_MissingDirectoryFallsThrough(t *testing.T) {
	t.Parallel()

	notExist := faultFS{MapFS: fstest.MapFS{}, failReadDir: fs.ErrNotExist} //nolint:exhaustruct // one fault.

	c := agentcatalog.New(
		projectRoot(notExist),
		builtinRoot(fstest.MapFS{"a.md": agentFile("builtin copy", "B")}),
	)

	def, err := c.Resolve("a")
	if err != nil {
		t.Fatalf("Resolve() = %v, want the missing directory to fall through", err)
	}
	if def.Source != agentcatalog.SourceBuiltin {
		t.Fatalf("Source = %v, want SourceBuiltin", def.Source)
	}
}

// A case-insensitive filesystem must not serve Foo.md for --agent foo.
func TestResolve_RequiresExactDirectoryEntry(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(projectRoot(fstest.MapFS{"Foo.md": agentFile("d", "b")}))

	if _, err := c.Resolve("foo"); !errors.Is(err, agentcatalog.ErrAgentNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrAgentNotFound", err)
	}
}

func TestList_MarksShadowedAndInvalid(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(
		projectRoot(fstest.MapFS{"a.md": brokenFile()}),
		userRoot(fstest.MapFS{"a.md": agentFile("user copy", "U"), "b.md": agentFile("only b", "B")}),
	)

	entries, err := c.List()
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List() returned %d entries, want 3", len(entries))
	}

	// a@project: claims the name, is invalid, is not shadowed.
	if entries[0].Name != "a" || entries[0].Source != agentcatalog.SourceProject {
		t.Fatalf("entry 0 = %+v", entries[0])
	}
	if entries[0].Err == nil {
		t.Error("entry 0 should carry the parse error")
	}
	if entries[0].Shadowed {
		t.Error("the highest-precedence claimant is never shadowed")
	}

	// a@user: shadowed by the invalid project claimant, which claimed the name.
	if !entries[1].Shadowed {
		t.Error("a@user should be shadowed by the blocking project claimant")
	}

	// b@user: sole claimant.
	if entries[2].Name != "b" || entries[2].Shadowed || entries[2].Err != nil {
		t.Errorf("entry 2 = %+v", entries[2])
	}
}

func TestList_IgnoresNonAgentFiles(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(projectRoot(fstest.MapFS{
		".keep":     {}, //nolint:exhaustruct // empty marker file.
		"README.md": agentFile("uppercase stem is not a valid name", "x"),
		"notes.txt": {}, //nolint:exhaustruct // not markdown.
		"real.md":   agentFile("d", "b"),
	}))

	entries, err := c.List()
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "real" {
		t.Fatalf("List() = %+v, want only the real agent", entries)
	}
}

func TestList_FailsOnSourceEnumerationError(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(projectRoot(faultFS{failReadDir: errors.New("boom")})) //nolint:exhaustruct // one fault.

	if _, err := c.List(); err == nil {
		t.Fatal("List() = nil error, want the enumeration failure surfaced")
	}
}

// A file that cannot be opened after enumeration is reported as a row rather
// than dropped, so a broken agent is visible instead of silently absent.
func TestList_ReportsUnreadableEntry(t *testing.T) {
	t.Parallel()

	fsys := faultFS{ //nolint:exhaustruct // only Open fails.
		MapFS:    fstest.MapFS{"a.md": agentFile("d", "b")},
		failOpen: errors.New("permission denied"),
	}

	entries, err := agentcatalog.New(projectRoot(fsys)).List()
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 || entries[0].Err == nil {
		t.Fatalf("List() = %+v, want one row carrying an error", entries)
	}
}

// A file that vanishes BETWEEN enumeration and the read reaches entryFor's
// !found arm, which a one-shot fault FS cannot produce: candidateNames and
// readFrom each call ReadDir, so the entry must be present for the first call
// and gone for the second.
func TestList_ReportsEntryThatVanishesMidListing(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // calls counter starts at zero.
	fsys := &vanishingFS{MapFS: fstest.MapFS{"a.md": agentFile("d", "b")}}

	entries, err := agentcatalog.New(projectRoot(fsys)).List()
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() = %+v, want the vanished entry reported as one row", entries)
	}
	if entries[0].Err == nil {
		t.Fatal("a vanished entry must carry an error rather than be dropped")
	}
}

// A missing directory is skipped by the ENUMERATION path too, not just by
// Resolve: List and Names go through candidateNames, which has its own
// ErrNotExist arm.
func TestListAndNames_SkipMissingDirectory(t *testing.T) {
	t.Parallel()

	notExist := faultFS{MapFS: fstest.MapFS{}, failReadDir: fs.ErrNotExist} //nolint:exhaustruct // one fault.

	c := agentcatalog.New(
		projectRoot(notExist),
		userRoot(fstest.MapFS{"a.md": agentFile("d", "b")}),
	)

	entries, err := c.List()
	if err != nil {
		t.Fatalf("List() = %v, want a missing directory to be skipped", err)
	}
	if len(entries) != 1 || entries[0].Source != agentcatalog.SourceUser {
		t.Fatalf("List() = %+v, want only the user entry", entries)
	}

	names, err := c.Names()
	if err != nil {
		t.Fatalf("Names() = %v", err)
	}
	if want := []string{"a"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
}

func TestNames_DeduplicatesAndKeepsInvalidClaimants(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(
		projectRoot(fstest.MapFS{"b.md": brokenFile()}),
		userRoot(fstest.MapFS{"a.md": agentFile("d", "x"), "b.md": agentFile("d", "x")}),
	)

	got, err := c.Names()
	if err != nil {
		t.Fatalf("Names() = %v", err)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %v, want %v (invalid claimant still listed, no duplicates)", got, want)
	}
}

func TestNames_FailsOnSourceEnumerationError(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(projectRoot(faultFS{failReadDir: errors.New("boom")})) //nolint:exhaustruct // one fault.

	if _, err := c.Names(); err == nil {
		t.Fatal("Names() = nil error, want completion to suppress rather than mislead")
	}
}
