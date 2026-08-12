package agentcatalog_test

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

// gitAt returns a marker probe reporting .git in exactly the listed dirs.
func gitAt(dirs ...string) func(string) (bool, error) {
	set := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		set[d] = true
	}

	return func(dir string) (bool, error) { return set[dir], nil }
}

func TestProjectSearchPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cwd    string
		home   string
		hasGit func(string) (bool, error)
		want   []string
	}{
		{
			name: "stops at and includes the git root",
			cwd:  "/home/u/proj/a/b", home: "/home/u",
			hasGit: gitAt("/home/u/proj"),
			want:   []string{"/home/u/proj/a/b", "/home/u/proj/a", "/home/u/proj"},
		},
		{
			name: "cwd is itself the git root",
			cwd:  "/home/u/proj", home: "/home/u",
			hasGit: gitAt("/home/u/proj"),
			want:   []string{"/home/u/proj"},
		},
		{
			name: "no marker below home yields cwd alone",
			cwd:  "/home/u/proj/a", home: "/home/u",
			hasGit: gitAt(),
			want:   []string{"/home/u/proj/a"},
		},
		{
			name: "home is never returned even when it holds .git",
			cwd:  "/home/u/proj", home: "/home/u",
			hasGit: gitAt("/home/u"),
			want:   []string{"/home/u/proj"},
		},
		{
			name: "cwd equal to home yields no project candidates",
			cwd:  "/home/u", home: "/home/u",
			hasGit: gitAt("/home/u"),
			want:   nil,
		},
		{
			name: "outside home walks to the filesystem root",
			cwd:  "/srv/proj/a", home: "/home/u",
			hasGit: gitAt("/srv/proj"),
			want:   []string{"/srv/proj/a", "/srv/proj"},
		},
		{
			name: "outside home with no marker yields cwd alone",
			cwd:  "/srv/proj/a", home: "/home/u",
			hasGit: gitAt(),
			want:   []string{"/srv/proj/a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := agentcatalog.ProjectSearchPath(tc.cwd, tc.home, tc.hasGit)
			if err != nil {
				t.Fatalf("ProjectSearchPath() = %v, want nil error", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ProjectSearchPath() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProjectSearchPath_RejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cwd  string
		home string
	}{
		{"relative cwd", "proj/a", "/home/u"},
		{"relative home", "/home/u/proj", "u"},
		{"uncleaned cwd", "/home/u/proj/../proj", "/home/u"},
		{"uncleaned home", "/home/u/proj", "/home/u/"},
		{"empty cwd", "", "/home/u"},
		{"empty home", "/home/u/proj", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := agentcatalog.ProjectSearchPath(tc.cwd, tc.home, gitAt()); err == nil {
				t.Fatal("ProjectSearchPath() = nil error, want an error for a non-canonical input")
			}
		})
	}
}

// A probe failure must not read as "no marker here": that would silently widen
// the search past a repository boundary it could not confirm.
func TestProjectSearchPath_PropagatesProbeError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("permission denied")
	probe := func(string) (bool, error) { return false, sentinel }

	_, err := agentcatalog.ProjectSearchPath("/home/u/proj/a", "/home/u", probe)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ProjectSearchPath() error = %v, want it to wrap the probe error", err)
	}
}

func TestClaimsSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{"directory claims", fs.ModeDir, true},
		{"symlink claims regardless of target", fs.ModeSymlink, true},
		{"symlinked directory claims", fs.ModeDir | fs.ModeSymlink, true},
		{"regular file is a stray, not a claim", 0, false},
		{"device is not a claim", fs.ModeDevice, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := agentcatalog.ClaimsSource(tc.mode); got != tc.want {
				t.Fatalf("ClaimsSource(%v) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
