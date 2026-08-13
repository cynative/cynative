package agentcatalog_test

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

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

func TestValidateHome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		home string
		ok   bool
	}{
		{"absolute cleaned path", "/home/u", true},
		{"root", "/", true},
		{"empty", "", false},
		// The dangerous case: os.UserHomeDir returns $HOME verbatim, so a
		// relative home makes every lookup resolve against the working
		// directory and hands a checkout the user tier.
		{"relative dot", ".", false},
		{"relative path", "home/u", false},
		{"uncleaned", "/home/u/../u", false},
		{"trailing slash", "/home/u/", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := agentcatalog.ValidateHome(tc.home)
			if tc.ok && err != nil {
				t.Fatalf("ValidateHome(%q) = %v, want nil", tc.home, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidateHome(%q) = nil, want an error", tc.home)
				}
				if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
					t.Fatalf("ValidateHome(%q) error = %v, want ErrAgentInvalid", tc.home, err)
				}
			}
		})
	}
}
