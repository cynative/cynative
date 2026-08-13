package agentcatalog_test

import (
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
