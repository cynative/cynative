package github

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

func TestDriftWarning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		level    exposure.Level
		header   string
		wantWarn bool
	}{
		{"read ok when header read", exposure.LevelRead, "issues=read", false},
		{"read ok when an OR-alt is read", exposure.LevelRead, "issues=write;issues=read", false},
		{"trailing comma still read", exposure.LevelRead, "issues=read,", false}, // covers empty-perm skip.
		{"read drift when only write", exposure.LevelRead, "issues=write", true},
		{"empty trailing alt not satisfiable", exposure.LevelRead, "issues=write;", true}, // covers empty-set false.
		{"read drift when AND-set needs a write", exposure.LevelRead, "issues=read,contents=write", true},
		{"no warn for write classification", exposure.LevelWrite, "issues=write", false},
		{"no warn for empty header", exposure.LevelRead, "", false},
		{"no warn for whitespace header", exposure.LevelRead, "   ", false},
		{"no warn for none", exposure.LevelNone, "issues=write", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			msg, warn := DriftWarning(c.level, c.header)
			if warn != c.wantWarn {
				t.Fatalf("DriftWarning(%v,%q) warn=%v, want %v", c.level, c.header, warn, c.wantWarn)
			}
			if warn && !strings.Contains(msg, "github_hardening") {
				t.Fatalf("warn message missing prefix: %q", msg)
			}
		})
	}
}
