package agentcatalog_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

func TestValidName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "public-exposure", true},
		{"digits", "aws-s3-2024", true},
		{"single char", "a", true},
		{"single digit", "7", true},
		{"empty", "", false},
		{"uppercase", "Public-Exposure", false},
		{"dot", "public.exposure", false},
		{"md suffix", "public-exposure.md", false},
		{"underscore", "public_exposure", false},
		{"space", "public exposure", false},
		{"slash", "a/b", false},
		{"backslash", `a\b`, false},
		{"parent traversal", "..", false},
		{"leading dash", "-lead", false},
		{"trailing dash", "trail-", false},
		{"unicode", "café", false},
		{"too long", strings.Repeat("a", 65), false},
		{"max length", strings.Repeat("a", 64), true},
		{"windows con", "con", false},
		{"windows nul", "nul", false},
		{"windows com1", "com1", false},
		{"windows lpt9", "lpt9", false},
		{"not a device", "console", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := agentcatalog.ValidName(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("ValidName(%q) = %v, want nil", tc.in, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidName(%q) = nil, want error", tc.in)
				}
				if !errors.Is(err, agentcatalog.ErrAgentName) {
					t.Fatalf("ValidName(%q) error = %v, want ErrAgentName", tc.in, err)
				}
			}
		})
	}
}
