package agentcatalog_test

import (
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

func TestSourceString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   agentcatalog.Source
		want string
	}{
		{"user", agentcatalog.SourceUser, "user"},
		{"builtin", agentcatalog.SourceBuiltin, "builtin"},
		{"out of range", agentcatalog.Source(99), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.in.String(); got != tc.want {
				t.Fatalf("Source(%d).String() = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
