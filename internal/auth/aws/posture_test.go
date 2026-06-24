package aws_test

import (
	"testing"

	awsh "github.com/cynative/cynative/internal/auth/aws"
)

func TestCredScopeLabel(t *testing.T) {
	t.Parallel()
	cases := map[awsh.CredScopeMode]string{
		awsh.CredScopeAssumeRole: "assume_role",
		awsh.CredScopeDisabled:   "disabled",
		awsh.CredScopeMode(99):   "disabled",
	}
	for mode, want := range cases {
		if got := awsh.CredScopeLabel(mode); got != want {
			t.Errorf("CredScopeLabel(%v) = %q, want %q", mode, got, want)
		}
	}
}

func TestScopeLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result awsh.ScopeResult
		want   string
	}{
		{
			name:   "confirmed assume_role",
			result: awsh.ScopeResult{Mode: awsh.CredScopeAssumeRole, Verified: true},
			want:   "assume_role",
		},
		{
			name:   "unverified assume_role (transient probe error)",
			result: awsh.ScopeResult{Mode: awsh.CredScopeAssumeRole, Verified: false},
			want:   "assume_role (unverified)",
		},
		{
			name:   "disabled with degrade reason",
			result: awsh.ScopeResult{Mode: awsh.CredScopeDisabled, Reason: "assume_role_unavailable"},
			want:   "disabled (degraded: assume_role_unavailable)",
		},
		{
			name:   "disabled no reason",
			result: awsh.ScopeResult{Mode: awsh.CredScopeDisabled},
			want:   "disabled",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := awsh.ScopeLabel(c.result); got != c.want {
				t.Errorf("ScopeLabel(%+v) = %q, want %q", c.result, got, c.want)
			}
		})
	}
}
