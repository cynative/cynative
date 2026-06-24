package redact

import "testing"

// TestGated covers the keyword pre-gate, including the keyword-less branch that
// the production rule set does not yet exercise (a later task adds such a rule).
func TestGated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		in       string
		keywords []string
		want     bool
	}{
		{"no keywords always runs", "anything", nil, true},
		{"empty keyword slice always runs", "anything", []string{}, true},
		{"keyword present", "has ghp_ here", []string{"ghp_"}, true},
		{"keyword absent", "nothing matches", []string{"ghp_", "xox"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := gated(tc.in, tc.keywords); got != tc.want {
				t.Errorf("gated(%q, %v) = %v, want %v", tc.in, tc.keywords, got, tc.want)
			}
		})
	}
}
