package redact

import (
	"maps"
	"slices"
	"testing"
)

// TestGated covers the keyword pre-gate, including the keyword-less branch.
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

// TestCommandFrom pins the memo that keeps the option scan linear: a scan
// stores its answer, a found command or none, at every option it read, and a
// later scan that reaches one of them returns that answer without reading on.
func TestCommandFrom(t *testing.T) {
	t.Parallel()

	m := newMatchers("password", "password", "--password")
	cases := []struct {
		name  string
		words []string
		want  int
		memo  map[int]int
	}{
		{"command found", []string{"sh", "--rcfile", "sh", "-o", "bash", "-c", "x"}, 6, map[int]int{1: 6, 3: 6, 5: 6}},
		{"no command", []string{"sh", "--rcfile", "sh", "-x", "y"}, -1, map[int]int{1: -1, 3: -1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memo := make(map[int]int)
			if got := m.commandFrom(tc.words, memo, 1); got != tc.want {
				t.Fatalf("commandFrom = %d, want %d", got, tc.want)
			}
			if !maps.Equal(memo, tc.memo) {
				t.Fatalf("memo = %v, want %v", memo, tc.memo)
			}
			// From the stored option on every word is a -c, so a scan that read
			// words[3] would return 4.
			words := slices.Clone(tc.words)
			for k := 3; k < len(words); k++ {
				words[k] = "-c"
			}
			if got := m.commandFrom(words, memo, 3); got != tc.want {
				t.Errorf("commandFrom from a stored option = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestCommandSpans_SharedCommandReadOnce pins that a command several shell names
// reach is read once, so the pass stays linear in the size of that command.
func TestCommandSpans_SharedCommandReadOnce(t *testing.T) {
	t.Parallel()

	m := newMatchers("password", "password", "--password")
	s := `["sh","-o","sh","-o","bash","-c","app --password x"]`
	elems, _ := m.run(s, 1)
	if got := m.commandSpans(s, elems); len(got) != 1 {
		t.Errorf("commandSpans = %v, want one span", got)
	}
}
