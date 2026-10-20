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

// TestRedact_ContentStillChangingAtTheLastRoundIsReplacedWhole lowers the round
// bound below what the input needs, so Redact gives up on it and returns a
// placeholder that a second Redact leaves as it is.
func TestRedact_ContentStillChangingAtTheLastRoundIsReplacedWhole(t *testing.T) {
	t.Parallel()

	// The command pass removes the '<' that stops the truncated XML rule, so the
	// second round redacts again and only the third changes nothing.
	const in = `<token>["--token","<p`

	r := New()
	r.rounds = 3
	if got, want := r.Redact(in), "<token>[REDACTED:credential-field]"; got != want {
		t.Fatalf("Redact with 3 rounds = %q, want %q", got, want)
	}

	r.rounds = 2
	got := r.Redact(in)
	if want := "[REDACTED:unstable]"; got != want {
		t.Fatalf("Redact with 2 rounds = %q, want %q", got, want)
	}
	if again := r.Redact(got); again != got {
		t.Errorf("Redact(%q) = %q, want it unchanged", got, again)
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

			memo := newScanMemo()
			if got := m.commandFrom(tc.words, memo, 1); got != tc.want {
				t.Fatalf("commandFrom = %d, want %d", got, tc.want)
			}
			if !maps.Equal(memo.command, tc.memo) {
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

// TestSkipToken pins where the encoded pass looks for the next JSON value after a
// read stops: past the string it stopped in, escaped quotes and all, so no quote
// inside it starts a read over the rest; at the token when it is no string, such
// as a separator the read did not expect, so a string after it is still read; and
// nowhere when the string is never closed.
func TestSkipToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		in     string
		before int
		want   int
	}{
		{"string with an invalid escape", `"a\q\"b" x`, 0, 8},
		{"separator before a string", `"a" : "b" x`, 3, 4},
		{"separator before a string never closed", `"a" : "b\q`, 3, -1},
		{"token that is no string", `{"a":1 x`, 6, 7},
		{"string never closed", `"a\q\"b`, 0, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := skipToken(tc.in, tc.before); got != tc.want {
				t.Errorf("skipToken(%q, %d) = %d, want %d", tc.in, tc.before, got, tc.want)
			}
		})
	}
}

// TestAfterOptions pins that afterOptions keeps its answer for every word it reads,
// so shells whose options reach the same words read each of them once.
func TestAfterOptions(t *testing.T) {
	t.Parallel()

	m := newMatchers("password", "password", "--password")
	words := []string{"-e", "-o", "pipefail", "--", "cmd"}
	memo := newScanMemo()
	if got := m.afterOptions(words, memo, 0); got != 4 {
		t.Fatalf("afterOptions = %d, want 4", got)
	}
	if want := map[int]int{0: 4, 1: 4, 3: 4}; !maps.Equal(memo.after, want) {
		t.Fatalf("memo = %v, want %v", memo.after, want)
	}
	// From the stored word on every word is a short option, so a scan that read
	// words[1] again would run to the end.
	words = []string{"-e", "-o", "-x", "-x", "-x"}
	if got := m.afterOptions(words, memo, 1); got != 4 {
		t.Errorf("afterOptions from a stored word = %d, want 4", got)
	}
}

// TestNestedCommands pins that a command several shells run is read once.
func TestNestedCommands(t *testing.T) {
	t.Parallel()

	m := newMatchers("password", "password", "--password")
	cmd := "sh -co sh -c app"
	got := m.nestedCommands(cmd, shellWords(cmd))
	if want := []nested{{4, "app", false}}; !slices.Equal(got, want) {
		t.Fatalf("nestedCommands = %v, want %v", got, want)
	}
}
