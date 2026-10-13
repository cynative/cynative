package apiref_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/apiref"
)

func TestStripMarkup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"tags and entities", "<p>Lists the <code>Roles</code> &amp; more.</p>", 100, "Lists the Roles & more."},
		{"whitespace collapses", "a\n\n  b\tc", 100, "a b c"},
		{"truncates on rune boundary", "héllo wörld", 7, "héll..."},
		{"empty", "", 10, ""},
		{"exact fit is not truncated", "abc", 3, "abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := apiref.StripMarkup(c.in, c.max); got != c.want {
				t.Errorf("StripMarkup(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	if got := apiref.Truncate("日本語テキスト", 5); got != "日本..." {
		t.Errorf("Truncate = %q", got)
	}
	if got := apiref.Truncate("ok", 5); got != "ok" {
		t.Errorf("Truncate short = %q", got)
	}
}

func TestTruncate_BelowEllipsisLength(t *testing.T) {
	t.Parallel()
	cases := []struct {
		max  int
		want string
	}{{-1, ""}, {0, ""}, {1, "日"}, {2, "日本"}, {3, "..."}}
	for _, tc := range cases {
		if got := apiref.Truncate("日本語テキスト", tc.max); got != tc.want {
			t.Errorf("Truncate(max=%d) = %q, want %q", tc.max, got, tc.want)
		}
	}
}

func TestStripMarkupCut(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		in       string
		maxBytes int
		maxRunes int
		want     string
	}{
		{"short text is StripMarkup", "<b>a</b>  b", 16, 10, "a b"},
		{"exactly maxBytes is not cut", "abcdefgh", 8, 10, "abcdefgh"},
		{"a cut always ends with the ellipsis", "abcdefghij", 8, 100, "abcdefgh..."},
		{"the cut backs off to a rune boundary", "abcdefgé", 8, 100, "abcdefg..."},
		{"a tag open across the cut drops the rest", "ab <span class=x>cd", 8, 100, "ab..."},
		{"a long cut is truncated to make room", "abcdefghij", 8, 6, "abc..."},
		{"whitespace at the cut collapses", "a b c d e f", 8, 100, "a b c d..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := apiref.StripMarkupCut(tc.in, tc.maxBytes, tc.maxRunes); got != tc.want {
				t.Errorf("StripMarkupCut(%q, %d, %d) = %q, want %q", tc.in, tc.maxBytes, tc.maxRunes, got, tc.want)
			}
		})
	}
}

func TestBounded(t *testing.T) {
	t.Parallel()
	const suffix = "; guidance the cut must keep"
	if got := apiref.Bounded("short", suffix); got != "short"+suffix {
		t.Errorf("short head: %q", got)
	}
	got := apiref.Bounded(strings.Repeat("é", 2*apiref.MaxReason), suffix)
	if !strings.HasSuffix(got, "..."+suffix) || utf8.RuneCountInString(got) != apiref.MaxReason {
		t.Errorf("long head: %d runes, %q", utf8.RuneCountInString(got), got[len(got)-60:])
	}
}

func TestStripMarkupCut_BelowEllipsisLength(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("ab ", 100)
	for n, want := range map[int]string{-1: "", 0: "", 1: "a", 2: "ab", 3: "..."} {
		if got := apiref.StripMarkupCut(long, 16, n); got != want {
			t.Errorf("maxRunes %d: %q, want %q", n, got, want)
		}
	}
}
