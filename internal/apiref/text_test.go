package apiref_test

import (
	"testing"

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
