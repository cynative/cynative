package cloudauth

import (
	"errors"
	"strings"
	"testing"
)

func TestShortenError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   error
		max  int
		want string
	}{
		{"strips newlines and CR", errors.New("a\nb\r\nc"), 100, "a b c"},
		{"short passes through", errors.New("short"), 100, "short"},
		{"truncates and appends ellipsis", errors.New(strings.Repeat("x", 200)), 10, strings.Repeat("x", 10) + "…"},
		{"exact length not truncated", errors.New(strings.Repeat("y", 10)), 10, strings.Repeat("y", 10)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ShortenError(c.in, c.max); got != c.want {
				t.Errorf("ShortenError(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
			}
		})
	}
}
