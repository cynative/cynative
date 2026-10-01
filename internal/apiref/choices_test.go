package apiref_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

func TestChoices(t *testing.T) {
	t.Parallel()
	in := []string{"g", "b", "a", "f", "e", "d", "c"}
	if got := apiref.Choices(in); !slices.Equal(got, []string{"a", "b", "c", "d", "e"}) {
		t.Errorf("got %q", got)
	}
	if in[0] != "g" {
		t.Errorf("input mutated: %q", in)
	}
	long := strings.Repeat("x", apiref.MaxChoice+5)
	if got := apiref.Choices(
		[]string{long},
	); len([]rune(got[0])) != apiref.MaxChoice ||
		!strings.HasSuffix(got[0], "...") {
		t.Errorf("got %q", got[0])
	}
	if got := apiref.Choices(nil); len(got) != 0 {
		t.Errorf("got %q", got)
	}
}
