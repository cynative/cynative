package gitlab

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/apiref"
)

// TestClassifyVersion_BoundsTheEcho pins that an unrecognized version, which the instance supplies, reaches the
// reason quoted and bounded: a long value and one heavy with quotes, backslashes and control characters.
func TestClassifyVersion_BoundsTheEcho(t *testing.T) {
	t.Parallel()
	const prefix = "instance reports unrecognized version "
	cases := map[string]string{
		"long":         strings.Repeat("9", 10000),
		"escape heavy": strings.Repeat("\"\\\n\x00\u202e", 400),
	}
	for name, version := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			class, ref, reason := ClassifyVersion(version, "gitlab.com", "443")
			if class != VersionUnknown || ref != "" {
				t.Fatalf("class %v ref %q", class, ref)
			}
			want := prefix + apiref.Truncate(strconv.Quote(version), apiref.MaxChoice)
			if reason != want {
				t.Errorf("reason = %q, want %q", reason, want)
			}
			if n := utf8.RuneCountInString(reason); n > len(prefix)+apiref.MaxChoice {
				t.Errorf("reason has %d runes", n)
			}
			if strings.ContainsAny(reason, "\n\x00") {
				t.Errorf("reason carries a raw control character: %q", reason)
			}
		})
	}
}
