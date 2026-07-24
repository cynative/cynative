package sandbox

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzFinalize pins panic-freedom, valid UTF-8 output, and the truncation /
// empty-output contracts over arbitrary script output (#181).
func FuzzFinalize(f *testing.F) {
	f.Add(10, "0123456789ABCDEF")
	f.Add(32*1024, "hello")
	f.Add(1, "")
	f.Add(8, string([]byte{0xff, 0xfe, 'h', 'i'}))
	f.Add(4, string([]byte{0xed, 0xa0, 0x80})) // lone UTF-8 surrogate → repaired

	f.Fuzz(func(t *testing.T, maxOut int, out string) {
		if maxOut < 1 {
			maxOut = 1
		}
		if maxOut > 1<<20 {
			maxOut = 1 << 20
		}

		got := (&Sandbox{maxOutput: maxOut}).finalize(out)

		if !utf8.ValidString(got) {
			t.Fatalf("non-UTF-8 output: %q", got)
		}
		if got == "" {
			t.Fatal("finalize returned empty string")
		}
		if out == "" && got != noOutputMessage {
			t.Fatalf("empty input → %q, want %q", got, noOutputMessage)
		}
		if len(out) > maxOut {
			marker := fmt.Sprintf("truncated at %d bytes", maxOut)
			if !strings.Contains(got, marker) {
				t.Fatalf("missing truncation marker %q in %q", marker, got)
			}
		}
	})
}
