package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSanitizeInline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "public-exposure", "public-exposure"},
		{"escape becomes a space", "a\x1b[31mred", "a [31mred"},
		{"newline becomes a space", "a\nb", "a b"},
		{"carriage return becomes a space", "a\rb", "a b"},
		{"tab becomes a space", "a\tb", "a b"},
		{"DEL becomes a space", "a\x7fb", "a b"},
		{"C1 control becomes a space", "a\u0085b", "a b"},
		{"bell becomes a space", "a\ab", "a b"},
		{"non-ascii text preserved", "café ✓", "café ✓"},
		{"empty stays empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := sanitizeInline(tc.in); got != tc.want {
				t.Fatalf("sanitizeInline(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeErr(t *testing.T) {
	t.Parallel()

	if sanitizeErr(nil) != nil {
		t.Fatal("sanitizeErr(nil) must stay nil")
	}

	sentinel := errors.New("boom")
	wrapped := sanitizeErr(fmt.Errorf("at /p/\x1b[31mevil.md: %w", sentinel))

	if strings.Contains(wrapped.Error(), "\x1b") {
		t.Errorf("sanitizeErr did not strip the escape: %q", wrapped.Error())
	}
	if !errors.Is(wrapped, sentinel) {
		t.Error("sanitizeErr must preserve errors.Is through Unwrap")
	}
}
