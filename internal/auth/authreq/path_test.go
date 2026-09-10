package authreq_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// equalReadings compares two reading sets element by element.
func equalReadings(a, b [][]string) bool {
	return slices.EqualFunc(a, b, slices.Equal)
}

func TestPathReadings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want [][]string
	}{
		{"plain path reads once", "https://x.example.com/a/b", [][]string{{"a", "b"}}},
		{"root reads as one empty segment", "https://x.example.com/", [][]string{{""}}},
		{"empty path reads as the wire's root", "https://x.example.com", [][]string{{""}}},
		{
			"encoded slash splits only in the decoded reading",
			"https://x.example.com/a/b%2Fc",
			[][]string{{"a", "b/c"}, {"a", "b", "c"}},
		},
		{
			"encoded literal decodes in both readings",
			"https://x.example.com/a/%70olicy",
			[][]string{{"a", "policy"}},
		},
		{
			"over-encoded slash stays inside one segment",
			"https://x.example.com/a/b%252Fc",
			[][]string{{"a", "b%2Fc"}},
		},
		{"interior and trailing empties survive", "https://x.example.com/a//b/", [][]string{{"a", "", "b", ""}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, c.raw, nil)
			if err != nil {
				t.Fatalf("new request %q: %v", c.raw, err)
			}

			if got := authreq.NewView(req, "").PathReadings(); !equalReadings(got, c.want) {
				t.Errorf("PathReadings() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestPathReadingsKeepsAnUndecodableSegment pins the fallback. [url.Parse] rejects
// a malformed escape upstream, so only a hand-built view reaches this branch,
// and it must keep the segment rather than drop its contents.
func TestPathReadingsKeepsAnUndecodableSegment(t *testing.T) {
	t.Parallel()

	v := authreq.View{Path: "/a/b%zz", EscapedPath: "/a/b%zz"}
	want := [][]string{{"a", "b%zz"}}

	if got := v.PathReadings(); !equalReadings(got, want) {
		t.Errorf("PathReadings() = %v, want %v", got, want)
	}
}
