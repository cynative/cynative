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
			[][]string{{"a", "b%2Fc"}, {"a", "b", "c"}},
		},
		{
			"encoded literal decodes only in the decoded reading",
			"https://x.example.com/a/%70olicy",
			[][]string{{"a", "%70olicy"}, {"a", "policy"}},
		},
		{
			"over-encoded slash decodes one level only in the decoded reading",
			"https://x.example.com/a/b%252Fc",
			[][]string{{"a", "b%252Fc"}, {"a", "b%2Fc"}},
		},
		{
			"interior and trailing empties survive, and the trailing one also drops",
			"https://x.example.com/a//b/",
			[][]string{{"a", "", "b", ""}, {"a", "", "b"}},
		},
		{
			"a doubled leading slash keeps its empty segment",
			"https://x.example.com//a/b",
			[][]string{{"", "a", "b"}},
		},
		{
			"a trailing slash also reads with the empty segment dropped",
			"https://x.example.com/bucket/",
			[][]string{{"bucket", ""}, {"bucket"}},
		},
		{
			"a doubled trailing slash drops only the one segment",
			"https://x.example.com/a//",
			[][]string{{"a", "", ""}, {"a", ""}},
		},
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
