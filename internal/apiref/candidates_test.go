package apiref_test

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

func route53Routes() []apiref.Route {
	return []apiref.Route{
		{Operation: "ListHostedZones", Method: "GET", Template: "/2013-04-01/hostedzone"},
		{Operation: "CreateHostedZone", Method: "POST", Template: "/2013-04-01/hostedzone"},
		{Operation: "GetHostedZone", Method: "GET", Template: "/2013-04-01/hostedzone/{Id}"},
		{Operation: "ListHealthChecks", Method: "GET", Template: "/2013-04-01/healthcheck"},
	}
}

func TestCandidates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		path   string
		want   []string
	}{
		{
			"near miss plural", "GET", "/2013-04-01/hostedzones",
			[]string{"ListHostedZones (GET /2013-04-01/hostedzone)"},
		},
		{
			"wrong method", "DELETE", "/2013-04-01/hostedzone",
			[]string{"CreateHostedZone (POST /2013-04-01/hostedzone)", "ListHostedZones (GET /2013-04-01/hostedzone)"},
		},
		{"too far", "GET", "/2013-04-01/zonesxyz", nil},
		{"different arity", "GET", "/2013-04-01", nil},
		{"escaped slash stays one segment", "GET", "/2013-04-01/hostedzone%2Fx", nil},
		{"trailing slash", "GET", "/2013-04-01/hostedzone/", nil},
		{"root path", "GET", "/", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := apiref.Candidates(route53Routes(), c.method, c.path)
			if !slices.Equal(got, c.want) {
				t.Errorf("Candidates(%s %s) = %q, want %q", c.method, c.path, got, c.want)
			}
		})
	}
}

func TestCandidates_GreedyTemplate(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{{Operation: "GetObject", Method: "GET", Template: "/{Bucket}/{Key+}?x-id=GetObject"}}
	got := apiref.Candidates(routes, "PUT", "/b/k/a/b")
	if !slices.Equal(got, []string{"GetObject (GET /{Bucket}/{Key+}?x-id=GetObject)"}) {
		t.Errorf("got %q", got)
	}
	if got = apiref.Candidates(routes, "PUT", "/b"); got != nil {
		t.Errorf("greedy needs at least one tail segment, got %q", got)
	}
	if got = apiref.Candidates(routes, "GET", "/b/k"); got != nil {
		t.Errorf("a greedy template is never a near miss, got %q", got)
	}
}

func TestCandidates_TooManyYieldsNone(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{
		{Operation: "A", Method: "GET", Template: "/x/aa"},
		{Operation: "B", Method: "GET", Template: "/x/ab"},
		{Operation: "C", Method: "GET", Template: "/x/ac"},
		{Operation: "D", Method: "GET", Template: "/x/ad"},
	}
	if got := apiref.Candidates(routes, "GET", "/x/a"); got != nil {
		t.Errorf("want nil, got %q", got)
	}
}

func TestCandidates_Dedupes(t *testing.T) {
	t.Parallel()

	r := apiref.Route{Operation: "A", Method: "GET", Template: "/x/aa"}
	if got := apiref.Candidates([]apiref.Route{r, r}, "GET", "/x/a"); len(got) != 1 {
		t.Errorf("want one, got %q", got)
	}
}

func TestBound(t *testing.T) {
	t.Parallel()

	if got := apiref.Bound([]string{"b", "a", "b"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("got %q", got)
	}
	if got := apiref.Bound([]string{"a", "b", "c", "d"}); got != nil {
		t.Errorf("over the cap: %q", got)
	}
	if got := apiref.Bound(nil); got != nil {
		t.Errorf("empty: %q", got)
	}
}

func TestBound_TruncatesLines(t *testing.T) {
	t.Parallel()

	got := apiref.Bound([]string{strings.Repeat("é", 5000)})
	if len(got) != 1 || len([]rune(got[0])) > apiref.MaxChoice {
		t.Errorf("line not bounded: %d candidates", len(got))
	}
	long := apiref.Candidates([]apiref.Route{
		{Operation: strings.Repeat("o", 5000), Method: "POST", Template: "/a"},
	}, "GET", "/a")
	if len(long) != 1 || len([]rune(long[0])) > apiref.MaxChoice {
		t.Errorf("candidate not bounded: %d", len(long))
	}
}

func TestCandidateOperations(t *testing.T) {
	t.Parallel()

	got := apiref.CandidateOperations(route53Routes(), "GET", "/2013-04-01/hostedzones")
	if !slices.Equal(got, []string{"ListHostedZones"}) {
		t.Errorf("got %q", got)
	}
}

func TestCandidates_GreedyWithSuffix(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{{Operation: "GetPolicy", Method: "GET", Template: "/{Name+}/policy"}}
	cases := []struct {
		name string
		path string
		want []string
	}{
		{"suffix matches", "/a/b/policy", []string{"GetPolicy (GET /{Name+}/policy)"}},
		{"suffix differs", "/a/b/other", nil},
		{"greedy needs a segment", "/policy", nil},
		{"single empty segment", "//policy", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := apiref.Candidates(routes, "PUT", c.path)
			if !slices.Equal(got, c.want) {
				t.Errorf("Candidates(PUT %s) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestCandidates_WrongMethodBeatsNearMiss(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{
		{Operation: "Near", Method: "GET", Template: "/x/aa"},
		{Operation: "Exact", Method: "POST", Template: "/x/a"},
	}
	got := apiref.Candidates(routes, "GET", "/x/a")
	if !slices.Equal(got, []string{"Exact (POST /x/a)"}) {
		t.Errorf("got %q", got)
	}
}

func TestCandidates_EditDistanceByRune(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{{Operation: "A", Method: "GET", Template: "/x/\u00e9\u00e9\u00e9"}}
	got := apiref.Candidates(routes, "GET", "/x/e\u00e9e")
	if !slices.Equal(got, []string{"A (GET /x/\u00e9\u00e9\u00e9)"}) {
		t.Errorf("got %q", got)
	}
}

// allocatedBytes reports the heap bytes one call of f allocates, averaged over a few runs. It reads
// process-wide counters, so callers run serially.
func allocatedBytes(f func()) uint64 {
	const runs = 5
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / runs
}

func TestCandidates_PathCapIsPinnedByBehavior(t *testing.T) {
	t.Parallel()

	routes := []apiref.Route{{Operation: "GetObject", Method: "GET", Template: "/{Bucket}/{Key+}"}}
	const prefix = "/b/"
	atCap := prefix + strings.Repeat("k", 2048-len(prefix))
	want := []string{"GetObject (GET /{Bucket}/{Key+})"}
	if got := apiref.Candidates(routes, "PUT", atCap); !slices.Equal(got, want) {
		t.Errorf("2048-byte path: got %v, want %v", got, want)
	}
	if got := apiref.Candidates(routes, "PUT", atCap+"k"); got != nil {
		t.Errorf("2049-byte path: got %v, want nil", got)
	}
	if got := apiref.CandidateOperations(routes, "PUT", atCap+"k"); got != nil {
		t.Errorf("2049-byte path operations: got %v, want nil", got)
	}
}

// The allocation counters are process-wide, so this test runs serially.
//
//nolint:paralleltest // process-wide allocation counters, see above.
func TestCandidates_LongSegmentUnderCapSkipsEditDistance(t *testing.T) {
	routes := route53Routes()
	long := "/2013-04-01/" + strings.Repeat("a", 2000)
	if got := apiref.Candidates(routes, "GET", long); got != nil {
		t.Errorf("Candidates = %v, want nil", got)
	}
	if n := allocatedBytes(func() { _ = apiref.Candidates(routes, "GET", long) }); n > 4096 {
		t.Errorf("allocated %d bytes per call over a 2000-byte segment, want at most 4096", n)
	}
	if got := apiref.Candidates(routes, "GET", "/2013-04-01/hostedzones"); len(got) != 1 {
		t.Errorf("near miss under the caps = %v, want one candidate", got)
	}
}

func TestCandidates_ZeroOrMoreTail(t *testing.T) {
	t.Parallel()

	star := []apiref.Route{{Operation: "GetR", Method: "GET", Template: "/r/{p*}"}}
	for _, path := range []string{"/r", "/r/a", "/r/a/b"} {
		if got := apiref.Candidates(star, "PUT", path); !slices.Equal(got, []string{"GetR (GET /r/{p*})"}) {
			t.Errorf("%s: got %q", path, got)
		}
	}
	for _, path := range []string{"/", "/x/a"} {
		if got := apiref.Candidates(star, "PUT", path); got != nil {
			t.Errorf("%s: got %q", path, got)
		}
	}
	if got := apiref.Candidates(star, "GET", "/rr"); got != nil {
		t.Errorf("a star label must not be a near miss: %q", got)
	}
	plus := []apiref.Route{{Operation: "GetR", Method: "GET", Template: "/r/{p+}"}}
	if got := apiref.Candidates(plus, "PUT", "/r"); got != nil {
		t.Errorf("plus matched zero segments: %q", got)
	}
}
