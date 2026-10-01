package apiref_test

import (
	"slices"
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

func TestCandidateOperations(t *testing.T) {
	t.Parallel()

	got := apiref.CandidateOperations(route53Routes(), "GET", "/2013-04-01/hostedzones")
	if !slices.Equal(got, []string{"ListHostedZones"}) {
		t.Errorf("got %q", got)
	}
}
