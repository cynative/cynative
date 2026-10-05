package github

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

const miniOpenAPI = `{
  "components": {
    "parameters": {
      "path": {"name": "path", "x-multi-segment": true},
      "basehead": {"name": "basehead", "x-multi-segment": true},
      "tag": {"name": "tag", "x-multi-segment": true}
    }
  },
  "paths": {
    "/repos/{owner}/{repo}/issues": {
      "get":  {"x-github": {"category": "issues", "subcategory": "issues"}},
      "post": {"x-github": {"category": "issues", "subcategory": "issues"}}
    },
    "/repos/{owner}/{repo}/issues/{issue_number}": {
      "get": {"x-github": {"category": "issues", "subcategory": "issues"}}
    },
    "/repos/{owner}/{repo}/contents/{path}": {
      "get": {"x-github": {"category": "repos", "subcategory": "contents"}}
    },
    "/repos/{owner}/{repo}/compare/{basehead}": {
      "get": {"x-github": {"category": "repos", "subcategory": "commits"}}
    },
    "/repos/{owner}/{repo}/releases/tags/{tag}": {
      "get": {"x-github": {"category": "repos", "subcategory": "releases"}}
    },
    "/repos/{owner}/{repo}/secret-scanning/alerts": {
      "get": {"x-github": {"category": "secret-scanning", "subcategory": "secret-scanning"}}
    },
    "/markdown": {
      "post": {"x-github": {"category": "markdown", "subcategory": "markdown"}}
    }
  }
}`

func TestDistillAndLookup(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}

	cases := []struct {
		method, path string
		wantCat      string
		wantSub      string
		wantOK       bool
	}{
		{"GET", "/repos/o/r/issues", "issues", "issues", true},
		{"POST", "/repos/o/r/issues", "issues", "issues", true},
		{"GET", "/repos/o/r/issues/42", "issues", "issues", true},
		{"GET", "/repos/o/r/contents/src/a/b.go", "repos", "contents", true}, // catch-all {path}.
		{"GET", "/repos/o/r/secret-scanning/alerts", "secret-scanning", "secret-scanning", true},
		{"DELETE", "/repos/o/r/issues", "", "", false}, // method not in table.
		{"GET", "/unknown/path", "", "", false},        // no template.
	}
	for _, c := range cases {
		got := tbl.Lookup(c.method, c.path)
		if (len(got) > 0) != c.wantOK {
			t.Fatalf("Lookup(%q,%q) = %+v, want match=%v", c.method, c.path, got, c.wantOK)
		}
		if c.wantOK && (one(t, got).Category != c.wantCat || one(t, got).Subcategory != c.wantSub) {
			t.Fatalf("Lookup(%q,%q) = %+v, want {%s %s}", c.method, c.path, got, c.wantCat, c.wantSub)
		}
	}
}

func TestLiteralBeatsParam(t *testing.T) {
	t.Parallel()

	// /user/{x} (param) vs /user/following (literal) at the same arity: literal wins.
	const doc = `{"paths":{
		"/user/{id}": {"get": {"x-github": {"category": "users", "subcategory": "users"}}},
		"/user/following": {"get": {"x-github": {"category": "users", "subcategory": "followers"}}}
	}}`
	tbl, err := DistillOpenAPI([]byte(doc))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	got := one(t, tbl.Lookup("GET", "/user/following"))
	if got.Subcategory != "followers" {
		t.Fatalf("literal precedence: got %+v, want followers", got)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	blob := tbl.Serialize()
	back, err := UnmarshalTable(blob)
	if err != nil {
		t.Fatalf("UnmarshalTable: %v", err)
	}
	got := one(t, back.Lookup("GET", "/repos/o/r/contents/x/y"))
	if got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("round-trip lookup = %+v", got)
	}
}

func TestDistill_rejects(t *testing.T) {
	t.Parallel()

	bad := []struct {
		name, doc string
	}{
		{"empty paths", `{"paths":{}}`},
		{"garbage", `not json`},
		{"missing category", `{"paths":{"/x":{"get":{"x-github":{"subcategory":"s"}}}}}`},
		{"malformed op value", `{"paths":{"/x":{"get":"oops"}}}`},
		{"only non-method keys", `{"paths":{"/x":{"summary":"text"}}}`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DistillOpenAPI([]byte(c.doc)); err == nil {
				t.Fatalf("DistillOpenAPI(%s) err = nil, want error (fail closed)", c.name)
			}
		})
	}
}

func TestDistill_skipsNonMethodKeyOnSuccess(t *testing.T) {
	t.Parallel()

	// A path with both a method and a non-method key distills fine (continue skips
	// the non-method key, the method route is kept).
	const mixedDoc = `{"paths":{"/x":{"summary":"text","get":{"x-github":{"category":"meta","subcategory":"meta"}}}}}`
	tbl, err := DistillOpenAPI([]byte(mixedDoc))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if r := tbl.Lookup("GET", "/x"); len(r) != 1 || r[0].Category != "meta" {
		t.Fatalf("lookup = %+v, want meta", r)
	}
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// Routes returns all templates across all methods — miniOpenAPI defines exactly
	// 8 method/path operations (GET+POST issues, GET issues/{issue_number},
	// GET contents/{path}, GET compare/{basehead}, GET releases/tags/{tag},
	// GET secret-scanning/alerts, POST markdown).
	routes := tbl.Routes()
	if len(routes) != 8 {
		t.Fatalf("Routes() = %d, want 8", len(routes))
	}
}

func TestUnmarshalTable_rejects(t *testing.T) {
	t.Parallel()

	bad := []struct {
		name, blob string
	}{
		{"garbage json", "not json"},
		{"empty method map", `{"m":{}}`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := UnmarshalTable([]byte(c.blob)); err == nil {
				t.Fatalf("UnmarshalTable(%s) err = nil, want error", c.name)
			}
		})
	}
}

func TestSplitPath_empty(t *testing.T) {
	t.Parallel()

	// splitPath on an empty string or bare "/" must return nil (no segments).
	if got := splitPath(""); got != nil {
		t.Fatalf("splitPath(%q) = %v, want nil", "", got)
	}
	if got := splitPath("/"); got != nil {
		t.Fatalf("splitPath(%q) = %v, want nil", "/", got)
	}
}

// TestDistill_multiSegment_inlineArray verifies that collectMultiSegment also
// finds x-multi-segment params declared as inline arrays on operations (F2).
func TestDistill_multiSegment_inlineArray(t *testing.T) {
	t.Parallel()

	// Inline parameters are an array under the operation — verify the []any
	// branch of walkAny is exercised and the param is collected.
	const doc = `{
		"paths": {
			"/repos/{owner}/{repo}/git/trees/{tree_sha}": {
				"get": {
					"x-github": {"category": "git", "subcategory": "trees"},
					"parameters": [
						{"name": "tree_sha", "x-multi-segment": true},
						{"name": "owner"}
					]
				}
			}
		}
	}`
	tbl, err := DistillOpenAPI([]byte(doc))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if !tbl.multiSegment["tree_sha"] {
		t.Fatal("multiSegment[tree_sha] = false, want true (inline array param)")
	}
	// owner has no x-multi-segment, must not be in the set.
	if tbl.multiSegment["owner"] {
		t.Fatal("multiSegment[owner] = true, want false (no x-multi-segment)")
	}
	// tree_sha with an embedded slash classifies correctly.
	got := one(t, tbl.Lookup("GET", "/repos/o/r/git/trees/abc/def"))
	if got.Category != "git" {
		t.Fatalf("inline-array param catch-all: got %+v, want git/trees", got)
	}
}

// TestDistill_multiSegment verifies that DistillOpenAPI collects x-multi-segment
// param names from components.parameters and that routes with those params treat
// embedded slashes correctly (F2).
func TestDistill_multiSegment(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}

	// The miniOpenAPI fixture declares path, basehead, tag as x-multi-segment.
	for _, name := range []string{"path", "basehead", "tag"} {
		if !tbl.multiSegment[name] {
			t.Fatalf("multiSegment[%q] = false, want true", name)
		}
	}

	// compare/{basehead} — basehead value contains a slash (main...feature/foo).
	got := one(t, tbl.Lookup("GET", "/repos/o/r/compare/main...feature/foo"))
	if got.Category != "repos" || got.Subcategory != "commits" {
		t.Fatalf("compare/basehead with slash: got %+v, want repos/commits", got)
	}

	// releases/tags/{tag} — tag value contains a slash (release/1.0).
	got = one(t, tbl.Lookup("GET", "/repos/o/r/releases/tags/release/1.0"))
	if got.Category != "repos" || got.Subcategory != "releases" {
		t.Fatalf("releases/tags with slash: got %+v, want repos/releases", got)
	}
}

// TestMultiSegment_roundTrip verifies that multiSegment survives Serialize/UnmarshalTable (F2).
func TestMultiSegment_roundTrip(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	blob := tbl.Serialize()
	back, err := UnmarshalTable(blob)
	if err != nil {
		t.Fatalf("UnmarshalTable: %v", err)
	}
	// After round-trip, compare/{basehead} with a slash still classifies.
	got := one(t, back.Lookup("GET", "/repos/o/r/compare/main...feature/foo"))
	if got.Subcategory != "commits" {
		t.Fatalf("round-trip compare lookup = %+v, want commits", got)
	}
}

// TestCatchAll_zeroSegments verifies that a trailing catch-all param matches
// zero remaining segments, so /repos/o/r/contents (no path suffix) resolves
// to the contents template (F3).
func TestCatchAll_zeroSegments(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(miniOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}

	// Root contents path with no trailing segment.
	got := one(t, tbl.Lookup("GET", "/repos/o/r/contents"))
	if got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("zero-segment catch-all: got %+v, want repos/contents", got)
	}

	// Contents with a non-empty path still works.
	got = one(t, tbl.Lookup("GET", "/repos/o/r/contents/a/b.go"))
	if got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("multi-segment catch-all: got %+v, want repos/contents", got)
	}

	// A genuinely unmatched short path is still rejected.
	if got := tbl.Lookup("GET", "/repos/o"); got != nil {
		t.Fatalf("short unmatched path must not match, got %+v", got)
	}
}

// one returns the single route of a lookup, failing the test unless exactly one route came back.
func one(t *testing.T, routes []Route) Route {
	t.Helper()
	if len(routes) != 1 {
		t.Fatalf("routes = %+v, want exactly one", routes)
	}

	return routes[0]
}

const shadowOpenAPI = `{
  "components": {"parameters": {
    "branch": {"name": "branch", "x-multi-segment": true},
    "ref": {"name": "ref", "x-multi-segment": true},
    "path": {"name": "path", "x-multi-segment": true}
  }},
  "paths": {
    "/repos/{owner}/{repo}/branches/{branch}": {"get": {"x-github": {"category": "branches", "subcategory": "branches"}}},
    "/repos/{owner}/{repo}/branches/{branch}/protection": {"get": {"x-github": {"category": "branches", "subcategory": "branch-protection"}}},
    "/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users": {"get": {"x-github": {"category": "branches", "subcategory": "branch-protection"}}},
    "/repos/{owner}/{repo}/commits/{ref}": {"get": {"x-github": {"category": "commits", "subcategory": "commits"}}},
    "/repos/{owner}/{repo}/commits/{ref}/check-runs": {"get": {"x-github": {"category": "checks", "subcategory": "runs"}}},
    "/repos/{owner}/{repo}/commits/{ref}/status": {"get": {"x-github": {"category": "commits", "subcategory": "statuses"}}},
    "/repos/{owner}/{repo}/contents/{path}": {"get": {"x-github": {"category": "repos", "subcategory": "contents"}}},
    "/a/{ref}/{path}": {"get": {"x-github": {"category": "two", "subcategory": "greedy"}}},
    "/a/{ref}/z/{path}/end": {"get": {"x-github": {"category": "two", "subcategory": "suffix"}}},
    "/b/{id}": {"get": {"x-github": {"category": "b", "subcategory": "id"}}},
    "/c/{id}/lit": {"get": {"x-github": {"category": "c", "subcategory": "lit"}}},
    "/user/codespaces/secrets/{secret_name}": {"get": {"x-github": {"category": "codespaces", "subcategory": "secrets"}}},
    "/user/codespaces/secrets/{other}": {"get": {"x-github": {"category": "codespaces", "subcategory": "secrets"}}},
    "/user/codespaces/{codespace_name}/machines": {"get": {"x-github": {"category": "codespaces", "subcategory": "machines"}}}
  }
}`

func shadowTable(t *testing.T) *Table {
	t.Helper()
	tbl, err := DistillOpenAPI([]byte(shadowOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}

	return tbl
}

func TestLookup_MultiSegmentSpans(t *testing.T) {
	t.Parallel()

	tbl := shadowTable(t)
	cases := []struct {
		path string
		want []Route
	}{
		{"/repos/o/r/branches/main", []Route{{"branches", "branches"}}},
		{"/repos/o/r/branches/feat/x", []Route{{"branches", "branches"}}},
		{"/repos/o/r/branches/main/protection", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/branches/feat/x/protection", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/branches/feat%2Fx/protection", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/branches//protection", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/branches/main//protection", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/branches/main/protection/restrictions/users", []Route{{"branches", "branch-protection"}}},
		{"/repos/o/r/commits/main/check-runs", []Route{{"checks", "runs"}}},
		{"/repos/o/r/commits/feat/x/check-runs", []Route{{"checks", "runs"}}},
		{"/repos/o/r/commits/main/status", []Route{{"commits", "statuses"}}},
		{"/repos/o/r/contents", []Route{{"repos", "contents"}}},
		{"/repos/o/r/contents/", []Route{{"repos", "contents"}}},
		{"/repos/o/r/contents//", []Route{{"repos", "contents"}}},
		{"/repos/o/r/contents/dir/", []Route{{"repos", "contents"}}},
		{"/a/x", []Route{{"two", "greedy"}}},
		{"/a/x/y/z", []Route{{"two", "greedy"}}},
		{"/a/x/z/p/q/end", []Route{{"two", "suffix"}}},
		{"/b/", []Route{{"b", "id"}}},
		{"/", nil},
		{"", nil},
		{"/repos/o", nil},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			if got := tbl.Lookup("GET", c.path); !slices.Equal(got, c.want) {
				t.Errorf("Lookup(%q) = %+v, want %+v", c.path, got, c.want)
			}
		})
	}
}

func TestLookup_TrailingSlashReading(t *testing.T) {
	t.Parallel()

	tbl := shadowTable(t)
	cases := []struct {
		path string
		want []Route
	}{
		// One trailing slash: the escaped reading names the catch-all, the trimmed one the check runs.
		{"/repos/o/r/commits/main/check-runs/", []Route{{"checks", "runs"}, {"commits", "commits"}}},
		// Two trailing slashes get no extra reading.
		{"/repos/o/r/commits/main/check-runs//", []Route{{"commits", "commits"}}},
		// A literal-ended route with no catch-all above it stays unmatched: the extra reading never admits alone.
		{"/c/1/lit/", nil},
		// The same for a param-ended one.
		{"/b/x/", nil},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			if got := tbl.Lookup("GET", c.path); !slices.Equal(got, c.want) {
				t.Errorf("Lookup(%q) = %+v, want %+v", c.path, got, c.want)
			}
		})
	}
}

func TestLookup_TiesReturnEveryFamilySorted(t *testing.T) {
	t.Parallel()

	// secrets/{secret_name} and secrets/{other} collapse to one pair; machines stays.
	want := []Route{{"codespaces", "machines"}, {"codespaces", "secrets"}}
	tbl := shadowTable(t)
	if got := tbl.Lookup("GET", "/user/codespaces/secrets/machines"); !slices.Equal(got, want) {
		t.Fatalf("Lookup = %+v, want %+v", got, want)
	}
	// The stored template order does not change the result.
	w := tableWire{ByMethod: map[string][]Templ{"GET": nil}}
	for _, tm := range slices.Backward(tbl.byMethod["GET"]) {
		w.ByMethod["GET"] = append(w.ByMethod["GET"], tm)
	}
	blob, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := UnmarshalTable(blob)
	if err != nil {
		t.Fatalf("UnmarshalTable: %v", err)
	}
	if got := back.Lookup("GET", "/user/codespaces/secrets/machines"); !slices.Equal(got, want) {
		t.Fatalf("reversed-order Lookup = %+v, want %+v", got, want)
	}
	cached, err := UnmarshalTable(tbl.Serialize())
	if err != nil {
		t.Fatalf("UnmarshalTable(Serialize): %v", err)
	}
	if got := cached.Lookup("GET", "/user/codespaces/secrets/machines"); !slices.Equal(got, want) {
		t.Fatalf("round-trip Lookup = %+v, want %+v", got, want)
	}
}

func TestBest_KeepsOnlyTheTopRank(t *testing.T) {
	t.Parallel()

	tbl := &Table{multiSegment: map[string]bool{}}
	tmpls := []Templ{
		{Segments: []string{"{a}", "{b}"}, Route: Route{"low", "one"}},
		{Segments: []string{"{c}", "{d}"}, Route: Route{"low", "two"}},
		{Segments: []string{"x", "{e}"}, Route: Route{"top", "one"}},
		{Segments: []string{"{f}", "{g}"}, Route: Route{"low", "three"}},
	}
	got := tbl.best(tmpls, []string{"x", "y"})
	if want := []Route{{"top", "one"}}; !slices.Equal(got, want) {
		t.Fatalf("best = %+v, want %+v", got, want)
	}
}

func TestMatchTemplate_BoundedOnLongPaths(t *testing.T) {
	t.Parallel()

	names := []string{"p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"}
	tbl := &Table{multiSegment: map[string]bool{}}
	tmpl := []string{"a"}
	for _, n := range names {
		tbl.multiSegment[n] = true
		tmpl = append(tmpl, "{"+n+"}")
	}
	tmpl = append(tmpl, "end")
	req := append([]string{"a"}, slices.Repeat([]string{"z"}, 200)...)
	// Without the memo the walk explores every way to split 200 segments among ten spans, which never finishes;
	// with it the work is bounded by (template segments + 1) x (request segments + 1) states.
	done := make(chan bool, 1)
	go func() { done <- tbl.matchTemplate(tmpl, req) }()
	select {
	case got := <-done:
		if got {
			t.Fatal("a path without the literal end matched")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("matchTemplate did not return within 5s")
	}
}

func TestMatchFixed(t *testing.T) {
	t.Parallel()

	tbl := shadowTable(t)
	if tbl.matchTemplate([]string{"b", "{id}"}, []string{"b", "x", "y"}) {
		t.Error("a longer request matched a fixed-length template")
	}
	if tbl.matchTemplate([]string{"c", "{id}", "lit"}, []string{"c", "1", "other"}) {
		t.Error("a differing literal matched")
	}
}
