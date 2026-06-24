package github

import "testing"

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
		got, ok := tbl.Lookup(c.method, c.path)
		if ok != c.wantOK {
			t.Fatalf("Lookup(%q,%q) ok=%v, want %v", c.method, c.path, ok, c.wantOK)
		}
		if ok && (got.Category != c.wantCat || got.Subcategory != c.wantSub) {
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
	got, ok := tbl.Lookup("GET", "/user/following")
	if !ok || got.Subcategory != "followers" {
		t.Fatalf("literal precedence: got %+v ok=%v, want followers", got, ok)
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
	got, ok := back.Lookup("GET", "/repos/o/r/contents/x/y")
	if !ok || got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("round-trip lookup = %+v ok=%v", got, ok)
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
	if r, ok := tbl.Lookup("GET", "/x"); !ok || r.Category != "meta" {
		t.Fatalf("lookup = %+v ok=%v, want meta", r, ok)
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
	got, ok := tbl.Lookup("GET", "/repos/o/r/git/trees/abc/def")
	if !ok || got.Category != "git" {
		t.Fatalf("inline-array param catch-all: got %+v ok=%v, want git/trees", got, ok)
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
	got, ok := tbl.Lookup("GET", "/repos/o/r/compare/main...feature/foo")
	if !ok || got.Category != "repos" || got.Subcategory != "commits" {
		t.Fatalf("compare/basehead with slash: got %+v ok=%v, want repos/commits", got, ok)
	}

	// releases/tags/{tag} — tag value contains a slash (release/1.0).
	got, ok = tbl.Lookup("GET", "/repos/o/r/releases/tags/release/1.0")
	if !ok || got.Category != "repos" || got.Subcategory != "releases" {
		t.Fatalf("releases/tags with slash: got %+v ok=%v, want repos/releases", got, ok)
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
	got, ok := back.Lookup("GET", "/repos/o/r/compare/main...feature/foo")
	if !ok || got.Subcategory != "commits" {
		t.Fatalf("round-trip compare lookup = %+v ok=%v, want commits", got, ok)
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
	got, ok := tbl.Lookup("GET", "/repos/o/r/contents")
	if !ok || got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("zero-segment catch-all: got %+v ok=%v, want repos/contents", got, ok)
	}

	// Contents with a non-empty path still works.
	got, ok = tbl.Lookup("GET", "/repos/o/r/contents/a/b.go")
	if !ok || got.Category != "repos" || got.Subcategory != "contents" {
		t.Fatalf("multi-segment catch-all: got %+v ok=%v, want repos/contents", got, ok)
	}

	// A genuinely unmatched short path is still rejected.
	_, ok = tbl.Lookup("GET", "/repos/o")
	if ok {
		t.Fatal("short unmatched path must not match, got ok=true")
	}
}
