package gitlab

import (
	"errors"
	"slices"
	"testing"
)

func TestNormalizeTag(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"CI variables":       "ci-variables",
		"Merge requests":     "merge-requests",
		"To-dos":             "to-dos",
		"Pipeline schedules": "pipeline-schedules",
		"Projects":           "projects",
	}
	for in, want := range cases {
		if got := NormalizeTag(in); got != want {
			t.Errorf("NormalizeTag(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestNormalizeTag_allNonAlnum covers the all-non-alphanumeric tag → "" case.
func TestNormalizeTag_allNonAlnum(t *testing.T) {
	t.Parallel()
	if got := NormalizeTag("---"); got != "" {
		t.Errorf("NormalizeTag(%q)=%q, want empty", "---", got)
	}
}

func TestDistillOpenAPI_TagsToCategory(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
    post:
      tags: ["Issues"]
  /api/v4/projects/{id}/variables/{key}:
    get:
      tags: ["CI variables"]
  /api/v4/internal/secret_meta:
    get: {}
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	r, ok := tbl.Lookup("GET", "/api/v4/projects/42/issues")
	if !ok || r.Category != "issues" {
		t.Errorf("GET issues → %+v ok=%v, want category issues", r, ok)
	}
	r, ok = tbl.Lookup("GET", "/api/v4/projects/42/variables/DEPLOY_KEY")
	if !ok || r.Category != "ci-variables" {
		t.Errorf("GET variable → %+v ok=%v, want ci-variables", r, ok)
	}
	// Untagged op is skipped → not classifiable.
	if _, found := tbl.Lookup("GET", "/api/v4/internal/secret_meta"); found {
		t.Error("untagged op should be absent from table (fail closed)")
	}
}

// TestDistillOpenAPI_ForcesCIVariablesForVariablesTemplate verifies the
// distill-time override: a template whose segments contain a literal "variables"
// segment is forced to the ci-variables category regardless of the operation's own
// tag (here "Pipelines"), while a sibling template with no such segment keeps its
// genuine category. This is what closes the request-time bypass — the override now
// keys off the trusted spec template, not the user-controlled request path.
func TestDistillOpenAPI_ForcesCIVariablesForVariablesTemplate(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/pipelines/{pid}/variables:
    get:
      tags: ["Pipelines"]
  /api/v4/projects/{id}/repository/files/{file_path}:
    put:
      tags: ["Repository files"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// The Pipelines-tagged variables template is forced to ci-variables.
	if r, ok := tbl.Lookup("GET", "/api/v4/projects/1/pipelines/9/variables"); !ok || r.Category != "ci-variables" {
		t.Errorf("variables template → %+v ok=%v, want ci-variables (forced override)", r, ok)
	}
	// A sibling template with no literal variables segment keeps its genuine category.
	if r, ok := tbl.Lookup("PUT", "/api/v4/projects/1/repository/files/variables"); !ok ||
		r.Category != "repository-files" {
		t.Errorf("repository-files template → %+v ok=%v, want repository-files (no override)", r, ok)
	}
}

// TestDistillOpenAPI_skipsNonMethodKey verifies a non-method path-item key (a
// parameters/summary key under a path) is skipped without failing the parse.
func TestDistillOpenAPI_skipsNonMethodKey(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    summary: "project endpoints"
    parameters: []
    get:
      tags: ["Projects"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if r, ok := tbl.Lookup("GET", "/api/v4/projects"); !ok || r.Category != "projects" {
		t.Errorf("lookup = %+v ok=%v, want projects", r, ok)
	}
}

// TestDistillOpenAPI_emptyTagsSkipped covers an op with tags: [] (no non-empty
// tag) being skipped — the path produces no route.
func TestDistillOpenAPI_emptyTagsSkipped(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: []
  /api/v4/groups:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if _, ok := tbl.Lookup("GET", "/api/v4/projects"); ok {
		t.Error("op with empty tags should be skipped")
	}
	if _, ok := tbl.Lookup("GET", "/api/v4/groups"); !ok {
		t.Error("tagged op should classify")
	}
}

// TestDistillOpenAPI_emptyStringTagSkipped covers an op whose only tag is an
// empty string (normalizes to "") being skipped.
func TestDistillOpenAPI_emptyStringTagSkipped(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: [""]
  /api/v4/groups:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if _, ok := tbl.Lookup("GET", "/api/v4/projects"); ok {
		t.Error("op with only an empty-string tag should be skipped")
	}
}

// TestDistillOpenAPI_undecodableNodeSkipped covers firstTagCategory's decode-
// error path: an op node whose tags field is the wrong shape fails to decode
// into the tags struct and is skipped.
func TestDistillOpenAPI_undecodableNodeSkipped(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags:
        bad: "mapping-not-a-list"
  /api/v4/groups:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if _, ok := tbl.Lookup("GET", "/api/v4/projects"); ok {
		t.Error("op whose node fails to decode should be skipped")
	}
	if _, ok := tbl.Lookup("GET", "/api/v4/groups"); !ok {
		t.Error("tagged op should classify")
	}
}

// TestDistillOpenAPI_rejects covers the two fail-closed reject paths: invalid
// YAML and a spec that produces no routes.
func TestDistillOpenAPI_rejects(t *testing.T) {
	t.Parallel()
	bad := []struct {
		name string
		raw  string
	}{
		{"invalid yaml", "\t::not yaml::\n  - [unbalanced"},
		{"no routes (all untagged)", "openapi: \"3.0.0\"\npaths:\n  /api/v4/x:\n    get: {}\n"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := DistillOpenAPI([]byte(c.raw))
			if err == nil {
				t.Fatalf("DistillOpenAPI(%s) err = nil, want error (fail closed)", c.name)
			}
			if !errors.Is(err, ErrTableRejected) {
				t.Fatalf("DistillOpenAPI(%s) err = %v, want ErrTableRejected", c.name, err)
			}
		})
	}
}

// TestLookup_RequiresRootAnchor pins the ROOT-only anchor: a request classifies
// only when its path STARTS with the decoded "api","v4" pair. A non-root "api/v4"
// — a path-prefixed form (/group/api/v4/...) or a self-managed subpath install
// (/gitlab/api/v4/...) — is DENIED (the connector serves the API at the host root
// only, so a non-root api/v4 would attach the Bearer token to a non-API path). The
// encoded-'api' case still anchors because it decodes to "api" at index 0.
//
// This test DISCRIMINATES against the prior anchor-anywhere behavior: under the old
// anchorIndex (first api/v4 pair ANYWHERE), the /group/... and /gitlab/... paths
// would anchor at index 1 and classify to "issues" — the !ok assertions below would
// then FAIL. They pass only under root anchoring.
func TestLookup_RequiresRootAnchor(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
`)
	tbl, _ := DistillOpenAPI(raw)
	// Root anchor: path starts with api/v4 → classifies.
	if r, ok := tbl.Lookup("GET", "/api/v4/projects/42/issues"); !ok || r.Category != "issues" {
		t.Errorf("root path → %+v ok=%v, want issues", r, ok)
	}
	// Encoded 'api' at the root still anchors (decodes to api at index 0).
	if r, ok := tbl.Lookup("GET", "/%61pi/v4/projects/42/issues"); !ok || r.Category != "issues" {
		t.Errorf("encoded root api segment → %+v ok=%v, want issues", r, ok)
	}
	// Path-prefixed api/v4 (attacker-controlled leading segment) → DENIED.
	if r, ok := tbl.Lookup("GET", "/group/api/v4/projects/42/issues"); ok {
		t.Errorf("non-root /group/api/v4/... must be denied → %+v ok=%v", r, ok)
	}
	// Self-managed subpath install → DENIED (subpath installs are unsupported: the
	// eager /api/v4/user probe runs at the host root, so they cannot register).
	if r, ok := tbl.Lookup("GET", "/gitlab/api/v4/projects/42/issues"); ok {
		t.Errorf("subpath /gitlab/api/v4/... must be denied → %+v ok=%v", r, ok)
	}
	// No api/v4 anchor at all → not found.
	if _, ok := tbl.Lookup("GET", "/foo/bar/baz"); ok {
		t.Error("no anchor should fail closed")
	}
}

// TestLookup_literalBeatsParam verifies a more-literal template wins over a
// param template at the same arity.
func TestLookup_literalBeatsParam(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/user/{id}:
    get:
      tags: ["Users"]
  /api/v4/user/status:
    get:
      tags: ["User status"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	r, ok := tbl.Lookup("GET", "/api/v4/user/status")
	if !ok || r.Category != "user-status" {
		t.Errorf("literal precedence → %+v ok=%v, want user-status", r, ok)
	}
}

// TestLookup_arityMismatch verifies a request whose segment count differs from
// every template does not match.
func TestLookup_arityMismatch(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// Too few segments after the anchor.
	if _, ok := tbl.Lookup("GET", "/api/v4/projects/42"); ok {
		t.Error("arity mismatch (too short) must not match")
	}
	// Too many segments after the anchor.
	if _, ok := tbl.Lookup("GET", "/api/v4/projects/42/issues/extra"); ok {
		t.Error("arity mismatch (too long) must not match")
	}
}

// TestLookup_undecodableSegmentFallback verifies decodeSegs leaves an
// undecodable segment (a lone '%') as-is so it is still usable for matching.
func TestLookup_undecodableSegmentFallback(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// A lone '%' is not a valid percent-escape; the segment is left as-is and
	// still matches the {id} param template.
	if r, ok := tbl.Lookup("GET", "/api/v4/projects/%/issues"); !ok || r.Category != "issues" {
		t.Errorf("undecodable segment fallback → %+v ok=%v, want issues", r, ok)
	}
}

// TestAnchorIndex_rootKeepsDownstreamPair verifies root anchoring keeps the ENTIRE
// path from index 0 — a downstream "api/v4" carried in a path PARAMETER (a project
// path or file named ".../api/v4/...") is NOT a re-anchor point. With BOTH a
// 5-segment projects template and a 3-segment bare-issues template registered, the
// request "/api/v4/projects/api/v4/issues" decodes to the six segments
// [api,v4,projects,api,v4,issues] and is kept whole (anchor at index 0) → matches
// NEITHER template → denied. A broken anchor that re-anchored on the downstream
// api/v4 would trim to [api,v4,issues] → match the bare-issues template and forge a
// classification, so asserting ok==false DISCRIMINATES against any anchor that does
// not pin to the root.
func TestAnchorIndex_rootKeepsDownstreamPair(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
  /api/v4/issues:
    get:
      tags: ["Issues"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if r, ok := tbl.Lookup("GET", "/api/v4/projects/api/v4/issues"); ok {
		t.Errorf("root anchor must keep all six segments and deny; a re-anchor would classify → %+v ok=%v", r, ok)
	}
}

// TestAnchorIndex_root verifies anchorIndex returns 0 for a root api/v4 path and -1
// otherwise (no pair, too short, or a non-root pair), pinning the helper directly.
func TestAnchorIndex_root(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		segs []string
		want int
	}{
		{"root pair", []string{"api", "v4", "projects"}, 0},
		{"exactly api,v4", []string{"api", "v4"}, 0},
		{"non-root pair", []string{"group", "api", "v4", "projects"}, -1},
		{"no pair", []string{"foo", "bar"}, -1},
		{"only api", []string{"api"}, -1},
		{"api then not v4", []string{"api", "v3"}, -1},
		{"empty", nil, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := anchorIndex(c.segs); got != c.want {
				t.Errorf("anchorIndex(%v) = %d, want %d", c.segs, got, c.want)
			}
		})
	}
}

// TestDecodeSegs_percentSlashStaysOneSegment verifies the correct split-then-
// decode order keeps a %2F-encoded value inside ONE path segment: a request
// "/api/v4/groups/a%2Fb/issues" must split on literal "/" first (5 segments) and
// only then decode "a%2Fb" → "a/b" as a single {id} value, so it matches the
// 5-segment template and classifies. A broken decode-then-split would yield
// [api,v4,groups,a,b,issues] (6 segments) → arity mismatch → deny. Asserting the
// request DOES classify therefore FAILS under decode-then-split.
func TestDecodeSegs_percentSlashStaysOneSegment(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/groups/{id}/issues:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// %2F inside the {id} value stays one segment under correct split-then-decode
	// → 5 segments → matches. A decode-then-split would forge a 6th segment and
	// deny on arity.
	if r, ok := tbl.Lookup("GET", "/api/v4/groups/a%2Fb/issues"); !ok || r.Category != "groups" {
		t.Errorf("%%2F must stay one segment and classify → %+v ok=%v, want groups", r, ok)
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	t.Parallel()
	raw := []byte("openapi: \"3.0.0\"\npaths:\n  /api/v4/projects:\n    get:\n      tags: [\"Projects\"]\n")
	tbl, _ := DistillOpenAPI(raw)
	tbl2, err := UnmarshalTable(tbl.Serialize())
	if err != nil {
		t.Fatalf("UnmarshalTable: %v", err)
	}
	if r, ok := tbl2.Lookup("GET", "/api/v4/projects"); !ok || r.Category != "projects" {
		t.Errorf("round-trip lookup → %+v ok=%v", r, ok)
	}
}

// TestUnmarshalTable_rejects covers the two fail-closed deserialize paths.
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
			_, err := UnmarshalTable([]byte(c.blob))
			if err == nil {
				t.Fatalf("UnmarshalTable(%s) err = nil, want error", c.name)
			}
			if !errors.Is(err, ErrTableRejected) {
				t.Fatalf("UnmarshalTable(%s) err = %v, want ErrTableRejected", c.name, err)
			}
		})
	}
}

// TestKnows verifies Knows reports true for a real category and false otherwise.
func TestKnows(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: ["Projects"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if !tbl.Knows("projects") {
		t.Error("Knows(projects) = false, want true")
	}
	if tbl.Knows("nonexistent") {
		t.Error("Knows(nonexistent) = true, want false")
	}
}

// TestSplitPathSegs_empty covers the empty/bare-slash path → nil branch.
func TestSplitPathSegs_empty(t *testing.T) {
	t.Parallel()
	if got := splitPathSegs(""); got != nil {
		t.Errorf("splitPathSegs(%q) = %v, want nil", "", got)
	}
	if got := splitPathSegs("/"); got != nil {
		t.Errorf("splitPathSegs(%q) = %v, want nil", "/", got)
	}
}

// TestRoutes verifies Routes returns every distilled template.
func TestRoutes(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
    post:
      tags: ["Issues"]
  /api/v4/groups:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// 3 operations: GET+POST issues, GET groups.
	if got := len(tbl.Routes()); got != 3 {
		t.Fatalf("Routes() = %d, want 3", got)
	}
}

// TestLookup_StripsFormatSuffix verifies Lookup strips GitLab's optional Rails
// ".:format" suffix from the last request segment before matching: a literal
// endpoint (projects) matches its format-suffixed form (projects.json), and a
// sensitive variables endpoint still resolves to ci-variables (forced at distill
// time) when requested as variables.json — so the format suffix cannot dodge the
// secret-leak category.
func TestLookup_StripsFormatSuffix(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: ["Projects"]
  /api/v4/projects/{id}/variables:
    get:
      tags: ["Pipelines"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	r, ok := tbl.Lookup("GET", "/api/v4/projects.json")
	if !ok || r.Category != "projects" {
		t.Errorf("GET /api/v4/projects.json → %+v ok=%v, want category projects", r, ok)
	}
	// The format suffix must not let a sensitive read escape ci-variables.
	r, ok = tbl.Lookup("GET", "/api/v4/projects/1/variables.json")
	if !ok || r.Category != "ci-variables" {
		t.Errorf("GET /api/v4/projects/1/variables.json → %+v ok=%v, want ci-variables", r, ok)
	}
}

// sameSet reports whether got and want hold the same strings, order-insensitive.
func sameSet(got, want []string) bool {
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	return slices.Equal(g, w)
}

// TestExpandOptionalGroups exercises the Grape optional-route normalizer: optional
// "(...)" groups expand into both the present and absent forms (no "//"), escaped
// "\(\)" become LITERAL "()" (NOT optional), and a plain path is returned verbatim.
// It DISCRIMINATES: a normalizer that baked the markers literally would emit the raw
// "(-/)" / "\(\)" strings instead of the expected concrete forms.
func TestExpandOptionalGroups(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			"dash-slash group (epics)",
			"/api/v4/groups/{id}/(-/)epics",
			[]string{"/api/v4/groups/{id}/-/epics", "/api/v4/groups/{id}/epics"},
		},
		{
			"slash-param group (vscode settings sync)",
			"/api/v4/vscode/settings_sync(/{settings_context_hash})/v1/manifest",
			[]string{
				"/api/v4/vscode/settings_sync/{settings_context_hash}/v1/manifest",
				"/api/v4/vscode/settings_sync/v1/manifest",
			},
		},
		{
			"ref-param group (trigger pipeline)",
			"/api/v4/projects/{id}/(ref/{ref}/)trigger/pipeline",
			[]string{
				"/api/v4/projects/{id}/ref/{ref}/trigger/pipeline",
				"/api/v4/projects/{id}/trigger/pipeline",
			},
		},
		{
			"escaped parens are literal OData (nuget FindPackagesById)",
			`/api/v4/projects/{project_id}/packages/nuget/v2/FindPackagesById\(\)`,
			[]string{"/api/v4/projects/{project_id}/packages/nuget/v2/FindPackagesById()"},
		},
		{
			"escaped parens are literal OData (nuget Packages)",
			`/api/v4/projects/{project_id}/packages/nuget/v2/Packages\(\)`,
			[]string{"/api/v4/projects/{project_id}/packages/nuget/v2/Packages()"},
		},
		{
			"plain path is returned verbatim",
			"/api/v4/projects/{id}/issues",
			[]string{"/api/v4/projects/{id}/issues"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := expandOptionalGroups(c.in)
			if !sameSet(got, c.want) {
				t.Errorf("expandOptionalGroups(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestExpandOptionalGroups_multipleGroups verifies two optional groups in one path
// fan out to 2^2 = 4 concrete forms (a synthetic worst case; the real spec has ≤1
// group per path).
func TestExpandOptionalGroups_multipleGroups(t *testing.T) {
	t.Parallel()
	got := expandOptionalGroups("/api/v4/(-/)a/(-/)b")
	want := []string{
		"/api/v4/-/a/-/b",
		"/api/v4/-/a/b",
		"/api/v4/a/-/b",
		"/api/v4/a/b",
	}
	if !sameSet(got, want) {
		t.Errorf("expandOptionalGroups multi = %v, want %v", got, want)
	}
}

// TestExpandOptionalGroups_unbalanced verifies an unbalanced "(" is left verbatim
// (it won't split into a real endpoint → unclassifiable → denied; fail closed).
func TestExpandOptionalGroups_unbalanced(t *testing.T) {
	t.Parallel()
	got := expandOptionalGroups("/api/v4/(broken")
	if !sameSet(got, []string{"/api/v4/(broken"}) {
		t.Errorf("unbalanced ( = %v, want verbatim", got)
	}
}

// TestDistillOpenAPI_ExpandsOptionalGroup verifies a spec path with a Grape "(-/)"
// optional group registers BOTH concrete forms: GitLab serves /groups/{id}/epics
// AND /groups/{id}/-/epics, and both must classify to the operation's category.
// DISCRIMINATING: under literal splitting the "(-" / ")epics" segments match
// neither real request → both Lookups would fail.
func TestDistillOpenAPI_ExpandsOptionalGroup(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/groups/{id}/(-/)epics:
    get:
      tags: ["Epics"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	if r, ok := tbl.Lookup("GET", "/api/v4/groups/5/epics"); !ok || r.Category != "epics" {
		t.Errorf("bare form → %+v ok=%v, want epics", r, ok)
	}
	if r, ok := tbl.Lookup("GET", "/api/v4/groups/5/-/epics"); !ok || r.Category != "epics" {
		t.Errorf("dash form → %+v ok=%v, want epics", r, ok)
	}
}

// TestDistillOpenAPI_LiteralEscapedParens verifies the nuget OData "\(\)" path
// registers the LITERAL "()" form and a real request to it classifies (the parens
// are part of the path, not an optional group).
func TestDistillOpenAPI_LiteralEscapedParens(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/packages/nuget/v2/FindPackagesById\(\):
    get:
      tags: ["Nuget packages"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	// The path segment is the literal "FindPackagesById()".
	if r, ok := tbl.Lookup("GET", "/api/v4/projects/1/packages/nuget/v2/FindPackagesById()"); !ok ||
		r.Category != "nuget-packages" {
		t.Errorf("literal OData form → %+v ok=%v, want nuget-packages", r, ok)
	}
}

// TestDistillOpenAPI_OptionalGroupSpanningVariables verifies the distill-time
// ci-variables override still fires after optional-group expansion: a "variables"
// segment in the EXPANDED template is forced to ci-variables in both forms.
func TestDistillOpenAPI_OptionalGroupSpanningVariables(t *testing.T) {
	t.Parallel()
	raw := []byte(`
openapi: "3.0.0"
paths:
  /api/v4/groups/{id}/(-/)variables:
    get:
      tags: ["Groups"]
`)
	tbl, err := DistillOpenAPI(raw)
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	for _, p := range []string{"/api/v4/groups/5/variables", "/api/v4/groups/5/-/variables"} {
		if r, ok := tbl.Lookup("GET", p); !ok || r.Category != "ci-variables" {
			t.Errorf("variables override on %q → %+v ok=%v, want ci-variables", p, r, ok)
		}
	}
}
