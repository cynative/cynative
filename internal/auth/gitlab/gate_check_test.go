package gitlab_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// gateMasterFixture is the gate's master document for these tests. Its routes differ from docsFixture, which
// stands for a release here: it has the project and merge-request reads and nothing else.
const gateMasterFixture = `openapi: 3.0.0
paths:
  /api/v4/projects/{id}:
    get:
      tags: [Projects]
  /api/v4/projects/{id}/merge_requests:
    get:
      tags: [Merge requests]
`

const (
	gateDenies = "the gitlab gate (which uses the latest GitLab spec) does not recognize this path, so requests " +
		"to it are denied"
	gateNotChecked = "gate recognition not checked: the gitlab gate's table is not loaded yet"
	bakedGap       = "rendered path is not admitted by the gitlab gate"
)

func gateMasterTable(t *testing.T) *gitlab.Table {
	t.Helper()
	table, err := gitlab.DistillOpenAPI([]byte(gateMasterFixture))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func releaseFixtureDocs(t *testing.T) *openapidoc.OperationDocs {
	t.Helper()
	d, err := gitlab.DistillReleaseDocs([]byte(docsFixture))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func releaseLookup(t *testing.T, op string) apiref.Result {
	t.Helper()
	return gitlab.ReleaseReference(releaseFixtureDocs(t), apiref.Query{Operation: op}, testEndpoint, nil)
}

func TestRecognizes(t *testing.T) {
	t.Parallel()
	table := gateMasterTable(t)
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/api/v4/projects/{id}", true},
		{http.MethodHead, "/api/v4/projects/{id}", true},
		{http.MethodGet, "/api/v4/projects/{id}/merge_requests", true},
		{http.MethodPost, "/api/v4/projects/{id}/merge_requests", false},
		{http.MethodGet, "/api/v4/projects/{id}/issues", false},
		{"BREW", "/api/v4/projects/{id}", false},
	}
	for _, tc := range cases {
		if got := gitlab.Recognizes(table, tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s: got %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestReleaseReference_Limitations pins the release profile: no master caveat, the edition and the gate's
// document named instead.
func TestReleaseReference_Limitations(t *testing.T) {
	t.Parallel()
	res := releaseLookup(t, "getApiV4ProjectsId")
	want := []string{
		"the document is GitLab's Enterprise Edition file, so it lists EE-only operations a Community Edition " +
			"instance does not serve",
		"the gitlab gate classifies requests against GitLab's latest (master) document, not this release's",
	}
	if res.Outcome != apiref.OutcomeFound || !slices.Equal(res.Reference.Limitations, want) ||
		res.Reference.Endpoint != testEndpoint {
		t.Errorf("res = %+v", res)
	}
	if miss := releaseLookup(t, "projects/getApiV4ProjectsId"); miss.Outcome != apiref.OutcomeNotFound ||
		miss.Reason != `no operation "projects/getApiV4ProjectsId" in gitlab; GitLab operation names carry no `+
			`prefix: did you mean "getApiV4ProjectsId"?` {
		t.Errorf("miss = %+v", miss)
	}
}

func TestCheckGate(t *testing.T) {
	t.Parallel()
	table := gateMasterTable(t)
	t.Run("table not loaded", func(t *testing.T) {
		t.Parallel()
		res := gitlab.CheckGate(releaseLookup(t, "getApiV4ProjectsIdIssues"), nil)
		ref := res.Reference
		if res.Outcome != apiref.OutcomeFound || len(ref.Gaps) != 0 || ref.Limitations[len(ref.Limitations)-1] !=
			gateNotChecked {
			t.Errorf("res = %+v", res)
		}
	})
	t.Run("a path the table classifies", func(t *testing.T) {
		t.Parallel()
		before := releaseLookup(t, "getApiV4ProjectsIdMergeRequests")
		res := gitlab.CheckGate(releaseLookup(t, "getApiV4ProjectsIdMergeRequests"), table)
		if res.Outcome != apiref.OutcomeFound || len(res.Reference.Gaps) != 0 ||
			!slices.Equal(res.Reference.Limitations, before.Reference.Limitations) {
			t.Errorf("res = %+v", res)
		}
	})
	t.Run("a path the table does not classify", func(t *testing.T) {
		t.Parallel()
		res := gitlab.CheckGate(releaseLookup(t, "getApiV4ProjectsIdIssues"), table)
		if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, []string{gateDenies}) {
			t.Errorf("res = %+v", res)
		}
	})
	t.Run("a gap master's docs already record", func(t *testing.T) {
		t.Parallel()
		master := lookup(t, "getApiV4SwaggerDoc")
		res := gitlab.CheckGate(master, table)
		if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, []string{bakedGap}) {
			t.Errorf("res = %+v", res)
		}
	})
	t.Run("no reference", func(t *testing.T) {
		t.Parallel()
		miss := releaseLookup(t, "nope")
		if res := gitlab.CheckGate(miss, table); res.Outcome != apiref.OutcomeNotFound || res.Reference != nil ||
			res.Reason != miss.Reason {
			t.Errorf("res = %+v", res)
		}
	})
}

// TestCheckGate_LeavesTheDocsAlone pins that the verdict lands on the returned reference only: a second lookup in
// the same docs sees none of it.
func TestCheckGate_LeavesTheDocsAlone(t *testing.T) {
	t.Parallel()
	d := releaseFixtureDocs(t)
	q := apiref.Query{Operation: "getApiV4ProjectsIdIssues"}
	gitlab.CheckGate(gitlab.ReleaseReference(d, q, testEndpoint, nil), gateMasterTable(t))
	gitlab.CheckGate(gitlab.ReleaseReference(d, q, testEndpoint, nil), nil)
	if gaps := d.Ops["getApiV4ProjectsIdIssues"].Gaps; len(gaps) != 0 {
		t.Errorf("docs gaps = %q", gaps)
	}
	again := gitlab.ReleaseReference(d, q, testEndpoint, nil)
	if len(again.Reference.Gaps) != 0 || slices.Contains(again.Reference.Limitations, gateNotChecked) {
		t.Errorf("again = %+v", again)
	}
}

func TestRecognizedHint(t *testing.T) {
	t.Parallel()
	table := gateMasterTable(t)
	d := releaseFixtureDocs(t)
	hint := func(method, path string) apiref.Hint {
		return gitlab.RecognizedHint(d, authreq.View{Method: method, EscapedPath: path}, table)
	}
	got := hint(http.MethodDelete, "/api/v4/projects/1/merge_requests")
	if !slices.Equal(got.Candidates, []string{
		"getApiV4ProjectsIdMergeRequests (GET /api/v4/projects/{id}/merge_requests)",
	}) || got.Operation != "getApiV4ProjectsIdMergeRequests" {
		t.Errorf("merge requests hint = %+v", got)
	}
	// Unfiltered, the namespace rule would suggest the issues read, which the gate's table lacks.
	if unfiltered := gitlab.Hint(d, authreq.View{
		Method: http.MethodGet, EscapedPath: "/api/v4/projects/team/app/issues",
	}); unfiltered.Operation != "getApiV4ProjectsIdIssues" {
		t.Fatalf("unfiltered = %+v", unfiltered)
	}
	// Filtered, the fold reaches the project read instead, the one route under {id} the table classifies.
	got = hint(http.MethodGet, "/api/v4/projects/team/app/issues")
	if !slices.Equal(got.Candidates, []string{"getApiV4ProjectsId (GET /api/v4/projects/{id})"}) ||
		got.Operation != "getApiV4ProjectsId" {
		t.Errorf("issues hint = %+v", got)
	}
}
