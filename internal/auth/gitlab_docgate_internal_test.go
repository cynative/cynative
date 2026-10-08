package auth

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

const (
	gitlabGateDenies = "the gitlab gate (which uses the latest GitLab spec) does not recognize this path, so " +
		"requests to it are denied"
	gitlabGateNotChecked = "gate recognition not checked: the gitlab gate's table is not loaded yet"
)

// newReleaseGitLab builds a provider that reads the release fixture as v18.11.0-ee, with the gate's master table
// cache over tableFetch, which it counts.
func newReleaseGitLab(
	t *testing.T, tableFetch func(context.Context) ([]byte, error), tableLoads *atomic.Int32,
) *gitlabProvider {
	t.Helper()
	var refs []string
	p := newVersionedGitLab(t, t.TempDir(), time.Now, releaseDocsFetch(new(atomic.Int32)), &refs)
	p.tables = newTestGitLabSource(t, func(ctx context.Context) ([]byte, error) {
		tableLoads.Add(1)

		return tableFetch(ctx)
	})
	p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})

	return p
}

const releaseStatement = "documentation read from gitlab-org/gitlab at ref v18.11.0-ee; the instance reports " +
	"GitLab 18.11.0-ee"

// The per-call check runs against the gate's live table: before any request (the lookup must not load the
// table), after the table loads, and after its load failed.
const gitlabReleaseOnlyOp, gitlabSharedOp = "getApiV4ProjectsIdReleaseOnly", "getApiV4ProjectsIdIssues"

func TestGitLabReference_GateNotCheckedBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	p := newReleaseGitLab(t, okGitLabFetch, &loads)
	for _, op := range []string{gitlabReleaseOnlyOp, gitlabSharedOp} {
		res := p.Reference(t.Context(), apiref.Query{Operation: op})
		if res.Outcome != apiref.OutcomeFound || len(res.Reference.Gaps) != 0 ||
			!slices.Contains(res.Reference.Limitations, gitlabGateNotChecked) {
			t.Errorf("%s: res = %+v", op, res)
		}
	}
	if n := loads.Load(); n != 0 {
		t.Errorf("api_reference loaded the gate's table %d times", n)
	}
}

func TestGitLabReference_GateCheckedAfterTheTableLoads(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	p := newReleaseGitLab(t, okGitLabFetch, &loads)
	// The provider has no exposure ceiling, so the request is denied; it still loads the table.
	_ = p.AuthorizeAction(t.Context(), actionView(t, http.MethodGet,
		"https://gitlab.example/api/v4/projects/1/issues"), noArgs())
	if p.tables.Peek() == nil {
		t.Fatal("the request did not load the table")
	}
	res := p.Reference(t.Context(), apiref.Query{Operation: gitlabReleaseOnlyOp})
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, []string{gitlabGateDenies}) ||
		slices.Contains(res.Reference.Limitations, gitlabGateNotChecked) {
		t.Errorf("release-only: res = %+v", res)
	}
	res = p.Reference(t.Context(), apiref.Query{Operation: gitlabSharedOp})
	if res.Outcome != apiref.OutcomeFound || len(res.Reference.Gaps) != 0 ||
		slices.Contains(res.Reference.Limitations, gitlabGateNotChecked) {
		t.Errorf("shared: res = %+v", res)
	}
}

func TestGitLabReference_GateNotCheckedAfterTheTableFailed(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	p := newReleaseGitLab(t, errGitLabFetch, &loads)
	if err := p.AuthorizeAction(t.Context(), actionView(t, http.MethodGet,
		"https://gitlab.example/api/v4/projects/1/issues"), noArgs()); err == nil {
		t.Fatal("want a denial with no table")
	}
	res := p.Reference(t.Context(), apiref.Query{Operation: gitlabReleaseOnlyOp})
	if res.Outcome != apiref.OutcomeFound || !slices.Contains(res.Reference.Limitations, gitlabGateNotChecked) {
		t.Errorf("res = %+v", res)
	}
	if loads.Load() == 0 {
		t.Error("the table load was never attempted")
	}
}

// TestGitLabReference_GateVerdictIsNeverCached pins that the verdict stays out of the cached docs, in memory and
// on disk.
func TestGitLabReference_GateVerdictIsNeverCached(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	p := newReleaseGitLab(t, okGitLabFetch, &loads)
	p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdReleaseOnly"})
	if p.tables.Get(t.Context()) == nil {
		t.Fatal("table did not load")
	}
	p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdReleaseOnly"})
	if gaps := p.release.cache.Peek().Ops["getApiV4ProjectsIdReleaseOnly"].Gaps; len(gaps) != 0 {
		t.Errorf("cached gaps = %q", gaps)
	}
	raw, err := os.ReadFile(p.release.cache.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); strings.Contains(s, "gate") || strings.Contains(s, "denied") {
		t.Errorf("docs on disk carry a gate verdict: %s", s)
	}
}

// TestGitLabReference_StatesRefAndVersion pins the limitation naming the document's ref and the instance's version.
func TestGitLabReference_StatesRefAndVersion(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	release := newReleaseGitLab(t, okGitLabFetch, &loads)
	master := newDocsOnlyGitLab(t, "gitlab.com", "", okGitLabDocsFetch)
	master.useDocs(gitlabDocsChoice{version: "19.5.0-pre"})
	unread := newDocsOnlyGitLab(t, "gitlab.com", "", okGitLabDocsFetch)
	cases := []struct {
		name string
		p    *gitlabProvider
		op   string
		want string
	}{
		{"release", release, "getApiV4ProjectsIdIssues", releaseStatement},
		{
			"master", master, "getApiV4ProjectsId",
			"documentation read from gitlab-org/gitlab at ref master; the instance reports GitLab 19.5.0-pre",
		},
		{
			"version not read", unread, "getApiV4ProjectsId",
			"documentation read from gitlab-org/gitlab at ref master; the instance's version was not read",
		},
	}
	for _, tc := range cases {
		res := tc.p.Reference(t.Context(), apiref.Query{Operation: tc.op})
		if res.Reference == nil || !slices.Contains(res.Reference.Limitations, tc.want) {
			t.Errorf("%s: res = %+v", tc.name, res)
		}
	}
	if !slices.Contains(newReleaseGitLab(t, okGitLabFetch, &loads).Reference(t.Context(),
		apiref.Query{Operation: "getApiV4ProjectsIdIssues"}).Reference.Limitations,
		"the gitlab gate classifies requests against GitLab's latest (master) document, not this release's") {
		t.Error("the release profile is not used")
	}
}

// TestGitLabHint_SkipsWhatTheGateDenies pins the hint filter: a near miss of an operation the gate's table cannot
// classify is not suggested, one it can is, and with no table loaded nothing is.
func TestGitLabHint_SkipsWhatTheGateDenies(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	p := newReleaseGitLab(t, okGitLabFetch, &loads)
	view := func(path string) authreq.View { return authreq.View{Method: http.MethodGet, EscapedPath: path} }
	if h := p.Hint(t.Context(), view("/api/v4/projects/1/issue"), nil); len(h.Candidates) != 0 {
		t.Errorf("hint before the table loaded = %+v", h)
	}
	if p.tables.Get(t.Context()) == nil {
		t.Fatal("table did not load")
	}
	if h := p.Hint(t.Context(), view("/api/v4/projects/1/release_onl"), nil); len(h.Candidates) != 0 {
		t.Errorf("release-only hint = %+v", h)
	}
	h := p.Hint(t.Context(), view("/api/v4/projects/1/issue"), nil)
	if !slices.Equal(h.Candidates, []string{"getApiV4ProjectsIdIssues (GET /api/v4/projects/{id}/issues)"}) {
		t.Errorf("issues hint = %+v", h)
	}
}
