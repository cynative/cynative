package gitlab_test

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/gitlab"
)

func hintFor(t *testing.T, method, escapedPath string) apiref.Hint {
	t.Helper()
	v := authreq.View{Method: method, Hostname: "gitlab.com", Path: escapedPath, EscapedPath: escapedPath}
	return gitlab.Hint(docsFixtureDocs(t), v)
}

func TestHint_SharedRules(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		method, path string
		want         []string
		op           string
	}{
		"wrong method, one operation": {
			http.MethodDelete, "/api/v4/projects/1",
			[]string{"getApiV4ProjectsId (GET /api/v4/projects/{id})"},
			"getApiV4ProjectsId",
		},
		"wrong method, two operations": {
			http.MethodDelete, "/api/v4/projects/1/merge_requests",
			[]string{
				"getApiV4ProjectsIdMergeRequests (GET /api/v4/projects/{id}/merge_requests)",
				"postApiV4ProjectsIdMergeRequests (POST /api/v4/projects/{id}/merge_requests)",
			},
			"",
		},
		// The Grape absent form is a route too.
		"wrong method, absent Grape form": {
			http.MethodDelete, "/api/v4/groups/7/epics",
			[]string{"getApiV4GroupsIdDashEpics (GET /api/v4/groups/{id}/epics)"},
			"getApiV4GroupsIdDashEpics",
		},
		// A near miss wins before the namespace rule runs: "b" is one edit from "-".
		"near miss on the present Grape form": {
			http.MethodGet, "/api/v4/groups/a/b/epics",
			[]string{"getApiV4GroupsIdDashEpics (GET /api/v4/groups/{id}/-/epics)"},
			"getApiV4GroupsIdDashEpics",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := hintFor(t, tc.method, tc.path)
			if !slices.Equal(h.Candidates, tc.want) || h.Operation != tc.op || h.Note != "" {
				t.Errorf("hint = %+v", h)
			}
		})
	}
}

func TestHint_NamespaceRule(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		method, path, line, op, note string
	}{
		// Folding all three segments would match the project lookup; the smallest fold keeps the endpoint.
		"merge requests": {
			http.MethodGet, "/api/v4/projects/team/app/merge_requests",
			"getApiV4ProjectsIdMergeRequests (GET /api/v4/projects/{id}/merge_requests)",
			"getApiV4ProjectsIdMergeRequests",
			`If "team/app" is the namespace path, send it as one segment: "team%2Fapp".`,
		},
		"HEAD reads as GET": {
			http.MethodHead, "/api/v4/projects/team/app/merge_requests",
			"getApiV4ProjectsIdMergeRequests (GET /api/v4/projects/{id}/merge_requests)",
			"getApiV4ProjectsIdMergeRequests",
			`If "team/app" is the namespace path, send it as one segment: "team%2Fapp".`,
		},
		"bare project": {
			http.MethodGet, "/api/v4/projects/team/app",
			"getApiV4ProjectsId (GET /api/v4/projects/{id})", "getApiV4ProjectsId",
			`If "team/app" is the namespace path, send it as one segment: "team%2Fapp".`,
		},
		// The limitation: an endpoint the docs do not know folds into the namespace.
		"unknown suffix": {
			http.MethodGet, "/api/v4/projects/team/app/unknown",
			"getApiV4ProjectsId (GET /api/v4/projects/{id})", "getApiV4ProjectsId",
			`If "team/app/unknown" is the namespace path, send it as one segment: "team%2Fapp%2Funknown".`,
		},
		"group, present Grape form": {
			http.MethodGet, "/api/v4/groups/a/b/-/epics",
			"getApiV4GroupsIdDashEpics (GET /api/v4/groups/{id}/-/epics)", "getApiV4GroupsIdDashEpics",
			`If "a/b" is the namespace path, send it as one segment: "a%2Fb".`,
		},
		"group, absent Grape form": {
			http.MethodGet, "/api/v4/groups/team/sub/epics",
			"getApiV4GroupsIdDashEpics (GET /api/v4/groups/{id}/epics)", "getApiV4GroupsIdDashEpics",
			`If "team/sub" is the namespace path, send it as one segment: "team%2Fsub".`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := hintFor(t, tc.method, tc.path)
			if !slices.Equal(h.Candidates, []string{tc.line}) || h.Operation != tc.op || h.Note != tc.note {
				t.Errorf("hint = %+v", h)
			}
		})
	}
}

func TestHint_NamespaceRuleSuggestsNothing(t *testing.T) {
	t.Parallel()
	cases := map[string][2]string{
		// At the smallest fold both badges/{badge_id} and badges/render match.
		"two operations at the smallest fold": {http.MethodGet, "/api/v4/projects/a/b/badges/render"},
		"not under projects or groups":        {http.MethodGet, "/api/v4/users/a/b"},
		"one segment after projects":          {http.MethodGet, "/api/v4/projects/nope"},
		// No PATCH operation sits under /projects/{id}, so no fold matches.
		"no operation at any fold": {http.MethodPatch, "/api/v4/projects/a/b/c"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if h := hintFor(t, tc[0], tc[1]); len(h.Candidates) != 0 || h.Operation != "" || h.Note != "" {
				t.Errorf("hint = %+v", h)
			}
		})
	}
}

func TestHint_OverLongPathGetsNothing(t *testing.T) {
	t.Parallel()
	ns := strings.Repeat("n", 2000)
	if h := hintFor(t, http.MethodGet, "/api/v4/projects/"+ns+"/app/merge_requests"); h.Operation == "" {
		t.Fatalf("a path under the bound folds: %+v", h)
	}
	long := strings.Repeat("n", 2100)
	if h := hintFor(t, http.MethodGet, "/api/v4/projects/"+long+"/app/merge_requests"); len(h.Candidates) != 0 ||
		h.Operation != "" || h.Note != "" {
		t.Errorf("hint = %+v", h)
	}
}

func TestHint_NoteEchoIsBounded(t *testing.T) {
	t.Parallel()
	ns := strings.Repeat("n", 300)
	h := hintFor(t, http.MethodGet, "/api/v4/projects/"+ns+"/app/merge_requests")
	if strings.Contains(h.Note, strings.Repeat("n", apiref.MaxPathEcho)) || !strings.Contains(h.Note, `..."`) ||
		h.Operation != "getApiV4ProjectsIdMergeRequests" {
		t.Errorf("hint = %+v", h)
	}
}

// TestHint_NamespaceFoldIsCapped pins the fold at the deepest namespace GitLab allows: 22 segments fold, and 23
// would only fold an endpoint into the namespace.
func TestHint_NamespaceFoldIsCapped(t *testing.T) {
	t.Parallel()
	namespace := func(n int) string {
		segs := make([]string, 0, n)
		for i := range n {
			segs = append(segs, "g"+strconv.Itoa(i))
		}
		return strings.Join(segs, "/")
	}
	h := hintFor(t, http.MethodGet, "/api/v4/projects/"+namespace(22)+"/merge_requests")
	if h.Operation != "getApiV4ProjectsIdMergeRequests" {
		t.Errorf("22 segments: hint = %+v", h)
	}
	h = hintFor(t, http.MethodGet, "/api/v4/projects/"+namespace(23)+"/merge_requests")
	if len(h.Candidates) != 0 || h.Operation != "" || h.Note != "" {
		t.Errorf("23 segments: hint = %+v", h)
	}
}
