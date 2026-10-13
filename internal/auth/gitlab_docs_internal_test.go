package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/auth/openapidoc"
	"github.com/cynative/cynative/internal/cache"
)

func TestGitLabRefusedInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		loc  apiref.Location
		name string
		want bool
	}{
		{apiref.LocationQuery, "sudo", true},
		{apiref.LocationQuery, "SUDO", true},
		{apiref.LocationQuery, "token", true},
		{apiref.LocationQuery, "token[]", true},
		{apiref.LocationQuery, "private_token", true},
		{apiref.LocationQuery, "Feed_Token", true},
		{apiref.LocationQuery, "rss_token[x]", true},
		{apiref.LocationQuery, "page", false},
		{apiref.LocationHeader, "Sudo", true},
		{apiref.LocationHeader, "sudo", true},
		{apiref.LocationHeader, "Private-Token", true},
		{apiref.LocationHeader, "Private_Token", true},
		{apiref.LocationHeader, "job-token", true},
		{apiref.LocationHeader, "Cookie", true},
		{apiref.LocationHeader, "Authorization", true},
		{apiref.LocationHeader, "X-Request-Id", false},
		{apiref.LocationBody, "token", true},
		{apiref.LocationBody, "JOB_TOKEN", true},
		{apiref.LocationBody, "access_token[]", true},
		{apiref.LocationBody, "title", false},
		{apiref.LocationPath, "token", false},
	}
	for _, tc := range cases {
		if got := gitlabRefusedInput(tc.loc, tc.name); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.loc, tc.name, got, tc.want)
		}
	}
}

// TestGitLabRefusedInput_CoversEveryListedName ties the docs-side check to the gate's lists: a name added to a
// list is refused in the docs with no second edit.
func TestGitLabRefusedInput_CoversEveryListedName(t *testing.T) {
	t.Parallel()
	for _, h := range credentialHeaders {
		if !gitlabRefusedInput(apiref.LocationHeader, h) {
			t.Errorf("header %q not refused", h)
		}
	}
	for _, p := range credentialParams {
		if !gitlabRefusedInput(apiref.LocationQuery, p) {
			t.Errorf("query %q not refused", p)
		}
	}
	for _, p := range gitlabBodyCredentialParams {
		if !gitlabRefusedInput(apiref.LocationBody, p) {
			t.Errorf("body %q not refused", p)
		}
	}
}

func TestGitLabAuthorizeAction_MarksOnlyTheTableMiss(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, method, url string
		marked            bool
	}{
		{"route not in the table", http.MethodGet, "https://gitlab.com/api/v4/nope/route", true},
		{"ceiling", http.MethodGet, "https://gitlab.com/api/v4/projects/1/variables", false},
		{"write over the read ceiling", http.MethodPost, "https://gitlab.com/api/v4/projects", false},
		{"dot segment", http.MethodGet, "https://gitlab.com/api/v4/projects/1/./issues", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newTestGitLab(t, "gitlab.com")
			err := p.AuthorizeAction(t.Context(), actionView(t, tc.method, tc.url), noArgs())
			if err == nil {
				t.Fatal("want a denial")
			}
			if _, marked := errors.AsType[*authreq.UnmatchedRequestError](err); marked != tc.marked {
				t.Errorf("marked = %v, want %v (err %v)", marked, tc.marked, err)
			}
		})
	}
}

// gitlabDocsFixture is a GitLab OpenAPI excerpt with operation IDs, for the provider's docs cache.
const gitlabDocsFixture = `openapi: 3.0.0
info:
  version: '19.5'
paths:
  /api/v4/projects/{id}:
    get:
      tags: [Projects]
      operationId: getApiV4ProjectsId
      parameters:
      - {in: path, name: id, required: true, schema: {oneOf: [{type: string}, {type: integer}]}}
  /api/v4/projects/{id}/issues:
    get:
      tags: [Issues]
      operationId: getApiV4ProjectsIdIssues
      parameters:
      - {in: path, name: id, required: true, schema: {oneOf: [{type: string}, {type: integer}]}}
      - {in: query, name: sudo, schema: {type: string}}
      - {in: header, name: Private_Token, schema: {type: string}}
  /api/v4/runners:
    delete:
      tags: [Runners]
      operationId: deleteApiV4Runners
      parameters:
      - {in: query, name: token, required: true, schema: {type: string}}
`

func newGitLabDocsCache(
	dir string, fetch func(context.Context) ([]byte, error),
) *cache.TTLCache[openapidoc.OperationDocs] {
	return cache.NewNamedCache(cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now}, "docs", fetch,
		gitlabclass.DistillDocs, (*openapidoc.OperationDocs).Serialize, openapidoc.Unmarshal, openapidoc.Admit)
}

func okGitLabDocsFetch(context.Context) ([]byte, error) { return []byte(gitlabDocsFixture), nil }

// newDocsOnlyGitLab builds a provider whose only working seam is the docs cache: the token source fails the test
// when touched, and a nil table cache or resolver would panic if anything loaded them.
func newDocsOnlyGitLab(
	t *testing.T,
	host, apiHost string,
	fetch func(context.Context) ([]byte, error),
) *gitlabProvider {
	t.Helper()
	p := &gitlabProvider{
		tokenSource: &tokenSourceMock{TokenFunc: func() (*oauth2.Token, error) {
			t.Error("token source touched")

			return nil, errors.New("touched")
		}},
		host:    host,
		apiHost: apiHost,
		egress:  NoProxy(),
	}
	p.docs.cache = newGitLabDocsCache(t.TempDir(), fetch)

	return p
}

func TestGitLabProvider_ReferenceEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct{ host, apiHost, want string }{
		{"gitlab.com", "", "https://gitlab.com"},
		{"gitlab.example", "api.gitlab.example:8443", "https://api.gitlab.example:8443"},
		{"[2001:db8::1]:8443", "", "https://[2001:db8::1]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			p := newDocsOnlyGitLab(t, tc.host, tc.apiHost, okGitLabDocsFetch)
			res := p.Reference(t.Context(), apiref.Query{Connector: "gitlab", Operation: "getApiV4ProjectsId"})
			if res.Outcome != apiref.OutcomeFound || res.Reference.Endpoint != tc.want {
				t.Errorf("res = %+v", res)
			}
		})
	}
}

func TestGitLabProvider_ReferenceRefusesCredentialInputs(t *testing.T) {
	t.Parallel()
	p := newDocsOnlyGitLab(t, "gitlab.com", "", okGitLabDocsFetch)
	res := p.Reference(t.Context(), apiref.Query{Operation: "deleteApiV4Runners"})
	want := []string{"required input token is a credential the gitlab connector refuses"}
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, want) ||
		len(res.Reference.Inputs) != 0 {
		t.Errorf("res = %+v", res)
	}
	issues := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdIssues"})
	if issues.Outcome != apiref.OutcomeFound || len(issues.Reference.Inputs) != 1 ||
		issues.Reference.Inputs[0].Name != "id" {
		t.Errorf("optional sudo and Private_Token must be dropped: %+v", issues)
	}
}

func TestGitLabProvider_ReferenceUnavailable(t *testing.T) {
	t.Parallel()
	const reason = "GitLab OpenAPI documentation could not be loaded"
	bare := &gitlabProvider{host: "gitlab.com"}
	failing := newDocsOnlyGitLab(t, "gitlab.com", "", errGitLabFetch)
	for name, p := range map[string]*gitlabProvider{"no docs wired": bare, "fetch fails": failing} {
		res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsId"})
		if res.Outcome != apiref.OutcomeUnavailable || res.Reason != reason {
			t.Errorf("%s: res = %+v", name, res)
		}
		if h := p.Hint(
			t.Context(),
			authreq.View{Method: "GET", EscapedPath: "/api/v4/x"},
			nil,
		); len(
			h.Candidates,
		) != 0 {
			t.Errorf("%s: hint = %+v", name, h)
		}
	}
}

func TestGitLabProvider_HintTriesAFailingDocsLoadOnce(t *testing.T) {
	t.Parallel()
	var fetches atomic.Int32
	p := newDocsOnlyGitLab(t, "gitlab.com", "", func(context.Context) ([]byte, error) {
		fetches.Add(1)

		return nil, errors.New("offline")
	})
	v := authreq.View{Method: "GET", EscapedPath: "/api/v4/projects/team/app/issues"}
	p.Hint(t.Context(), v, nil)
	p.Hint(t.Context(), v, nil)
	if n := fetches.Load(); n != 1 {
		t.Errorf("two hints fetched %d times, want 1", n)
	}
}

func TestGitLabExplainUnmatched_NamespaceHint(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	p.docs.cache = newGitLabDocsCache(t.TempDir(), okGitLabDocsFetch)
	v := actionView(t, http.MethodGet, "https://gitlab.com/api/v4/projects/team/app/issues")
	err := p.AuthorizeAction(t.Context(), v, noArgs())
	got := ExplainUnmatched(t.Context(), "gitlab", v, []Provider{p}, err).Error()
	want := `gitlab_hardening: cannot classify request as read or write: GET /api/v4/projects/team/app/issues. ` +
		`GET "/api/v4/projects/team/app/issues" on gitlab matched no operation in the cached API metadata. The gate ` +
		`stopped before attaching credentials or sending anything; this says nothing about the principal's ` +
		`permissions. Check the request shape against the operation reference. Candidates: getApiV4ProjectsIdIssues ` +
		`(GET /api/v4/projects/{id}/issues). If "team/app" is the namespace path, send it as one segment: ` +
		`"team%2Fapp". For an operation's request template call api_reference with ` +
		`{"connector":"gitlab","operation":"getApiV4ProjectsIdIssues"}.`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if !errors.Is(err, gitlabclass.ErrUnclassifiable) {
		t.Errorf("gate error lost its identity: %v", err)
	}
}
