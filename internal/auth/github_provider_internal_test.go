package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/exposure"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	"github.com/cynative/cynative/internal/cache"
)

const provFixtureOpenAPI = `{"paths":{
	"/user": {"get": {"x-github": {"category":"users","subcategory":"users"}}},
	"/repos/{owner}/{repo}/issues": {"post": {"x-github": {"category":"issues","subcategory":"issues"}}},
	"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}},
	"/repos/{owner}/{repo}/branches/{branch}/protection": {"get": {"x-github": {"category":"repos","subcategory":"branches"}}}
}}`

func testGithubProvider(
	t *testing.T, exp exposure.Exposure, fetch func(context.Context) ([]byte, error),
) (*githubProvider, *bytes.Buffer) {
	t.Helper()
	src := cache.NewTableCache(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		fetch,
		githubhardening.DistillOpenAPI, (*githubhardening.Table).Serialize,
		githubhardening.UnmarshalTable, githubhardening.AdmitTable,
	)
	p := newGithubProvider("tok", exp, src)
	buf := &bytes.Buffer{}
	p.errOut = buf
	return p, buf
}

func okFetch(context.Context) ([]byte, error) { return []byte(provFixtureOpenAPI), nil }

// getReq builds a GET request for the paths that still need a live request
// (InjectAuth, and AuditResponse's view projection); the action gate takes a
// view instead.
func getReq(t *testing.T, rawurl string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawurl, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return r
}

func TestGithubProvider_AuthorizeAction(t *testing.T) {
	t.Parallel()

	base := githubhardening.BaselineExposure()
	cases := []struct {
		name     string
		exposure exposure.Exposure
		method   string
		url      string
		wantErr  error
	}{
		{"read allowed by default", base, "GET", "https://api.github.com/user", nil},
		{
			"write blocked by default", base, "POST",
			"https://api.github.com/repos/o/r/issues", githubhardening.ErrExposureExceeded,
		},
		{
			"write allowed when issues:write",
			exposure.MergeExposure(base, exposure.Exposure{"issues": exposure.LevelWrite}),
			"POST", "https://api.github.com/repos/o/r/issues", nil,
		},
		{
			"secret-scanning denied by default", base, "GET",
			"https://api.github.com/repos/o/r/secret-scanning/alerts", githubhardening.ErrExposureExceeded,
		},
		{"unknown route fails closed", base, "GET", "https://api.github.com/nope", githubhardening.ErrUnclassifiable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p, _ := testGithubProvider(t, c.exposure, okFetch)
			err := p.AuthorizeAction(context.Background(), actionView(t, c.method, c.url), noArgs())
			if c.wantErr == nil && err != nil {
				t.Fatalf("AuthorizeAction = %v, want nil", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("AuthorizeAction = %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestGithubProvider_AuthorizeAction_unknownKeyFatal(t *testing.T) {
	t.Parallel()

	// A typo'd narrowing key under default:write must be fatal (fail closed).
	exp := exposure.MergeExposure(
		githubhardening.BaselineExposure(),
		exposure.Exposure{"default": exposure.LevelWrite, "issuez": exposure.LevelNone},
	)
	p, _ := testGithubProvider(t, exp, okFetch)
	err := p.AuthorizeAction(context.Background(), actionView(t, "GET", "https://api.github.com/user"), noArgs())
	if !errors.Is(err, githubhardening.ErrUnknownKey) {
		t.Fatalf("AuthorizeAction = %v, want ErrUnknownKey", err)
	}
}

func TestGithubAuthorizeAction_DeniesGraphQL(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
			err := p.AuthorizeAction(
				context.Background(), actionView(t, method, "https://api.github.com/graphql"), noArgs(),
			)
			if !errors.Is(err, githubhardening.ErrGraphQLUnsupported) {
				t.Fatalf("AuthorizeAction(%s /graphql) err = %v, want ErrGraphQLUnsupported", method, err)
			}
		})
	}
}

// TestGithubAuthorizeAction_EncodedGraphQLFailsClosed documents that a
// percent-encoded GraphQL probe does not bypass the deny. GitHub routes only the
// literal /graphql, so IsGraphQLEndpoint is an exact match; an encoded form
// (/%67raphql) falls through to REST classification and fails closed as an
// unknown route — denied before any credential is attached.
func TestGithubAuthorizeAction_EncodedGraphQLFailsClosed(t *testing.T) {
	t.Parallel()
	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	err := p.AuthorizeAction(
		context.Background(), actionView(t, http.MethodPost, "https://api.github.com/%67raphql"), noArgs(),
	)
	if !errors.Is(err, githubhardening.ErrUnclassifiable) {
		t.Fatalf("AuthorizeAction(POST /%%67raphql) err = %v, want ErrUnclassifiable (fail-closed)", err)
	}
}

func TestGithubProvider_notReadyWhenNoTable(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(),
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") })
	err := p.AuthorizeAction(context.Background(), actionView(t, "GET", "https://api.github.com/user"), noArgs())
	if !errors.Is(err, githubhardening.ErrTableNotReady) {
		t.Fatalf("AuthorizeAction = %v, want ErrTableNotReady", err)
	}
}

// TestGithubProvider_AuditResponse_nilErrOut asserts that emitting a drift warning
// with a nil errOut does not panic ([io.Discard] is substituted instead).
func TestGithubProvider_AuditResponse_nilErrOut(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	p.errOut = nil // nil writer — out() must substitute io.Discard, no panic.
	h := http.Header{}
	h.Set("X-Accepted-Github-Permissions", "issues=write") // GET classified read but GitHub wants write → drift.
	p.AuditResponse(authreq.NewAuditView(getReq(t, "https://api.github.com/repos/o/r/issues/1")), h)
}

func TestGithubProvider_downloadHostGetOnly(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	if err := p.AuthorizeAction(
		context.Background(), actionView(t, "GET", "https://codeload.github.com/o/r/tarball/main"), noArgs(),
	); err != nil {
		t.Errorf("download GET = %v, want nil", err)
	}
	// The view lower-cases the hostname at projection, so a mixed-case authority
	// still matches the download-host set.
	if err := p.AuthorizeAction(
		context.Background(), actionView(t, "GET", "https://CODELOAD.GitHub.com/o/r/tarball/main"), noArgs(),
	); err != nil {
		t.Errorf("download GET (upper-case host) = %v, want nil", err)
	}
	if err := p.AuthorizeAction(
		context.Background(), actionView(t, "POST", "https://codeload.github.com/o/r/x"), noArgs(),
	); !errors.Is(err, githubhardening.ErrExposureExceeded) {
		t.Errorf("download POST = %v, want ErrExposureExceeded", err)
	}
}

// TestGithubAuthorizeAction_GraphQLDeniedOnDownloadHost pins the ordering of the
// GraphQL check and the download-host fast path. IsGraphQLEndpoint matches on the
// path only, so if the download branch ran first a /graphql request to a download
// host would take the table-free GET fast path and return nil with the token
// attached.
func TestGithubAuthorizeAction_GraphQLDeniedOnDownloadHost(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	err := p.AuthorizeAction(
		context.Background(), actionView(t, "GET", "https://codeload.github.com/graphql"), noArgs(),
	)
	if !errors.Is(err, githubhardening.ErrGraphQLUnsupported) {
		t.Fatalf("AuthorizeAction(GET codeload /graphql) err = %v, want ErrGraphQLUnsupported", err)
	}
}

func TestGithubProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	for _, host := range []string{
		"api.github.com", "codeload.github.com",
		"release-assets.githubusercontent.com", "objects.githubusercontent.com",
	} {
		ok, err := p.AuthorizesHost(context.Background(), host, noArgs())
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v, want true/nil", host, ok, err)
		}
	}
	for _, host := range []string{"evil.com", "githubusercontent.com", "x.objects.githubusercontent.com"} {
		ok, err := p.AuthorizesHost(context.Background(), host, noArgs())
		if err != nil || ok {
			t.Fatalf("%s: ok=%v err=%v, want false/nil", host, ok, err)
		}
	}
}

func TestGithubProvider_InjectAuth_stripsAPIVersion(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	r := getReq(t, "https://api.github.com/user")
	r.Header.Set("X-Github-Api-Version", "1999-01-01") // model-supplied — must be removed.
	if err := p.InjectAuth(r, noArgs()); err != nil {
		t.Fatalf("InjectAuth: %v", err)
	}
	// Header must be absent: stripping lets GitHub use its current default version,
	// which the live-fetched OpenAPI spec (main branch) describes — keeping the
	// table and wire behaviour aligned without pinning a constant.
	if got := r.Header.Get("X-Github-Api-Version"); got != "" {
		t.Errorf("X-Github-Api-Version = %q, want empty (stripped)", got)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("authorization = %q", got)
	}
}

// TestGithubProvider_AuthorizeAction_escapedPath verifies that a branch name
// containing an encoded slash (%2F) in the URL is treated as a single path
// segment and classifies correctly — not ErrUnclassifiable.
func TestGithubProvider_AuthorizeAction_escapedPath(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	// A URL with %2F in the branch segment: GET /repos/o/r/branches/feature%2Ffoo/protection.
	// The view's Path decodes to "/repos/o/r/branches/feature/foo/protection" (too many
	// segments), but its EscapedPath preserves "%2F" as one segment, matching the template.
	v := actionView(t, "GET", "https://api.github.com/repos/o/r/branches/feature%2Ffoo/protection")
	if err := p.AuthorizeAction(context.Background(), v, noArgs()); err != nil {
		t.Fatalf("AuthorizeAction with %%2F branch = %v, want nil (read allowed)", err)
	}
}

func TestGithubProvider_Description(t *testing.T) {
	t.Parallel()

	desc := newGithubProvider("tok", githubhardening.BaselineExposure(), nil).Description()
	if !strings.Contains(desc, "GitHub") {
		t.Errorf("description must mention GitHub, got %q", desc)
	}
	if !strings.Contains(desc, "permissions") {
		t.Errorf("description must mention the permissions ceiling, got %q", desc)
	}
}

func TestGithubProvider_AuditResponse_drift(t *testing.T) {
	t.Parallel()

	p, buf := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	h := http.Header{}
	h.Set("X-Accepted-Github-Permissions", "issues=write") // GET classified read but GitHub wants write.
	p.AuditResponse(authreq.NewAuditView(getReq(t, "https://api.github.com/repos/o/r/issues/1")), h)
	if !strings.Contains(buf.String(), "github_hardening") {
		t.Errorf("expected drift warning, got %q", buf.String())
	}
}

func TestGithubProvider_AuditResponse_noop(t *testing.T) {
	t.Parallel()

	p, buf := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	// No header → nothing logged.
	p.AuditResponse(authreq.NewAuditView(getReq(t, "https://api.github.com/user")), http.Header{})
	// Unrecognized method → RequiredLevel errors → nothing logged.
	bad := getReq(t, "https://api.github.com/user")
	bad.Method = "WAT"
	withHdr := http.Header{}
	withHdr.Set("X-Accepted-Github-Permissions", "issues=write")
	p.AuditResponse(authreq.NewAuditView(bad), withHdr)
	if buf.Len() != 0 {
		t.Errorf("expected no audit output, got %q", buf.String())
	}
}

// plainProvider implements Provider but NOT ResponseAuditor, to exercise the
// dispatcher's "found but no audit capability" branch.
type plainProvider struct{}

func (plainProvider) Name() string                                         { return "plain" }
func (plainProvider) Description() string                                  { return "" }
func (plainProvider) InjectAuth(*http.Request, authreq.ProviderArgs) error { return nil }
func (plainProvider) AuthorizesHost(context.Context, string, authreq.ProviderArgs) (bool, error) {
	return true, nil
}

func TestAuditResponse_dispatcher(t *testing.T) {
	t.Parallel()

	v := authreq.NewAuditView(getReq(t, "https://api.github.com/repos/o/r/issues/1"))
	// Unknown provider name → silent no-op (find returns an error).
	AuditResponse("nonexistent", v, http.Header{}, nil)
	// Found but not a ResponseAuditor → silent no-op (assertion fails).
	AuditResponse("plain", v, http.Header{}, []Provider{plainProvider{}})

	// Found AND a ResponseAuditor → the audit runs (drift warning emitted).
	gh, buf := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	h := http.Header{}
	h.Set("X-Accepted-Github-Permissions", "issues=write")
	AuditResponse("github", v, h, []Provider{gh})
	if !strings.Contains(buf.String(), "github_hardening") {
		t.Errorf("dispatcher must run the auditor, got %q", buf.String())
	}
}

const shadowProvFixtureOpenAPI = `{"components":{"parameters":{
	"branch":{"name":"branch","x-multi-segment":true},"ref":{"name":"ref","x-multi-segment":true}}},"paths":{
	"/repos/{owner}/{repo}/branches/{branch}": {"get": {"x-github": {"category":"branches","subcategory":"branches"}}},
	"/repos/{owner}/{repo}/branches/{branch}/protection": {"get": {"x-github": {"category":"branches","subcategory":"branch-protection"}}},
	"/repos/{owner}/{repo}/commits/{ref}": {"get": {"x-github": {"category":"commits","subcategory":"commits"}}},
	"/repos/{owner}/{repo}/commits/{ref}/check-runs": {"get": {"x-github": {"category":"checks","subcategory":"runs"}}},
	"/repos/{owner}/{repo}/commits/{ref}/secret-scanning": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}},
	"/user/codespaces/secrets/{secret_name}": {"get": {"x-github": {"category":"codespaces","subcategory":"secrets"}}},
	"/user/codespaces/{codespace_name}/machines": {"get": {"x-github": {"category":"codespaces","subcategory":"machines"}}}
}}`

func shadowFetch(context.Context) ([]byte, error) { return []byte(shadowProvFixtureOpenAPI), nil }

func TestGithubProvider_AuthorizeAction_EveryRouteCeiling(t *testing.T) {
	t.Parallel()

	base := githubhardening.BaselineExposure()
	with := func(key string) exposure.Exposure {
		return exposure.MergeExposure(base, exposure.Exposure{key: exposure.LevelNone})
	}
	const api = "https://api.github.com"
	cases := []struct {
		name     string
		exposure exposure.Exposure
		path     string
		allowed  bool
	}{
		{"protection denied", with("branches/branch-protection"), "/repos/o/r/branches/main/protection", false},
		{
			"protection denied, slashed branch", with("branches/branch-protection"),
			"/repos/o/r/branches/feat/x/protection", false,
		},
		{"branch read still allowed", with("branches/branch-protection"), "/repos/o/r/branches/feat/x", true},
		{
			"protection allowed when branches denied", with("branches/branches"),
			"/repos/o/r/branches/feat/x/protection", true,
		},
		{"branch denied when branches denied", with("branches/branches"), "/repos/o/r/branches/main", false},
		{"check runs denied", with("checks"), "/repos/o/r/commits/main/check-runs", false},
		{"check runs denied, one trailing slash", with("checks"), "/repos/o/r/commits/main/check-runs/", false},
		{"two trailing slashes are a commit", with("checks"), "/repos/o/r/commits/main/check-runs//", true},
		{"commit allowed", with("checks"), "/repos/o/r/commits/main", true},
		{"shadowed secret scanning denied", base, "/repos/o/r/commits/main/secret-scanning", false},
		{"tie denied by the first route", with("codespaces/secrets"), "/user/codespaces/secrets/machines", false},
		{"tie denied by the second route", with("codespaces/machines"), "/user/codespaces/secrets/machines", false},
		{"tie allowed when both allow", base, "/user/codespaces/secrets/machines", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p, _ := testGithubProvider(t, c.exposure, shadowFetch)
			err := p.AuthorizeAction(context.Background(), actionView(t, http.MethodGet, api+c.path), noArgs())
			if c.allowed && err != nil {
				t.Fatalf("AuthorizeAction = %v, want nil", err)
			}
			if !c.allowed && !errors.Is(err, githubhardening.ErrExposureExceeded) {
				t.Fatalf("AuthorizeAction = %v, want ErrExposureExceeded", err)
			}
		})
	}
}

func TestGithubProvider_AuthorizeAction_ShadowedDenialText(t *testing.T) {
	t.Parallel()

	exp := exposure.MergeExposure(githubhardening.BaselineExposure(),
		exposure.Exposure{"branches/branch-protection": exposure.LevelNone})
	p, _ := testGithubProvider(t, exp, shadowFetch)
	err := p.AuthorizeAction(context.Background(),
		actionView(t, http.MethodGet, "https://api.github.com/repos/o/r/branches/main/protection"), noArgs())
	want := `github_hardening: request exceeds configured exposure: ` +
		`GET /repos/o/r/branches/main/protection needs read on "branches" (ceiling none)`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestGithubProvider_AuthorizeAction_DotSegmentsDenied(t *testing.T) {
	t.Parallel()

	const api = "https://api.github.com"
	paths := []string{
		"/repos/o/r/branches/x/../../../../../repos/o/r/secret-scanning/alerts",
		"/repos/o/r/branches/x/%2e%2e/%2E%2e/%2e%2e/%2e%2e/%2e%2e/repos/o/r/secret-scanning/alerts",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), shadowFetch)
			err := p.AuthorizeAction(context.Background(), actionView(t, http.MethodGet, api+path), noArgs())
			if !errors.Is(err, githubhardening.ErrUnclassifiable) {
				t.Fatalf("AuthorizeAction = %v, want ErrUnclassifiable", err)
			}
		})
	}
}
