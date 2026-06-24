package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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
	src := githubhardening.NewTableSource(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		fetch,
	)
	p := newGithubProvider("tok", exp, src)
	buf := &bytes.Buffer{}
	p.errOut = buf
	return p, buf
}

func okFetch(context.Context) ([]byte, error) { return []byte(provFixtureOpenAPI), nil }

func req(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), method, rawurl, nil)
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
			err := p.AuthorizeAction(context.Background(), req(t, c.method, c.url), nil)
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
	err := p.AuthorizeAction(context.Background(), req(t, "GET", "https://api.github.com/user"), nil)
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
			req, _ := http.NewRequestWithContext(
				context.Background(), method, "https://api.github.com/graphql", nil)
			err := p.AuthorizeAction(context.Background(), req, nil)
			if !errors.Is(err, githubhardening.ErrGraphQLUnsupported) {
				t.Fatalf("AuthorizeAction(%s /graphql) err = %v, want ErrGraphQLUnsupported", method, err)
			}
		})
	}
}

// TestGithubAuthorizeAction_GraphQLHostOverrideNotBypassed verifies that a /graphql
// request with a download-host Host: override is denied (GraphQL check precedes the
// download-host fast-path, so the override cannot slip it through).
func TestGithubAuthorizeAction_GraphQLHostOverrideNotBypassed(t *testing.T) {
	t.Parallel()
	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "https://api.github.com/graphql", nil)
	req.Host = "codeload.github.com"
	err := p.AuthorizeAction(context.Background(), req, nil)
	if !errors.Is(err, githubhardening.ErrGraphQLUnsupported) {
		t.Fatalf("AuthorizeAction(GET /graphql, Host=codeload) err = %v, want ErrGraphQLUnsupported", err)
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
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://api.github.com/%67raphql", nil)
	err := p.AuthorizeAction(context.Background(), req, nil)
	if !errors.Is(err, githubhardening.ErrUnclassifiable) {
		t.Fatalf("AuthorizeAction(POST /%%67raphql) err = %v, want ErrUnclassifiable (fail-closed)", err)
	}
}

func TestGithubProvider_notReadyWhenNoTable(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(),
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") })
	err := p.AuthorizeAction(context.Background(), req(t, "GET", "https://api.github.com/user"), nil)
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
	p.AuditResponse(req(t, "GET", "https://api.github.com/repos/o/r/issues/1"), h)
}

func TestGithubProvider_downloadHostGetOnly(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	if err := p.AuthorizeAction(
		context.Background(), req(t, "GET", "https://codeload.github.com/o/r/tarball/main"), nil,
	); err != nil {
		t.Errorf("download GET = %v, want nil", err)
	}
	if err := p.AuthorizeAction(
		context.Background(), req(t, "POST", "https://codeload.github.com/o/r/x"), nil,
	); err == nil {
		t.Error("download POST = nil, want denied")
	}
}

func TestGithubProvider_downloadHostViaOverride(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	// A Host override naming a download host pulls the request under the
	// GET/HEAD-only gate even though the URL host is api.github.com.
	r := req(t, "POST", "https://api.github.com/x")
	r.Host = "CODELOAD.GITHUB.COM:443"
	if err := p.AuthorizeAction(context.Background(), r, nil); !errors.Is(err, githubhardening.ErrExposureExceeded) {
		t.Errorf("override download host POST = %v, want ErrExposureExceeded", err)
	}

	// A Host override naming a download host for GET is allowed via the download branch.
	rGet := req(t, "GET", "https://api.github.com/o/r/tarball/main")
	rGet.Host = "codeload.github.com"
	if err := p.AuthorizeAction(context.Background(), rGet, nil); err != nil {
		t.Errorf("override download host GET = %v, want nil", err)
	}
}

// TestGithubProvider_downloadURLWithAPIHostOverride verifies that a codeload
// URL combined with a Host: api.github.com override does NOT take the download
// fast-path. The Host header is the effective served authority on GitHub's
// shared infrastructure, so the request falls through to classification. The
// codeload path is not an api.github.com route, so it returns an error.
func TestGithubProvider_downloadURLWithAPIHostOverride(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	r := req(t, "GET", "https://codeload.github.com/o/r/tarball/main")
	r.Host = "api.github.com"
	err := p.AuthorizeAction(context.Background(), r, nil)
	if err == nil {
		t.Fatal("codeload URL + Host: api.github.com GET = nil, want an error (unclassifiable as api route)")
	}
	// The codeload path does not match any api.github.com route template, so
	// classification fails closed with ErrUnclassifiable.
	if !errors.Is(err, githubhardening.ErrUnclassifiable) {
		t.Errorf("codeload URL + Host: api.github.com GET = %v, want ErrUnclassifiable", err)
	}
}

func TestGithubProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	for _, host := range []string{
		"api.github.com", "codeload.github.com",
		"release-assets.githubusercontent.com", "objects.githubusercontent.com",
	} {
		ok, err := p.AuthorizesHost(context.Background(), host, nil)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v, want true/nil", host, ok, err)
		}
	}
	for _, host := range []string{"evil.com", "githubusercontent.com", "x.objects.githubusercontent.com"} {
		ok, err := p.AuthorizesHost(context.Background(), host, nil)
		if err != nil || ok {
			t.Fatalf("%s: ok=%v err=%v, want false/nil", host, ok, err)
		}
	}
}

func TestGithubProvider_InjectAuth_stripsAPIVersion(t *testing.T) {
	t.Parallel()

	p, _ := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	r := req(t, "GET", "https://api.github.com/user")
	r.Header.Set("X-Github-Api-Version", "1999-01-01") // model-supplied — must be removed.
	if err := p.InjectAuth(r, nil); err != nil {
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
	// req.URL.Path decodes to "/repos/o/r/branches/feature/foo/protection" (too many segments),
	// but req.URL.EscapedPath() preserves "%2F" as one segment — matching the template.
	r := req(t, "GET", "https://api.github.com/repos/o/r/branches/feature%2Ffoo/protection")
	if err := p.AuthorizeAction(context.Background(), r, nil); err != nil {
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
	p.AuditResponse(req(t, "GET", "https://api.github.com/repos/o/r/issues/1"), h)
	if !strings.Contains(buf.String(), "github_hardening") {
		t.Errorf("expected drift warning, got %q", buf.String())
	}
}

func TestGithubProvider_AuditResponse_noop(t *testing.T) {
	t.Parallel()

	p, buf := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	// No header → nothing logged.
	p.AuditResponse(req(t, "GET", "https://api.github.com/user"), http.Header{})
	// Unrecognized method → RequiredLevel errors → nothing logged.
	bad := req(t, "GET", "https://api.github.com/user")
	bad.Method = "WAT"
	withHdr := http.Header{}
	withHdr.Set("X-Accepted-Github-Permissions", "issues=write")
	p.AuditResponse(bad, withHdr)
	if buf.Len() != 0 {
		t.Errorf("expected no audit output, got %q", buf.String())
	}
}

// plainProvider implements Provider but NOT ResponseAuditor, to exercise the
// dispatcher's "found but no audit capability" branch.
type plainProvider struct{}

func (plainProvider) Name() string                                    { return "plain" }
func (plainProvider) Description() string                             { return "" }
func (plainProvider) InjectAuth(*http.Request, json.RawMessage) error { return nil }
func (plainProvider) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return true, nil
}

func TestAuditResponse_dispatcher(t *testing.T) {
	t.Parallel()

	r := req(t, "GET", "https://api.github.com/repos/o/r/issues/1")
	// Unknown provider name → silent no-op (find returns an error).
	AuditResponse("nonexistent", r, http.Header{}, nil)
	// Found but not a ResponseAuditor → silent no-op (assertion fails).
	AuditResponse("plain", r, http.Header{}, []Provider{plainProvider{}})

	// Found AND a ResponseAuditor → the audit runs (drift warning emitted).
	gh, buf := testGithubProvider(t, githubhardening.BaselineExposure(), okFetch)
	h := http.Header{}
	h.Set("X-Accepted-Github-Permissions", "issues=write")
	AuditResponse("github", r, h, []Provider{gh})
	if !strings.Contains(buf.String(), "github_hardening") {
		t.Errorf("dispatcher must run the auditor, got %q", buf.String())
	}
}
