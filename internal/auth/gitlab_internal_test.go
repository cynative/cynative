package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/auth/exposure"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/cache"

	"golang.org/x/oauth2"
)

// gitlabFixtureOpenAPI is a minimal GitLab OpenAPI v3 (YAML) spec covering the
// routes the provider tests exercise. ci-variables uses the "CI variables" tag so
// AdmitTable accepts the variables-segment route (the scatter allow-set).
const gitlabFixtureOpenAPI = `openapi: "3.0.0"
paths:
  /api/v4/user:
    get:
      tags: ["Users"]
  /api/v4/projects:
    get:
      tags: ["Projects"]
    post:
      tags: ["Projects"]
  /api/v4/projects/{id}:
    delete:
      tags: ["Projects"]
    put:
      tags: ["Projects"]
    patch:
      tags: ["Projects"]
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
    post:
      tags: ["Issues"]
  /api/v4/projects/{id}/variables:
    get:
      tags: ["CI variables"]
  /api/v4/projects/{id}/trigger/pipeline:
    post:
      tags: ["Pipeline triggers"]
  /api/v4/projects/{id}/repository/files/{path}:
    post:
      tags: ["Repository files"]
  /api/v4/markdown:
    post:
      tags: ["Markdown"]
`

// okGitLabFetch returns the fixture spec as the table source bytes.
func okGitLabFetch(context.Context) ([]byte, error) { return []byte(gitlabFixtureOpenAPI), nil }

// errGitLabFetch always errors, so the TableSource resolves to nil (fail-closed).
func errGitLabFetch(context.Context) ([]byte, error) { return nil, errors.New("fetch failed") }

// newTestGitLabSource builds a TableSource over fetch with a temp cache dir.
func newTestGitLabSource(t *testing.T, fetch func(context.Context) ([]byte, error)) *gitlabclass.TableSource {
	t.Helper()
	return gitlabclass.NewTableSource(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		fetch,
	)
}

// newTestGitLab builds a bare provider with the baseline exposure and a working
// table source, plus a static token and a public-IP resolver.
func newTestGitLab(t *testing.T, host string) *gitlabProvider {
	t.Helper()
	return newTestGitLabExposure(t, host, gitlabclass.BaselineExposure(), okGitLabFetch)
}

// newTestGitLabExposure builds a provider with the given exposure ceiling and a
// table source over fetch.
func newTestGitLabExposure(
	t *testing.T, host string, exp exposure.Exposure, fetch func(context.Context) ([]byte, error),
) *gitlabProvider {
	t.Helper()
	return &gitlabProvider{ //nolint:exhaustruct // test provider.
		tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), //nolint:exhaustruct // access only.
		host:        host,
		exposure:    exp,
		tables:      newTestGitLabSource(t, fetch),
		resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
}

func TestGitLabProvider_NameAndInjectAuth(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	if p.Name() != "gitlab" {
		t.Fatalf("Name = %q", p.Name())
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/user", nil)
	if err := p.InjectAuth(req, nil); err != nil {
		t.Fatalf("InjectAuth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestGitLabProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.example.com")
	p.apiHost = "api.gitlab.example.com"
	ok, _ := p.AuthorizesHost(context.Background(), "api.gitlab.example.com", nil)
	if !ok {
		t.Fatal("served (api) host should be allowed")
	}
	denied, _ := p.AuthorizesHost(context.Background(), "evil.com", nil)
	if denied {
		t.Fatal("foreign host must be denied")
	}
}

// TestGitLabProvider_AuthorizeAction_Exposure exercises the per-category exposure
// ceiling: reads pass by default, writes are blocked by default, a per-category
// write override permits the matching write, and ci-variables reads are blocked.
func TestGitLabProvider_AuthorizeAction_Exposure(t *testing.T) {
	t.Parallel()
	base := gitlabclass.BaselineExposure()
	cases := []struct {
		name     string
		exposure exposure.Exposure
		method   string
		url      string
		wantErr  error
	}{
		{"read allowed by default", base, http.MethodGet, "https://gitlab.com/api/v4/projects", nil},
		{
			"write blocked by default", base, http.MethodPost,
			"https://gitlab.com/api/v4/projects", gitlabclass.ErrExposureExceeded,
		},
		{
			"write allowed when projects:write",
			exposure.MergeExposure(base, exposure.Exposure{"projects": exposure.LevelWrite}),
			http.MethodPost, "https://gitlab.com/api/v4/projects", nil,
		},
		{
			"delete allowed when default:write",
			exposure.MergeExposure(base, exposure.Exposure{"default": exposure.LevelWrite}),
			http.MethodDelete, "https://gitlab.com/api/v4/projects/1", nil,
		},
		{
			"ci-variables read blocked by default", base, http.MethodGet,
			"https://gitlab.com/api/v4/projects/1/variables", gitlabclass.ErrExposureExceeded,
		},
		{
			"unknown route fails closed", base, http.MethodGet,
			"https://gitlab.com/api/v4/nope/route", gitlabclass.ErrUnclassifiable,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := newTestGitLabExposure(t, "gitlab.com", c.exposure, okGitLabFetch)
			req, _ := http.NewRequestWithContext(context.Background(), c.method, c.url, nil)
			err := p.AuthorizeAction(context.Background(), req, nil)
			if c.wantErr == nil && err != nil {
				t.Fatalf("AuthorizeAction = %v, want nil", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("AuthorizeAction = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// bypassFixtureOpenAPI exercises the distill-time variables override: a
// repository-files PUT template (its file_path parameter can be any value,
// including the literal "variables") and a real ci-variables POST template. The
// override keys off the trusted spec template, so the repository-files template
// keeps its genuine category even when the request's file_path value is
// "variables".
const bypassFixtureOpenAPI = `openapi: "3.0.0"
paths:
  /api/v4/projects/{id}/repository/files/{file_path}:
    put:
      tags: ["Repository files"]
  /api/v4/projects/{id}/variables:
    post:
      tags: ["CI variables"]
`

// okBypassFetch returns the bypass fixture spec as the table source bytes.
func okBypassFetch(context.Context) ([]byte, error) { return []byte(bypassFixtureOpenAPI), nil }

// TestAuthorizeAction_VariablesParamValueNoBypass is the regression test for the
// fail-open exposure bypass: with ci-variables OPENED to write but the default at
// read, a repository-files PUT whose file_path value is literally "variables" must
// still be DENIED (its true category is repository-files, under default:read) —
// the "variables" path-PARAMETER value must NOT grant the ci-variables write
// ceiling. Under the old request-time SensitiveCategory override this PUT would
// have been ALLOWED (forced to ci-variables → write). A genuine CI-variable write
// (POST /variables) stays ALLOWED.
func TestAuthorizeAction_VariablesParamValueNoBypass(t *testing.T) {
	t.Parallel()
	exp := exposure.MergeExposure(
		gitlabclass.BaselineExposure(),
		exposure.Exposure{"ci-variables": exposure.LevelWrite},
	)
	p := newTestGitLabExposure(t, "gitlab.com", exp, okBypassFetch)

	// (a) The file literally named "variables" must NOT inherit the ci-variables
	// write ceiling: its true category is repository-files under default:read.
	putReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPut,
		"https://gitlab.com/api/v4/projects/1/repository/files/variables", nil)
	if err := p.AuthorizeAction(context.Background(), putReq, nil); !errors.Is(err, gitlabclass.ErrExposureExceeded) {
		t.Fatalf("PUT repository-files/variables must be denied with ErrExposureExceeded (no bypass), got %v", err)
	}

	// (b) A real CI-variable write is allowed under ci-variables:write.
	postReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://gitlab.com/api/v4/projects/1/variables", nil)
	if err := p.AuthorizeAction(context.Background(), postReq, nil); err != nil {
		t.Fatalf("POST projects/1/variables (real ci-variable write) must be allowed, got %v", err)
	}
}

// TestAuthorizeAction_NilTableDenies asserts that when the table source cannot be
// resolved (fetch always errors → Get returns nil) even a benign GET is denied
// with ErrTableNotReady (fail closed).
func TestAuthorizeAction_NilTableDenies(t *testing.T) {
	t.Parallel()
	p := newTestGitLabExposure(t, "gitlab.com", gitlabclass.BaselineExposure(), errGitLabFetch)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/projects", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); !errors.Is(err, gitlabclass.ErrTableNotReady) {
		t.Fatalf("nil table must deny with ErrTableNotReady, got %v", err)
	}
}

// TestGitLabProvider_AuthorizeAction_UnknownKeyFatal asserts a configured key that
// matches no real GitLab category fails closed (fatal) — under default:write a
// typo'd narrowing key would otherwise silently over-grant.
func TestGitLabProvider_AuthorizeAction_UnknownKeyFatal(t *testing.T) {
	t.Parallel()
	exp := exposure.MergeExposure(
		gitlabclass.BaselineExposure(),
		exposure.Exposure{"default": exposure.LevelWrite, "projectz": exposure.LevelNone},
	)
	p := newTestGitLabExposure(t, "gitlab.com", exp, okGitLabFetch)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/projects", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); !errors.Is(err, gitlabclass.ErrUnknownKey) {
		t.Fatalf("AuthorizeAction = %v, want ErrUnknownKey", err)
	}
}

func TestGitLabProvider_AuthorizesAddr_DefaultDeniesInternal(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com") // allowPrivateNetwork=false.
	ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.5"), nil)
	if err != nil || ok {
		t.Fatalf("internal IP must be denied by default: ok=%v err=%v", ok, err)
	}
}

func TestGitLabProvider_AuthorizesAddr_PrivateOptInPins(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.internal")
	p.allowPrivateNetwork = true
	p.resolver = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.5"), nil)
	if err != nil || !ok {
		t.Fatalf("pinned private IP should be allowed with opt-in: ok=%v err=%v", ok, err)
	}
	// Floor (metadata) always denied even with opt-in.
	metaDenied, _ := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("169.254.169.254"), nil)
	if metaDenied {
		t.Fatal("link-local metadata must always be denied")
	}
}

func TestGitLabProvider_CACertData(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	p.caData = "BASE64PEM"
	got, err := p.CACertData(context.Background(), nil)
	if err != nil || got != "BASE64PEM" {
		t.Fatalf("CACertData = %q, %v", got, err)
	}
}

// TestGitLabProvider_AuthorizeAction_GraphQLDenied guards that a POST to
// /api/graphql is denied regardless of the rawArgs body.
func TestGitLabProvider_AuthorizeAction_GraphQLDenied(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	args, _ := json.Marshal(map[string]string{"body": `{"query":"mutation { x }"}`})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://gitlab.com/api/graphql", strings.NewReader(""))
	if err := p.AuthorizeAction(context.Background(), req, args); !errors.Is(err, gitlabclass.ErrGraphQLUnsupported) {
		t.Fatalf("graphql request must be denied with ErrGraphQLUnsupported, got %v", err)
	}
}

// TestGitLabProvider_Description asserts the Description names the served host and
// the exposure model.
func TestGitLabProvider_Description(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		t.Parallel()
		p := newTestGitLab(t, "gitlab.com")
		desc := p.Description()
		for _, want := range []string{"connectors.gitlab.permissions", "read-only by default", "https://gitlab.com"} {
			if !strings.Contains(desc, want) {
				t.Errorf("description missing %q: %s", want, desc)
			}
		}
	})

	t.Run("self-managed host surfaced", func(t *testing.T) {
		t.Parallel()
		p := newTestGitLab(t, "gitlab.com")
		p.apiHost = "gitlab.internal:8443"
		if desc := p.Description(); !strings.Contains(desc, "https://gitlab.internal:8443") {
			t.Errorf("description must name the served (api) host: %s", desc)
		}
	})
}

// TestGitLabProvider_AuthorizesAddr_ResolverError asserts that a resolver error
// is returned as an error (not just false).
func TestGitLabProvider_AuthorizesAddr_ResolverError(t *testing.T) {
	t.Parallel()
	resolveErr := errors.New("dns failed")
	p := newTestGitLab(t, "gitlab.com")
	p.allowPrivateNetwork = true // skip internal-range deny so we reach the resolver.
	p.resolver = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return nil, resolveErr
	}
	// Use a public IP that passes the floor check.
	ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("93.184.216.34"), nil)
	if ok || err == nil {
		t.Fatalf("resolver error must return (false, err): ok=%v err=%v", ok, err)
	}
}

// TestGitLabProvider_AuthorizesAddr_PinMiss asserts that when allowPrivateNetwork
// is true and the resolver returns a different IP than the dialed one, the result
// is (false, nil).
func TestGitLabProvider_AuthorizesAddr_PinMiss(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.internal")
	p.allowPrivateNetwork = true
	// Resolver returns 10.0.0.5; we dial 10.0.0.6 — pin miss.
	p.resolver = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.6"), nil)
	if ok || err != nil {
		t.Fatalf("pin miss must return (false, nil): ok=%v err=%v", ok, err)
	}
}

// TestGitLabProvider_AuthorizeAction_EncodedSlashNoMarkdownBypass asserts that a
// repository-files write whose percent-encoded path decodes to end with
// "/api/v4/markdown" is still blocked (AuthorizeAction classifies on EscapedPath,
// not the decoded req.URL.Path) — closing the read-only bypass.
func TestGitLabProvider_AuthorizeAction_EncodedSlashNoMarkdownBypass(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://gitlab.com/api/v4/projects/1/repository/files/x%2Fapi%2Fv4%2Fmarkdown", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); err == nil {
		t.Fatal("encoded-slash write must be blocked, not classified as the markdown read")
	}
}

// TestGitLabProvider_AuthorizeAction_GraphQLGetDenied asserts a GET to
// /api/graphql is denied — GraphQL is not supported in any HTTP method.
func TestGitLabProvider_AuthorizeAction_GraphQLGetDenied(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/graphql?query=mutation%20%7B%20x%20%7D", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); !errors.Is(err, gitlabclass.ErrGraphQLUnsupported) {
		t.Fatalf("graphql GET must be denied with ErrGraphQLUnsupported, got %v", err)
	}
}

func TestRejectGitLabSmuggledControls(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		url     string
		sudoHdr string
		want    error // nil = not blocked.
	}{
		{"clean", "https://gitlab.com/api/v4/user", "", nil},
		{"sudo query", "https://gitlab.com/api/v4/projects?sudo=alice", "", errGitLabSudoBlocked},
		{"sudo query uppercase", "https://gitlab.com/api/v4/projects?SUDO=alice", "", errGitLabSudoBlocked},
		{"sudo header", "https://gitlab.com/api/v4/user", "alice", errGitLabSudoBlocked},
		{"token query", "https://gitlab.com/api/v4/projects?token=abc", "", ErrModelSuppliedCredential},
		{"token query uppercase", "https://gitlab.com/api/v4/projects?TOKEN=abc", "", ErrModelSuppliedCredential},
		// ";" is rejected by url.ParseQuery but honored by GitLab/Rack — fail closed.
		{"semicolon query", "https://gitlab.com/api/v4/projects?sudo=alice;x=1", "", ErrModelSuppliedCredential},
		// Rack bracket form expands to the base param.
		{"token bracket query", "https://gitlab.com/api/v4/projects?token[]=abc", "", ErrModelSuppliedCredential},
		{"sudo bracket query", "https://gitlab.com/api/v4/projects?sudo[]=alice", "", errGitLabSudoBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c.url, nil)
			if c.sudoHdr != "" {
				req.Header.Set("Sudo", c.sudoHdr)
			}
			err := rejectGitLabSmuggledControls(req)
			if c.want == nil {
				if err != nil {
					t.Fatalf("%q: unexpected err %v", c.name, err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("%q: err = %v, want %v", c.name, err, c.want)
			}
		})
	}
}

// TestGitLabProvider_AuthorizeAction_SudoRejected asserts sudo impersonation is
// blocked — even when the exposure ceiling would permit the request (the check
// precedes classification).
func TestGitLabProvider_AuthorizeAction_SudoRejected(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/projects?sudo=alice", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); !errors.Is(err, errGitLabSudoBlocked) {
		t.Fatalf("sudo must be rejected, got %v", err)
	}
}

// TestGitLabProvider_AuthorizeAction_BadRawArgs exercises the [json.Unmarshal]
// error branch in AuthorizeAction (invalid JSON in rawArgs).
func TestGitLabProvider_AuthorizeAction_BadRawArgs(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/projects", nil)
	// Pass invalid JSON as rawArgs to trigger the unmarshal error branch.
	err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{bad json`))
	if err == nil {
		t.Fatal("invalid rawArgs must return error")
	}
}

// TestGitLabProvider_AuthorizeAction_UnclassifiableMethod exercises the
// classifier returning an error (unknown HTTP method) in AuthorizeAction.
func TestGitLabProvider_AuthorizeAction_UnclassifiableMethod(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	// FROBNICATE is not a recognized HTTP method; classifier returns ErrUnclassifiable.
	req, _ := http.NewRequestWithContext(context.Background(), "FROBNICATE",
		"https://gitlab.com/api/v4/projects", nil)
	err := p.AuthorizeAction(context.Background(), req, nil)
	if err == nil {
		t.Fatal("unclassifiable method must return error")
	}
}

// TestRejectGitLabBodyCredential exercises the body credential guard across every
// encoding GitLab reads into params: urlencoded (incl. the ';'-separated form Rack
// honors but [url.ParseQuery] rejects), multipart/form-data, and a JSON object — for
// each of the GitLab credential parameter names (token, private_token,
// access_token, job_token). Clean bodies in each encoding are allowed.
func TestRejectGitLabBodyCredential(t *testing.T) {
	t.Parallel()
	const multipartToken = "--X\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nsecret\r\n--X--\r\n"
	const multipartPrivate = "--X\r\nContent-Disposition: form-data; name=\"private_token\"\r\n\r\ns\r\n--X--\r\n"
	const multipartClean = "--X\r\nContent-Disposition: form-data; name=\"ref\"\r\n\r\nmain\r\n--X--\r\n"
	// Folded (RFC822 continuation) Content-Disposition: the name= is on a wrapped line.
	const multipartFolded = "--X\r\nContent-Disposition: form-data;\r\n name=\"token\"\r\n\r\nsecret\r\n--X--\r\n"
	cases := []struct {
		name    string
		body    string
		blocked bool
	}{
		{"empty", "", false},
		{"form token", "token=abc&ref=main", true},
		{"form token uppercase", "TOKEN=abc", true},
		{"form private_token", "private_token=abc", true},
		{"form access_token", "access_token=abc", true},
		{"form job_token", "job_token=abc", true},
		{"form bracket private_token", "private_token[]=abc", true}, // Rack bracket form.
		{"form token semicolon", "ref=main;token=abc", true},        // Rack-style ';' separator.
		{"clean form", "ref=main&variables[FOO]=bar", false},
		{"bare semicolon non-token", "a;b=c", false},
		{"json token", `{"ref":"main","token":"abc"}`, true},
		{"json private_token", `{"private_token":"abc"}`, true},
		{"json job_token uppercase", `{"Job_Token":"abc"}`, true},
		{"json clean", `{"ref":"main"}`, false},
		{"json graphql mutation", `{"query":"mutation { createIssue { id } }"}`, false},
		{"json array", `[{"query":"q"}]`, false},
		{"multipart token", multipartToken, true},
		{"multipart private_token", multipartPrivate, true},
		{"multipart folded token", multipartFolded, true},
		{"multipart clean", multipartClean, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := rejectGitLabBodyCredential(c.body)
			if c.blocked {
				if !errors.Is(err, ErrModelSuppliedCredential) {
					t.Fatalf("%q: err = %v, want ErrModelSuppliedCredential", c.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: unexpected err %v", c.name, err)
			}
		})
	}
}

// TestGitLabProvider_AuthorizeAction_PortEnforcement asserts the injected Bearer
// is only attached to the configured (or default-443) port: a model targeting a
// different TLS port on the pinned host is rejected, closing the co-located-service
// credential-leak gap that host-only pinning leaves open.
func TestGitLabProvider_AuthorizeAction_PortEnforcement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		host    string
		url     string
		blocked bool
	}{
		{"configured port match", "gitlab.internal:8443", "https://gitlab.internal:8443/api/v4/projects", false},
		{"configured port mismatch", "gitlab.internal:8443", "https://gitlab.internal:4443/api/v4/projects", true},
		{"configured port vs default", "gitlab.internal:8443", "https://gitlab.internal/api/v4/projects", true},
		{"default host no port", "gitlab.com", "https://gitlab.com/api/v4/projects", false},
		{"default host explicit 443", "gitlab.com", "https://gitlab.com:443/api/v4/projects", false},
		{"default host nonstandard port", "gitlab.com", "https://gitlab.com:8443/api/v4/projects", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := newTestGitLab(t, c.host)
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c.url, nil)
			err := p.AuthorizeAction(context.Background(), req, nil)
			if c.blocked {
				if !errors.Is(err, ErrHostNotAuthorized) {
					t.Fatalf("%q: want ErrHostNotAuthorized, got %v", c.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: unexpected err %v", c.name, err)
			}
		})
	}
}

// TestGitLabProvider_AuthorizeAction_HostOverridePort asserts a model-supplied Host
// header override whose port differs from the configured port is rejected, even
// when the request URL port matches (the transport pins only the override's
// hostname).
func TestGitLabProvider_AuthorizeAction_HostOverridePort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		hostHeader string
		blocked    bool
	}{
		{"override matches", "gitlab.internal:8443", false},
		{"override port mismatch", "gitlab.internal:4443", true},
		{"override default-port mismatch", "gitlab.internal", true},
		{"no override", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := newTestGitLab(t, "gitlab.internal:8443")
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://gitlab.internal:8443/api/v4/projects", nil)
			if c.hostHeader != "" {
				req.Host = c.hostHeader
			}
			err := p.AuthorizeAction(context.Background(), req, nil)
			if c.blocked {
				if !errors.Is(err, ErrHostNotAuthorized) {
					t.Fatalf("%q: want ErrHostNotAuthorized, got %v", c.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: unexpected err %v", c.name, err)
			}
		})
	}
}

// TestGitLabProvider_AuthorizeAction_BodyTriggerToken asserts a smuggled pipeline
// trigger token in the request body is rejected regardless of the exposure ceiling
// (the guard precedes classification).
func TestGitLabProvider_AuthorizeAction_BodyTriggerToken(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://gitlab.com/api/v4/projects/1/trigger/pipeline", nil)
	rawArgs := json.RawMessage(`{"body":"token=secret&ref=main"}`)
	err := p.AuthorizeAction(context.Background(), req, rawArgs)
	if !errors.Is(err, ErrModelSuppliedCredential) {
		t.Fatalf("body trigger token must be rejected, got %v", err)
	}
}

// TestGitLabProvider_AuthorizesHost_HostPort asserts host pinning compares the
// port-stripped served hostname: a self-managed host configured with a :port
// suffix authorizes the bare hostname the transport passes.
func TestGitLabProvider_AuthorizesHost_HostPort(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.internal:8443")
	ok, _ := p.AuthorizesHost(context.Background(), "gitlab.internal", nil)
	if !ok {
		t.Fatal("port-stripped served host should authorize the bare hostname")
	}
	denied, _ := p.AuthorizesHost(context.Background(), "gitlab.internal:8443", nil)
	if denied {
		t.Fatal("the transport never passes a :port host; a host with one must not match")
	}
}

// TestGitLabProvider_AuthorizesAddr_HostPortResolvesHostname asserts the dial
// guard resolves the port-stripped hostname (LookupNetIP rejects a host:port).
func TestGitLabProvider_AuthorizesAddr_HostPortResolvesHostname(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.internal:8443")
	p.allowPrivateNetwork = true
	var gotHost string
	p.resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		gotHost = host
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	if _, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.5"), nil); err != nil {
		t.Fatalf("AuthorizesAddr: %v", err)
	}
	if gotHost != "gitlab.internal" {
		t.Fatalf("resolver host = %q, want port-stripped %q", gotHost, "gitlab.internal")
	}
}

// errTokenSource is a minimal oauth2.TokenSource that always returns an error,
// used to exercise the token-resolution error paths of currentToken/InjectAuth.
type errTokenSource struct{ err error }

func (s errTokenSource) Token() (*oauth2.Token, error) { return nil, s.err }

// TestGitLabProvider_CurrentToken_Error asserts that currentToken wraps and
// propagates a token-source error.
func TestGitLabProvider_CurrentToken_Error(t *testing.T) {
	t.Parallel()
	srcErr := errors.New("session dead")
	p := newTestGitLab(t, "gitlab.com")
	p.tokenSource = errTokenSource{err: srcErr}
	if _, err := p.currentToken(); !errors.Is(err, srcErr) {
		t.Fatalf("currentToken err = %v, want wrapping %v", err, srcErr)
	}
}

// TestGitlabAuthorizeAction_DeniesGraphQL asserts that /api/graphql is denied.
func TestGitlabAuthorizeAction_DeniesGraphQL(t *testing.T) {
	t.Parallel()
	p := newTestGitLab(t, "gitlab.com")
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://gitlab.com/api/graphql", nil)
	err := p.AuthorizeAction(context.Background(), req, nil)
	if !errors.Is(err, gitlabclass.ErrGraphQLUnsupported) {
		t.Fatalf("AuthorizeAction(/api/graphql) err = %v, want ErrGraphQLUnsupported", err)
	}
}

// TestGitLabProvider_InjectAuth_TokenSourceError asserts that when the token
// source returns an error, InjectAuth returns a wrapped error and does NOT set
// the Authorization header.
func TestGitLabProvider_InjectAuth_TokenSourceError(t *testing.T) {
	t.Parallel()
	srcErr := errors.New("oauth refresh failed")
	p := newTestGitLab(t, "gitlab.com")
	p.tokenSource = errTokenSource{err: srcErr}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/api/v4/user", nil)
	err := p.InjectAuth(req, nil)
	if err == nil {
		t.Fatal("InjectAuth must return error when token source fails")
	}
	if !errors.Is(err, srcErr) {
		t.Fatalf("InjectAuth err = %v, want wrapping %v", err, srcErr)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization must not be set after token resolution failure, got %q", got)
	}
}

// TestAuthorizeAction_NonAPIPath_FailsClosed asserts that a same-host path NOT
// under /api/v4 (a web-UI/artifact download URL like /-/jobs/artifacts/...) now
// fails closed as ErrUnclassifiable: the connector is /api/v4-only and the prior
// same-host download carve-out has been removed. okGitLabFetch supplies a valid
// table, so the request reaches ClassifyRequest → Lookup, which finds no api/v4
// anchor and denies.
func TestAuthorizeAction_NonAPIPath_FailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestGitLabExposure(t, "gitlab.com", gitlabclass.BaselineExposure(), okGitLabFetch)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://gitlab.com/-/jobs/artifacts/x", nil)
	if err := p.AuthorizeAction(context.Background(), req, nil); !errors.Is(err, gitlabclass.ErrUnclassifiable) {
		t.Fatalf("AuthorizeAction(/-/jobs/artifacts/x) = %v, want ErrUnclassifiable", err)
	}
}
