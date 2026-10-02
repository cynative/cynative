package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
	awshardening "github.com/cynative/cynative/internal/auth/aws"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	"github.com/cynative/cynative/internal/cache"
)

type fakeDocumenter struct {
	name string
	hint apiref.Hint
	res  apiref.Result
}

func (f *fakeDocumenter) Name() string        { return f.name }
func (f *fakeDocumenter) Description() string { return "fake" }
func (f *fakeDocumenter) InjectAuth(_ *http.Request, _ authreq.ProviderArgs) error {
	return nil
}

func (f *fakeDocumenter) AuthorizesHost(context.Context, string, authreq.ProviderArgs) (bool, error) {
	return true, nil
}

func (f *fakeDocumenter) Reference(context.Context, apiref.Query) apiref.Result { return f.res }

func (f *fakeDocumenter) Hint(context.Context, authreq.View, *authreq.UnmatchedRequestError) apiref.Hint {
	return f.hint
}

func TestLookupReference(t *testing.T) {
	t.Parallel()
	want := apiref.Result{Outcome: apiref.OutcomeFound}
	cases := []struct {
		name      string
		providers []Provider
		wantOut   apiref.Outcome
		wantReas  string
	}{
		{"not configured", nil, apiref.OutcomeUnsupported, `connector "failing" is not configured in this session`},
		{
			"no support",
			[]Provider{&authtest.FailingProvider{}},
			apiref.OutcomeUnsupported,
			`connector "failing" has no API reference support`,
		},
		{"delegates", []Provider{&fakeDocumenter{name: "failing", res: want}}, apiref.OutcomeFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := LookupReference(t.Context(), tc.providers, apiref.Query{Connector: "failing"})
			if got.Outcome != tc.wantOut || got.Reason != tc.wantReas {
				t.Errorf("got %+v", got)
			}
		})
	}
}

var errGateDetail = fmt.Errorf("%w for %q", awshardening.ErrActionUnresolved, "x")

func unmatched(service string) error {
	return error(&authreq.UnmatchedRequestError{
		Service: service,
		Err: fmt.Errorf(
			"aws_hardening: could not resolve IAM action for operation: no candidate serves the request for %q",
			"route53",
		),
	})
}

func name(ps []Provider) string {
	if len(ps) > 0 {
		return ps[0].Name()
	}

	return "aws"
}

func TestExplainUnmatched_PassThrough(t *testing.T) {
	t.Parallel()
	view := authreq.View{Method: "GET", EscapedPath: "/x"}
	plain := errors.New("plain")
	um := unmatched("route53")
	doc := &fakeDocumenter{name: "aws"}
	cases := []struct {
		name      string
		providers []Provider
		err       error
	}{
		{"plain error", []Provider{doc}, plain},
		{"unknown provider", nil, um},
		{"non documenter", []Provider{&authtest.FailingProvider{}}, um},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExplainUnmatched(
				t.Context(),
				name(tc.providers),
				view,
				tc.providers,
				tc.err,
			); got != tc.err { //nolint:errorlint // identity is the property.
				t.Errorf("got %v, want the original error", got)
			}
		})
	}
}

func TestExplainUnmatched_Message(t *testing.T) {
	t.Parallel()
	doc := &fakeDocumenter{name: "aws", hint: apiref.Hint{
		Candidates: []string{"ListHostedZones (GET /2013-04-01/hostedzone)"}, Operation: "ListHostedZones",
	}}
	view := authreq.View{Method: "GET", EscapedPath: "/2013-04-01/hostedzones"}
	got := ExplainUnmatched(t.Context(), "aws", view, []Provider{doc}, unmatched("route53"))
	want := `aws_hardening: could not resolve IAM action for operation: ` +
		`no candidate serves the request for "route53". ` +
		`GET "/2013-04-01/hostedzones" on aws/route53 matched no operation in the cached API metadata. ` +
		`The gate stopped before attaching credentials or sending anything; this says nothing about the ` +
		`principal's permissions. Check the request shape against the operation reference. ` +
		`Candidates: ListHostedZones (GET /2013-04-01/hostedzone). For an operation's request template ` +
		`call api_reference with {"connector":"aws","operation":"ListHostedZones","service":"route53"}.`
	if got.Error() != want {
		t.Errorf("got  %s\nwant %s", got.Error(), want)
	}
}

func TestExplainUnmatched_NoReferenceOmitsLookup(t *testing.T) {
	t.Parallel()
	doc := &fakeDocumenter{name: "aws", hint: apiref.Hint{NoReference: true}}
	view := authreq.View{Method: "POST", EscapedPath: "/"}
	msg := ExplainUnmatched(t.Context(), "aws", view, []Provider{doc}, unmatched("ec2")).Error()
	if strings.Contains(msg, "api_reference") || !strings.HasSuffix(msg, "against the operation reference.") ||
		!strings.Contains(msg, `POST "/" on aws/ec2 matched no operation`) {
		t.Errorf("msg = %s", msg)
	}
}

func TestExplainUnmatched_MessageUnwraps(t *testing.T) {
	t.Parallel()
	um := &authreq.UnmatchedRequestError{Service: "route53", Err: errGateDetail}
	doc := &fakeDocumenter{name: "aws"}
	got := ExplainUnmatched(t.Context(), "aws", authreq.View{Method: "GET"}, []Provider{doc}, um)
	if !errors.Is(got, awshardening.ErrActionUnresolved) {
		t.Errorf("errors.Is lost the gate sentinel: %v", got)
	}
	if _, ok := errors.AsType[*UnmatchedExplanationError](got); !ok {
		t.Errorf("want *UnmatchedExplanationError, got %T", got)
	}
}

func TestExplainUnmatched_EmptyHintAndService(t *testing.T) {
	t.Parallel()
	doc := &fakeDocumenter{name: "github"}
	um := &authreq.UnmatchedRequestError{Err: errors.New("no op")}
	got := ExplainUnmatched(t.Context(), "github", authreq.View{Method: "POST", EscapedPath: "/x"}, []Provider{doc}, um)
	msg := got.Error()
	if !strings.HasPrefix(msg, "no op. POST ") || !strings.Contains(msg, `on github matched no operation`) ||
		strings.Contains(msg, "Candidates:") ||
		!strings.Contains(msg, `{"connector":"github","operation":"<OperationName>"}`) {
		t.Errorf("msg = %s", msg)
	}
}

func TestExplainUnmatched_TruncatesAndEscapes(t *testing.T) {
	t.Parallel()
	doc := &fakeDocumenter{name: "github"}
	long := "/" + strings.Repeat("é", 400)
	um := &authreq.UnmatchedRequestError{Err: errors.New(strings.Repeat("g", 400))}
	got := ExplainUnmatched(t.Context(), "github", authreq.View{Method: "GET", EscapedPath: long}, []Provider{doc}, um)
	msg := got.Error()
	if strings.Contains(msg, strings.Repeat("é", apiref.MaxPathEcho+1)) ||
		strings.Contains(msg, strings.Repeat("g", apiref.MaxGateDetail+1)) {
		t.Errorf("echo not truncated: %d bytes", len(msg))
	}
	ctl := ExplainUnmatched(t.Context(), "github", authreq.View{Method: "GET", EscapedPath: "/a\nb\x00"},
		[]Provider{doc}, um)
	if strings.ContainsAny(ctl.Error(), "\n\x00") || !strings.Contains(ctl.Error(), `"/a\nb\x00"`) {
		t.Errorf("control characters not escaped: %q", ctl.Error())
	}
}

func TestExplainUnmatched_BoundsMethod(t *testing.T) {
	t.Parallel()
	doc := &fakeDocumenter{name: "github"}
	um := &authreq.UnmatchedRequestError{Err: errors.New("x")}
	method := strings.Repeat("M", 1000)
	msg := ExplainUnmatched(t.Context(), "github", authreq.View{Method: method, EscapedPath: "/a"},
		[]Provider{doc}, um).Error()
	if strings.Contains(msg, strings.Repeat("M", apiref.MaxMethodEcho+1)) ||
		!strings.Contains(msg, "matched no operation in the cached API metadata") {
		t.Errorf("method not bounded: %d bytes", len(msg))
	}
}

// docsSource is a ModelSource over the route-53 fixture.
type docsSource struct{ raw []byte }

func (s *docsSource) Resolve(_ context.Context, prefix string) ([]*awshardening.ServiceModel, error) {
	if prefix != "route53" {
		return nil, awshardening.ErrUnsupportedService
	}
	sm, err := awshardening.ParseModel(s.raw)
	if err != nil {
		return nil, err
	}
	sm.Dir = "route-53"

	return []*awshardening.ServiceModel{sm}, nil
}

func (s *docsSource) RawModel(context.Context, string) ([]byte, string, error) {
	return s.raw, "sha", nil
}

func TestAWSProvider_ReferenceAndHint(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("aws/testdata/smithy_docs/route-53.json")
	if err != nil {
		t.Fatal(err)
	}
	newProv := func(t *testing.T) *awsProvider {
		t.Helper()
		var cfg aws.Config
		cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			t.Error("credential seam touched")

			return aws.Credentials{}, errors.New("touched")
		})
		return newAWSProvider(cfg, func(context.Context) error {
			t.Error("lazy resolve touched")

			return nil
		})
	}
	um := &authreq.UnmatchedRequestError{Service: "route53", Err: errGateDetail}
	view := authreq.View{
		Method: "GET", Hostname: "route53.amazonaws.com", Path: "/2013-04-01/hostedzones",
		EscapedPath: "/2013-04-01/hostedzones",
	}

	t.Run("nil docs", func(t *testing.T) {
		t.Parallel()
		p := newProv(t)
		if res := p.Reference(
			t.Context(),
			apiref.Query{Service: "route53"},
		); res.Outcome != apiref.OutcomeUnavailable ||
			res.Reason != "AWS API metadata is not configured" {
			t.Errorf("res = %+v", res)
		}
		if h := p.Hint(t.Context(), view, um); len(h.Candidates) != 0 || h.Operation != "" {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("with docs", func(t *testing.T) {
		t.Parallel()
		p := newProv(t)
		p.docs = awshardening.NewDocumenter(&docsSource{raw: raw})
		res := p.Reference(t.Context(), apiref.Query{Service: "route53", Operation: "ListHostedZones"})
		if res.Outcome != apiref.OutcomeFound {
			t.Errorf("res = %+v", res)
		}
		h := p.Hint(t.Context(), view, um)
		if h.Operation != "ListHostedZones" || len(h.Candidates) == 0 {
			t.Errorf("hint = %+v", h)
		}
	})
}

func docsFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("github/testdata/openapi-docs.json")
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func newDocsCache(
	dir string,
	fetch func(context.Context) ([]byte, error),
) *cache.TTLCache[githubhardening.OperationDocs] {
	return cache.NewNamedCache(cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now}, "docs", fetch,
		githubhardening.DistillDocs, (*githubhardening.OperationDocs).Serialize,
		githubhardening.UnmarshalDocs, githubhardening.AdmitDocs)
}

func TestGithubProvider_ReferenceAndHint(t *testing.T) {
	t.Parallel()
	raw := docsFixture(t)
	um := &authreq.UnmatchedRequestError{Err: errors.New("x")}
	view := authreq.View{Method: "DELETE", Hostname: "api.github.com", Path: "/repos/o/r", EscapedPath: "/repos/o/r"}
	failing := func(context.Context) ([]byte, error) { return nil, errors.New("offline") }

	check := func(t *testing.T, p *githubProvider, wantFound bool) {
		t.Helper()
		res := p.Reference(t.Context(), apiref.Query{Operation: "repos/get"})
		h := p.Hint(t.Context(), view, um)
		if wantFound {
			if res.Outcome != apiref.OutcomeFound ||
				!slices.Contains(h.Candidates, "repos/get (GET /repos/{owner}/{repo})") {
				t.Errorf("res=%+v hint=%+v", res, h)
			}

			return
		}
		if res.Outcome != apiref.OutcomeUnavailable ||
			res.Reason != "GitHub OpenAPI documentation could not be loaded" ||
			len(h.Candidates) != 0 {
			t.Errorf("res=%+v hint=%+v", res, h)
		}
	}

	t.Run("nil cache", func(t *testing.T) {
		t.Parallel()
		check(t, newGithubProvider("t", githubhardening.BaselineExposure(), nil), false)
	})
	t.Run("fetch fails, no disk copy", func(t *testing.T) {
		t.Parallel()
		p := newGithubProvider("t", githubhardening.BaselineExposure(), nil)
		p.docs = newDocsCache(t.TempDir(), failing)
		check(t, p, false)
	})
	t.Run("warm cache never fetches", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if newDocsCache(dir, func(context.Context) ([]byte, error) { return raw, nil }).Get(t.Context()) == nil {
			t.Fatal("seed cache failed")
		}
		p := newGithubProvider("t", githubhardening.BaselineExposure(), nil)
		p.docs = newDocsCache(dir, func(context.Context) ([]byte, error) {
			t.Error("warm cache must not fetch")

			return nil, errors.New("unexpected")
		})
		check(t, p, true)
	})
}

func TestGithubProvider_HintTriesAFailingDocsLoadOnce(t *testing.T) {
	t.Parallel()
	um := &authreq.UnmatchedRequestError{Err: errors.New("x")}
	view := authreq.View{Method: "DELETE", Hostname: "api.github.com", Path: "/repos/o/r", EscapedPath: "/repos/o/r"}
	newProv := func(t *testing.T, fetches *atomic.Int32) *githubProvider {
		t.Helper()
		p := newGithubProvider("t", githubhardening.BaselineExposure(), nil)
		p.docs = newDocsCache(t.TempDir(), func(context.Context) ([]byte, error) {
			fetches.Add(1)

			return nil, errors.New("offline")
		})

		return p
	}

	t.Run("sequential", func(t *testing.T) {
		t.Parallel()
		var fetches atomic.Int32
		p := newProv(t, &fetches)
		for range 2 {
			if h := p.Hint(t.Context(), view, um); len(h.Candidates) != 0 {
				t.Errorf("hint = %+v", h)
			}
		}
		if n := fetches.Load(); n != 1 {
			t.Errorf("two hints fetched %d times, want 1", n)
		}
		res := p.Reference(t.Context(), apiref.Query{Operation: "repos/get"})
		if res.Outcome != apiref.OutcomeUnavailable || fetches.Load() != 2 {
			t.Errorf("reference did not try the cache again: res=%+v fetches=%d", res, fetches.Load())
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		t.Parallel()
		var fetches atomic.Int32
		p := newProv(t, &fetches)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { p.Hint(t.Context(), view, um) })
		}
		wg.Wait()
		if n := fetches.Load(); n != 1 {
			t.Errorf("8 concurrent hints fetched %d times, want 1", n)
		}
	})
	t.Run("cancelled context does not latch", func(t *testing.T) {
		t.Parallel()
		var fetches atomic.Int32
		p := newProv(t, &fetches)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		p.Hint(ctx, view, um)
		first := fetches.Load()
		p.Hint(t.Context(), view, um)
		if got := fetches.Load(); got != first+1 {
			t.Errorf("live hint after a cancelled one fetched %d more times, want 1", got-first)
		}
	})
}

func TestGithubProvider_ReferenceSuccessClearsHintLatch(t *testing.T) {
	t.Parallel()
	raw := docsFixture(t)
	um := &authreq.UnmatchedRequestError{Err: errors.New("x")}
	view := authreq.View{Method: "DELETE", Hostname: "api.github.com", Path: "/repos/o/r", EscapedPath: "/repos/o/r"}
	var fetches atomic.Int32
	p := newGithubProvider("t", githubhardening.BaselineExposure(), nil)
	p.docs = newDocsCache(t.TempDir(), func(context.Context) ([]byte, error) {
		if fetches.Add(1) == 1 {
			return nil, errors.New("offline")
		}

		return raw, nil
	})

	if h := p.Hint(t.Context(), view, um); len(h.Candidates) != 0 {
		t.Fatalf("hint on a failing fetch = %+v", h)
	}
	if res := p.Reference(t.Context(), apiref.Query{Operation: "repos/get"}); res.Outcome != apiref.OutcomeFound {
		t.Fatalf("reference = %+v", res)
	}
	before := fetches.Load()
	h := p.Hint(t.Context(), view, um)
	if !slices.Contains(h.Candidates, "repos/get (GET /repos/{owner}/{repo})") {
		t.Errorf("hint after a successful reference = %+v", h)
	}
	if got := fetches.Load(); got != before {
		t.Errorf("hint fetched %d more times, want 0", got-before)
	}
}

func TestProviderDescriptions_NameAPIReference(t *testing.T) {
	t.Parallel()
	for _, p := range []Provider{
		newGithubProvider("t", githubhardening.BaselineExposure(), nil),
		newAWSProvider(aws.Config{}, nil),
	} {
		if !strings.Contains(p.Description(), "call the api_reference tool.") {
			t.Errorf("%s description lacks the api_reference sentence: %q", p.Name(), p.Description())
		}
	}
}

func TestGithubOutcome_WiresDocsAndLeavesTableAlone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	d := stubDeps()
	cfg := GithubHardeningConfig{
		Dir:   dir,
		TTL:   time.Hour,
		Clock: time.Now,
	}
	// Seed a valid table through the same cache the outcome builds.
	seed := cache.NewTableCache(cfg.Config,
		func(context.Context) ([]byte, error) { return []byte(provFixtureOpenAPI), nil },
		githubhardening.DistillOpenAPI, (*githubhardening.Table).Serialize,
		githubhardening.UnmarshalTable, githubhardening.AdmitTable)
	if seed.Get(t.Context()) == nil {
		t.Fatal("seed table failed")
	}
	if err := os.WriteFile(filepath.Join(dir, "docs.json"), []byte("{not json"), cache.FilePerm); err != nil {
		t.Fatal(err)
	}
	out := d.githubOutcome(t.Context(), cfg, false)
	gh, ok := out.providers[0].(*githubProvider)
	if !ok || gh.docs == nil {
		t.Fatalf("provider = %+v", out.providers)
	}
	v := authreq.View{Method: "GET", Hostname: "api.github.com", Path: "/user", EscapedPath: "/user", Port: "443"}
	if err := gh.AuthorizeAction(t.Context(), v, authreq.ProviderArgs{}); err != nil {
		t.Errorf("AuthorizeAction must keep working with a malformed docs.json: %v", err)
	}
}
