package tools_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/auth/aws"
	"github.com/cynative/cynative/internal/auth/github"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/transport"
)

const (
	awsFixtureDir    = "../auth/aws/testdata/smithy_docs/"
	githubFixture    = "../auth/github/testdata/openapi-docs.json"
	formContentType  = "application/x-www-form-urlencoded; charset=utf-8"
	route53Path      = "/2013-04-01/hostedzone"
	hintCandidate    = "Candidates: ListHostedZones (GET /2013-04-01/hostedzone)"
	hintLookup       = `api_reference with {"connector":"aws","operation":"ListHostedZones","service":"route53"}`
	maxInnerParallel = 2
)

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

// awsDocumenter documents one real Smithy fixture.
func awsDocumenter(t *testing.T, prefix, file, dir string) *aws.Documenter {
	t.Helper()
	raw := readFixture(t, awsFixtureDir+file)
	sm, err := aws.ParseModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	sm.Dir = dir
	src := rawSource{apiRefSource{models: map[string][]*aws.ServiceModel{prefix: {sm}}}, raw}

	return aws.NewDocumenter(src)
}

type wireCapture struct {
	method, uri, contentType, target, body string
}

func fillPlaceholders(s string) string {
	return strings.NewReplacer("<owner>", "octo", "<repo>", "hello", "<text>", "hi", "<TableName>", "t1", "<region>", "us-east-1").
		Replace(s)
}

// sendTemplate runs a filled template through the real http_request tool against a TLS test server and returns
// what reached the server plus the template's own host and path.
func sendTemplate(t *testing.T, args transport.RequestArgs) (wireCapture, string) {
	t.Helper()
	var (
		mu  sync.Mutex
		got wireCapture
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = wireCapture{
			method: r.Method, uri: r.RequestURI, contentType: r.Header.Get("Content-Type"),
			target: r.Header.Get("X-Amz-Target"), body: string(b),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tpl, err := url.Parse(fillPlaceholders(args.URL))
	if err != nil {
		t.Fatal(err)
	}
	args.URL = srv.URL + tpl.EscapedPath()
	if tpl.RawQuery != "" {
		args.URL += "?" + tpl.RawQuery
	}
	args.AuthProvider = "loopback"
	args.AWSAuth = nil
	args.Body = fillPlaceholders(args.Body)
	for i := range args.Headers {
		args.Headers[i].Value = fillPlaceholders(args.Headers[i].Value)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	ctx, fail := audit.WithFailure(t.Context())
	out, err := tools.NewHTTPRequestTool(providers, nil).Run(ctx, string(raw))
	if err != nil || fail.Failed() {
		t.Fatalf("http_request failed: %v %s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()

	return got, tpl.Host
}

func wireRequest(t *testing.T, host string, c wireCapture) authreq.View {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), c.method, "https://"+host+c.uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.contentType != "" {
		req.Header.Set("Content-Type", c.contentType)
	}
	if c.target != "" {
		req.Header.Set("X-Amz-Target", c.target)
	}

	return authreq.NewView(req, c.body)
}

// assertAWSClassifies runs the real AWS classifier over the request as it reached the wire.
func assertAWSClassifies(t *testing.T, file, op, host string, got wireCapture) {
	t.Helper()
	model, err := aws.ParseModel(readFixture(t, awsFixtureDir+file))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := aws.ParseHost(host)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := aws.ClassifyOperation(model, wireRequest(t, host, got), parsed)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0] != op {
		t.Errorf("classified %v, want [%s]", ops, op)
	}
}

func TestAPIReferenceContract_AWSWire(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, prefix, file, dir, op string
		host                        string
		method, uri, body           string
		contentType, target         string
	}{
		{
			"route53", "route53", "route-53.json", "route-53", "ListHostedZones", "route53.amazonaws.com",
			http.MethodGet, route53Path, "", "", "",
		},
		{
			"iam", "iam", "iam.json", "iam", "ListRoles", "iam.amazonaws.com",
			http.MethodPost, "/", "Action=ListRoles&Version=2010-05-08", formContentType, "",
		},
		{
			"dynamodb", "dynamodb", "dynamodb.json", "dynamodb", "DescribeTable", "dynamodb.us-east-1.amazonaws.com",
			http.MethodPost, "/", `{"TableName":"t1"}`, "application/x-amz-json-1.0", "DynamoDB_20120810.DescribeTable",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := &stubAWS{docs: awsDocumenter(t, c.prefix, c.file, c.dir)}
			_, out, _ := runRef(t, []auth.Provider{p},
				fmt.Sprintf(`{"connector":"aws","service":%q,"operation":%q}`, c.prefix, c.op))
			if out.Outcome != "found" {
				t.Fatalf("outcome %q: %+v", out.Outcome, out)
			}
			args := templateArgs(t, out)
			got, host := sendTemplate(t, args)
			if host != c.host {
				t.Errorf("host = %q", host)
			}
			if got.method != c.method || got.uri != c.uri || got.body != c.body ||
				got.contentType != c.contentType || got.target != c.target {
				t.Errorf("wire = %+v, want %+v", got, c)
			}

			assertAWSClassifies(t, c.file, c.op, host, got)
		})
	}
}

func TestAPIReferenceContract_GitHubWire(t *testing.T) {
	t.Parallel()

	cases := []struct{ op, method, uri, body, contentType string }{
		{"repos/get", http.MethodGet, "/repos/octo/hello", "", ""},
		{"markdown/render", http.MethodPost, "/markdown", `{"text":"hi"}`, "application/json"},
	}
	tbl, err := github.DistillOpenAPI(readFixture(t, githubFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			t.Parallel()
			p := &docProvider{name: "github", res: githubReference(t, c.op)}
			_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"github","operation":"`+c.op+`"}`)
			got, host := sendTemplate(t, templateArgs(t, out))
			if host != "api.github.com" {
				t.Errorf("host = %q", host)
			}
			if got.method != c.method || got.uri != c.uri || got.body != c.body || got.contentType != c.contentType {
				t.Errorf("wire = %+v, want %+v", got, c)
			}
			v := wireRequest(t, host, got)
			if _, cerr := github.ClassifyRequest(tbl, v.Method, v.EscapedPath); cerr != nil {
				t.Errorf("ClassifyRequest: %v", cerr)
			}
		})
	}
}

// fakeHTTP is an http_request stand-in for the sandbox that answers by the request body's Marker.
type fakeHTTP struct {
	answer func(marker string) string
}

func (fakeHTTP) Info() *schema.ToolInfo { return &schema.ToolInfo{Name: "http_request", Desc: "fake"} }

func (fakeHTTP) Run(context.Context, string) (string, error) { return "", errors.New("unused") }

func (f fakeHTTP) StructuredRun(_ context.Context, args string) (string, error) {
	var in transport.RequestArgs
	if err := json.Unmarshal([]byte(args), &in); err != nil {
		return "", err
	}
	form, err := url.ParseQuery(in.Body)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(transport.Response{Status: http.StatusOK, Body: f.answer(form.Get("Marker"))})
	if err != nil {
		return "", err
	}

	return string(b), nil
}

const iamScript = `
let marker = null, names = [];
for (;;) {
  const body = "Action=ListRoles&Version=2010-05-08" + (marker ? "&Marker=" + encodeURIComponent(marker) : "");
  const r = await http_request({method: "POST", url: "https://iam.amazonaws.com/", body, auth_provider: "aws",
    headers: [{key: "Content-Type", value: "application/x-www-form-urlencoded; charset=utf-8"}],
    aws_auth: {service: "iam"}});
  const res = xml.parse(r.body).ListRolesResponse.ListRolesResult;
  const roles = res.Roles == null ? [] : [].concat(res.Roles.member == null ? [] : res.Roles.member);
  names.push(...roles.map(x => x.RoleName));
  if (res.IsTruncated !== 'true') break;
  marker = res.Marker;
}
console.log(names.join(","));
`

func runScript(t *testing.T, inner []schema.InvokableTool, code string) (string, *audit.Failure) {
	t.Helper()
	ce, err := tools.NewCodeExecutionTool(inner, nil, maxInnerParallel, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, fail := audit.WithFailure(t.Context())
	args, _ := json.Marshal(map[string]string{"code": code})
	out, err := ce.Run(ctx, string(args))
	if err != nil {
		t.Fatal(err)
	}

	return out, fail
}

func TestAPIReferenceContract_IAMXMLGuidance(t *testing.T) {
	t.Parallel()

	_, out, _ := runRef(t, []auth.Provider{&stubAWS{docs: awsDocumenter(t, "iam", "iam.json", "iam")}},
		`{"connector":"aws","service":"iam","operation":"ListRoles"}`)
	parse, _ := out.Reference["response"].(map[string]any)["parse"].(string)
	for _, want := range []string{"xml.parse", "ListRolesResult", "Roles", "member"} {
		if !strings.Contains(parse, want) {
			t.Errorf("Response.Parse %q lacks %q", parse, want)
		}
	}

	const (
		page1 = `<ListRolesResponse><ListRolesResult><IsTruncated>true</IsTruncated><Marker>m1</Marker><Roles>` +
			`<member><RoleName>a</RoleName></member><member><RoleName>b</RoleName></member></Roles>` +
			`</ListRolesResult></ListRolesResponse>`
		page2 = `<ListRolesResponse><ListRolesResult><IsTruncated>false</IsTruncated><Roles>` +
			`<member><RoleName>c</RoleName></member></Roles></ListRolesResult></ListRolesResponse>`
		empty = `<ListRolesResponse><ListRolesResult><IsTruncated>false</IsTruncated><Roles/>` +
			`</ListRolesResult></ListRolesResponse>`
	)
	cases := []struct {
		name   string
		answer func(string) string
		want   string
	}{
		{"paginated", func(m string) string {
			if m == "m1" {
				return page2
			}

			return page1
		}, "a,b,c"},
		{"empty", func(string) string { return empty }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, fail := runScript(t, []schema.InvokableTool{fakeHTTP{c.answer}}, iamScript)
			if strings.TrimSpace(got) != c.want || fail.Failed() {
				t.Errorf("output %q failed %v, want %q", got, fail.Failed(), c.want)
			}
		})
	}
}

// stubAWS is an aws-named provider whose action gate returns a configurable error.
type stubAWS struct {
	gate func() error
	docs *aws.Documenter
}

func (stubAWS) Name() string        { return "aws" }
func (stubAWS) Description() string { return "stub aws" }

func (stubAWS) InjectAuth(*http.Request, authreq.ProviderArgs) error { return nil }

func (stubAWS) AuthorizesHost(_ context.Context, host string, _ authreq.ProviderArgs) (bool, error) {
	return host == "route53.amazonaws.com", nil
}

func (s stubAWS) AuthorizeAction(context.Context, authreq.View, authreq.ProviderArgs) error {
	return s.gate()
}

func (s stubAWS) Reference(ctx context.Context, q apiref.Query) apiref.Result {
	return s.docs.Reference(ctx, q)
}

func (s stubAWS) Hint(ctx context.Context, v authreq.View, e *authreq.UnmatchedRequestError) apiref.Hint {
	return s.docs.Hint(ctx, v, e.Service)
}

var (
	_ auth.ActionAuthorizer    = stubAWS{}
	_ auth.OperationDocumenter = stubAWS{}
)

func newStubAWS(t *testing.T, gate func() error) []auth.Provider {
	t.Helper()
	d := awsDocumenter(t, "route53", "route-53.json", "route-53")

	return []auth.Provider{&stubAWS{gate: gate, docs: d}}
}

func unmatchedGate() error {
	return &authreq.UnmatchedRequestError{
		Service: "route53", Err: fmt.Errorf("%w: no candidate", aws.ErrActionUnresolved),
	}
}

const hostedZonesCall = `{"method":"GET","url":"https://route53.amazonaws.com/2013-04-01/hostedzones",` +
	`"auth_provider":"aws","aws_auth":{"service":"route53"}}`

func TestAPIReferenceContract_UnmatchedHintDirectAndSandbox(t *testing.T) {
	t.Parallel()

	providers := newStubAWS(t, unmatchedGate)
	httpTool := tools.NewHTTPRequestTool(providers, nil)

	t.Run("direct", func(t *testing.T) {
		t.Parallel()
		ctx, fail := audit.WithFailure(t.Context())
		got, err := httpTool.Run(ctx, hostedZonesCall)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{hintCandidate, hintLookup} {
			if !strings.Contains(got, want) {
				t.Errorf("result lacks %q: %s", want, got)
			}
		}
		if fail.Count() != 1 {
			t.Errorf("failure count = %d", fail.Count())
		}
	})
	t.Run("sandbox", func(t *testing.T) {
		t.Parallel()
		code := "try { await http_request(" + hostedZonesCall + ") } catch (e) { console.log(e.message) }"
		got, fail := runScript(t, []schema.InvokableTool{httpTool}, code)
		for _, want := range []string{hintCandidate, hintLookup} {
			if !strings.Contains(got, want) {
				t.Errorf("output lacks %q: %s", want, got)
			}
		}
		if fail.Count() != 1 {
			t.Errorf("failure count = %d", fail.Count())
		}
	})
}

func TestAPIReferenceContract_OtherDenialsStayDistinct(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"policy denied", aws.ErrPolicyDenied, aws.ErrPolicyDenied.Error()},
		{"smithy unavailable", aws.ErrSmithyUnavailable, aws.ErrSmithyUnavailable.Error()},
		{
			"unmapped iam action", fmt.Errorf("%w: iam action", aws.ErrActionUnresolved),
			"could not resolve IAM action for operation: iam action",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			providers := newStubAWS(t, func() error { return c.err })
			got, err := tools.NewHTTPRequestTool(providers, nil).Run(t.Context(), hostedZonesCall)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(got, "api_reference with") || !strings.Contains(got, c.want) {
				t.Errorf("result = %s", got)
			}
		})
	}

	t.Run("server 403", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("AccessDenied"))
		}))
		t.Cleanup(srv.Close)
		providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
		raw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})
		got, err := tools.NewHTTPRequestTool(providers, nil).Run(t.Context(), string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, "api_reference with") || !strings.Contains(got, "AccessDenied") {
			t.Errorf("result = %s", got)
		}
	})
}
