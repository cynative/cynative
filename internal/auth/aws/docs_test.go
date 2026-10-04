package aws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/aws"
)

type fakeSource struct {
	models   map[string][]*aws.ServiceModel // prefix -> models (Dir set).
	raw      map[string][]byte              // dir -> bytes.
	resErr   error
	rawErr   error
	rawCalls atomic.Int32
}

func (f *fakeSource) Resolve(_ context.Context, p string) ([]*aws.ServiceModel, error) {
	if f.resErr != nil {
		return nil, f.resErr
	}
	ms, ok := f.models[p]
	if !ok {
		return nil, fmt.Errorf("%w: %q", aws.ErrUnsupportedService, p)
	}
	return ms, nil
}

func (f *fakeSource) RawModel(_ context.Context, dir string) ([]byte, string, error) {
	f.rawCalls.Add(1)
	if f.rawErr != nil {
		return nil, "", f.rawErr
	}
	return f.raw[dir], "sha-" + dir, nil
}

func fixtureBytes(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/smithy_docs/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// addModel registers raw under prefix as dir. Bytes that ParseModel rejects get a stub ServiceModel.
func (f *fakeSource) addModel(t *testing.T, prefix, dir string, raw []byte) {
	t.Helper()
	sm, err := aws.ParseModel(raw)
	if err != nil {
		sm = &aws.ServiceModel{}
	}
	sm.Dir = dir
	if f.models == nil {
		f.models = map[string][]*aws.ServiceModel{}
		f.raw = map[string][]byte{}
	}
	f.models[prefix] = append(f.models[prefix], sm)
	f.raw[dir] = raw
}

func route53Source(t *testing.T) *fakeSource {
	t.Helper()
	f := &fakeSource{}
	f.addModel(t, "route53", "route-53", fixtureBytes(t, "route-53.json"))
	return f
}

func TestDocumenter_Lookups(t *testing.T) {
	t.Parallel()

	iam := fixtureBytes(t, "iam.json")
	var doc map[string]any
	if err := json.Unmarshal(iam, &doc); err != nil {
		t.Fatal(err)
	}
	shapes, _ := doc["shapes"].(map[string]any)
	lower, _ := json.Marshal(shapes["com.amazonaws.iam#ListRoles"])
	shapes["com.amazonaws.iam#ListROLES"] = json.RawMessage(lower)
	cased, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		src         func(*testing.T) *fakeSource
		q           apiref.Query
		want        apiref.Outcome
		reason      string
		choices     []string
		sha, doc    string
		wantPathTpl string
	}{
		{
			name: "found", src: route53Source,
			q:    apiref.Query{Service: "route53", Operation: "ListHostedZones"},
			want: apiref.OutcomeFound, sha: "sha-route-53", doc: "models/route-53/service/2013-04-01",
		},
		{
			name: "case-insensitive", src: route53Source,
			q:    apiref.Query{Service: "route53", Operation: "listhostedzones"},
			want: apiref.OutcomeFound, sha: "sha-route-53", doc: "models/route-53/service/2013-04-01",
		},
		{
			name: "no such operation", src: route53Source,
			q:    apiref.Query{Service: "route53", Operation: "NoSuchOp"},
			want: apiref.OutcomeNotFound, reason: `no operation "NoSuchOp" in route-53`,
		},
		{
			name: "unknown prefix", src: route53Source,
			q:    apiref.Query{Service: "nope", Operation: "X"},
			want: apiref.OutcomeNotFound, reason: `no AWS model answers on endpoint prefix "nope"`,
		},
		{
			name:    "wrong model",
			src:     route53Source,
			q:       apiref.Query{Service: "route53", Model: "other", Operation: "ListHostedZones"},
			want:    apiref.OutcomeNotFound,
			reason:  `model "other" does not serve "route53"`,
			choices: []string{"route-53"},
		},
		{
			name: "ambiguous across dirs", src: emailSource(iam, iam),
			q:    apiref.Query{Service: "email", Operation: "ListRoles"},
			want: apiref.OutcomeAmbiguous, reason: `pass "model" to choose`, choices: []string{"ses", "sesv2"},
		},
		{
			name: "model picks one", src: emailSource(iam, iam),
			q:    apiref.Query{Service: "email", Model: "sesv2", Operation: "ListRoles"},
			want: apiref.OutcomeFound, sha: "sha-sesv2", doc: "models/sesv2/service/2010-05-08",
		},
		{
			name: "case collision in one model", src: emailSource(cased),
			q:    apiref.Query{Service: "email", Operation: "listroles"},
			want: apiref.OutcomeAmbiguous, choices: []string{"ListROLES", "ListRoles"},
		},
		{
			name: "exact beats case collision", src: emailSource(cased),
			q:    apiref.Query{Service: "email", Operation: "ListRoles"},
			want: apiref.OutcomeFound, sha: "sha-ses", doc: "models/ses/service/2010-05-08",
		},
		{
			name: "resolve unavailable",
			src: func(*testing.T) *fakeSource {
				return &fakeSource{resErr: aws.ErrSmithyUnavailable}
			},
			q:    apiref.Query{Service: "route53", Operation: "ListHostedZones"},
			want: apiref.OutcomeUnavailable, reason: "smithy model unavailable",
		},
		{
			name: "raw unavailable",
			src: func(t *testing.T) *fakeSource {
				f := route53Source(t)
				f.rawErr = aws.ErrSmithyUnavailable
				return f
			},
			q:    apiref.Query{Service: "route53", Operation: "ListHostedZones"},
			want: apiref.OutcomeUnavailable, reason: "route-53",
		},
		{
			name: "malformed unavailable", src: emailSource([]byte("{not json")),
			q:    apiref.Query{Service: "email", Operation: "ListRoles"},
			want: apiref.OutcomeUnavailable,
		},
		{
			name: "metadata failure beats ambiguity", src: emailSource(iam, []byte("{not json")),
			q:    apiref.Query{Service: "email", Operation: "ListRoles"},
			want: apiref.OutcomeUnavailable,
		},
		{
			name: "ec2Query unsupported", src: exSource(exModel("aws.protocols#ec2Query", "/", "", "")),
			q:    apiref.Query{Service: "ex", Operation: "Op"},
			want: apiref.OutcomeUnsupported, reason: "protocol ec2Query is not supported by api_reference",
		},
		{
			name: "incomplete", src: exSource(restJSONModel(
				`"Ids":{"target":"ex#IdList","traits":{"smithy.api#required":{}}}`, "")),
			q:    apiref.Query{Service: "ex", Operation: "Op"},
			want: apiref.OutcomeIncomplete, sha: "sha-ex", doc: "models/ex/service/2020-01-01",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			res := aws.NewDocumenter(c.src(t)).Reference(t.Context(), c.q)
			if res.Outcome != c.want {
				t.Fatalf("outcome %q (%s), want %q", res.Outcome, res.Reason, c.want)
			}
			if !strings.Contains(res.Reason, c.reason) {
				t.Errorf("reason %q lacks %q", res.Reason, c.reason)
			}
			if c.choices != nil && !slices.Equal(res.Choices, c.choices) {
				t.Errorf("choices %q, want %q", res.Choices, c.choices)
			}
			if c.sha != "" && (res.Reference.Source.SHA256 != c.sha || res.Reference.Source.Document != c.doc) {
				t.Errorf("source %+v, want %s %s", res.Reference.Source, c.sha, c.doc)
			}
		})
	}
}

func emailSource(raws ...[]byte) func(*testing.T) *fakeSource {
	return func(t *testing.T) *fakeSource {
		t.Helper()
		f := &fakeSource{}
		dirs := []string{"ses", "sesv2"}
		for i, raw := range raws {
			f.addModel(t, "email", dirs[i], raw)
		}
		return f
	}
}

func exSource(model string) func(*testing.T) *fakeSource {
	return func(t *testing.T) *fakeSource {
		t.Helper()
		f := &fakeSource{}
		f.addModel(t, "ex", "ex", []byte(model))
		return f
	}
}

func TestDocumenter_MemoizesModels(t *testing.T) {
	t.Parallel()

	f := route53Source(t)
	d := aws.NewDocumenter(f)
	for range 2 {
		res := d.Reference(t.Context(), apiref.Query{Service: "route53", Operation: "ListHostedZones"})
		if res.Outcome != apiref.OutcomeFound {
			t.Fatalf("outcome %q", res.Outcome)
		}
	}
	if n := f.rawCalls.Load(); n != 1 {
		t.Errorf("RawModel called %d times, want 1", n)
	}
}

func TestDocumenter_ChoicesAreBounded(t *testing.T) {
	t.Parallel()

	f := &fakeSource{}
	iam := fixtureBytes(t, "iam.json")
	for i := range apiref.MaxChoices + 2 {
		f.addModel(t, "email", fmt.Sprintf("m%d", i), iam)
	}
	res := aws.NewDocumenter(f).Reference(t.Context(), apiref.Query{Service: "email", Operation: "ListRoles"})
	if res.Outcome != apiref.OutcomeAmbiguous || len(res.Choices) != apiref.MaxChoices {
		t.Errorf("%q %q", res.Outcome, res.Choices)
	}
}

func TestDocumenter_SchemaChangeDrivesGuidance(t *testing.T) {
	t.Parallel()

	var doc map[string]any
	if err := json.Unmarshal(fixtureBytes(t, "route-53.json"), &doc); err != nil {
		t.Fatal(err)
	}
	shapes, _ := doc["shapes"].(map[string]any)
	op, _ := shapes["com.amazonaws.route53#ListHostedZones"].(map[string]any)
	traits, _ := op["traits"].(map[string]any)
	httpTrait, _ := traits["smithy.api#http"].(map[string]any)
	httpTrait["uri"] = "/2013-04-01/hostedzonez"
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSource{}
	f.addModel(t, "route53", "route-53", raw)

	res := aws.NewDocumenter(f).Reference(t.Context(), apiref.Query{Service: "route53", Operation: "ListHostedZones"})
	if res.Reference == nil || res.Reference.PathTemplate != "/2013-04-01/hostedzonez" {
		t.Fatalf("result %+v", res)
	}
	other := aws.NewDocumenter(f).Reference(
		t.Context(), apiref.Query{Service: "route53", Operation: "CreateHostedZone"})
	if other.Reference == nil || other.Reference.PathTemplate != "/2013-04-01/hostedzone" {
		t.Errorf("CreateHostedZone path %+v", other.Reference)
	}
}

func TestDocumenter_ReasonsAreBounded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 600)
	d := aws.NewDocumenter(route53Source(t))
	for name, q := range map[string]apiref.Query{
		"operation": {Service: "route53", Operation: long},
		"service":   {Service: long, Operation: "X"},
		"model":     {Service: "route53", Model: long, Operation: "X"},
	} {
		res := d.Reference(t.Context(), q)
		if res.Outcome != apiref.OutcomeNotFound || utf8.RuneCountInString(res.Reason) > apiref.MaxReason {
			t.Errorf("%s: outcome %q, reason length %d", name, res.Outcome, utf8.RuneCountInString(res.Reason))
		}
	}
}

func hintView(t *testing.T, method, rawURL string, hdr http.Header, body string) authreq.View {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, hdr)
	return authreq.NewView(req, body)
}

func hintSource(t *testing.T) *fakeSource {
	t.Helper()
	f := route53Source(t)
	iam := fixtureBytes(t, "iam.json")
	f.addModel(t, "iam", "iam", iam)
	r53 := fixtureBytes(t, "route-53.json")
	f.addModel(t, "email", "ses", r53)
	f.addModel(t, "email", "sesv2", r53)
	f.addModel(t, "jsonsvc", "jsonsvc", []byte(exModel("aws.protocols#awsJson1_1", "/", "", "")))
	f.addModel(t, "ec2x", "ec2x", []byte(exModel("aws.protocols#ec2Query", "/", "", "")))
	for i := 1; i <= apiref.MaxCandidates+1; i++ {
		raw := strings.Replace(exModel("aws.protocols#awsQuery", "/", "", ""), "2020-01-01",
			fmt.Sprintf("200%d-01-01", i), 1)
		f.addModel(t, "multi", fmt.Sprintf("m%d", i), []byte(raw))
	}
	return f
}

func TestDocumenterHint(t *testing.T) {
	t.Parallel()

	jsonTarget := func(target string) http.Header {
		return http.Header{"X-Amz-Target": {target}, "Content-Type": {"application/x-amz-json-1.1"}}
	}
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	cases := []struct {
		name    string
		method  string
		url     string
		hdr     http.Header
		body    string
		service string
		want    []string // substrings, one per candidate.
		op      string
		also    []string // further substrings of the first candidate.
	}{
		{
			name: "route53 plural path", method: "GET", url: "https://route53.amazonaws.com/2013-04-01/hostedzones",
			service: "route53", want: []string{"ListHostedZones (GET /2013-04-01/hostedzone)"}, op: "ListHostedZones",
		},
		{
			name: "iam as json", method: "POST", url: "https://iam.amazonaws.com/",
			hdr: jsonTarget("AWSIdentityManagementV20100508.ListRoles"), body: "{}", service: "iam",
			want: []string{"iam uses awsQuery: POST /"}, op: "ListRoles",
			also: []string{"Action=ListRoles&Version=2010-05-08", "responses are xml"},
		},
		{
			name: "action in query on a rest service", method: "GET",
			url: "https://route53.amazonaws.com/?Action=ListHostedZones", service: "route53",
			want: []string{"route53 uses restXml: GET /2013-04-01/hostedzone"}, op: "ListHostedZones",
		},
		{
			name: "action in form body", method: "POST", url: "https://route53.amazonaws.com/", hdr: form,
			body: "Action=ListHostedZones", service: "route53",
			want: []string{"route53 uses restXml: GET /2013-04-01/hostedzone"}, op: "ListHostedZones",
		},
		{
			name: "action on awsQuery is no mismatch", method: "POST", url: "https://iam.amazonaws.com/", hdr: form,
			body: "Action=ListRoles", service: "iam",
		},
		{
			name: "target on awsJson is no mismatch", method: "POST", url: "https://multi.amazonaws.com/",
			hdr: jsonTarget("Svc.Op"), service: "jsonsvc",
		},
		{
			name: "action on awsJson", method: "GET", url: "https://jsonsvc.amazonaws.com/?Action=Op",
			service: "jsonsvc", want: []string{"jsonsvc uses awsJson1_1: "}, op: "Op",
		},
		{
			name: "target wins over action", method: "POST", url: "https://iam.amazonaws.com/?Action=ListUsers",
			hdr: jsonTarget("Svc.ListRoles"), service: "iam",
			want: []string{"iam uses awsQuery: POST /"}, op: "ListRoles",
			also: []string{"Action=ListRoles&Version=2010-05-08"},
		},
		{name: "nothing close", method: "GET", url: "https://route53.amazonaws.com/zzz/yyy/xxx", service: "route53"},
		{
			name:    "two models merge",
			method:  "GET",
			url:     "https://email.us-east-1.amazonaws.com/2013-04-01/hostedzones",
			service: "email",
			want:    []string{"ListHostedZones (GET /2013-04-01/hostedzone)"},
			op:      "ListHostedZones",
		},
		{
			name: "ec2Query skipped", method: "POST", url: "https://ec2x.amazonaws.com/", hdr: jsonTarget("Svc.Op"),
			service: "ec2x",
		},
		{
			name: "protocol overflow", method: "POST", url: "https://multi.amazonaws.com/", hdr: jsonTarget("Svc.Op"),
			service: "multi",
		},
		{
			name: "target op absent", method: "POST", url: "https://iam.amazonaws.com/", hdr: jsonTarget("Svc.Nope"),
			service: "iam",
		},
		{
			name: "unparsable form", method: "POST", url: "https://route53.amazonaws.com/", hdr: form,
			body: "%zz", service: "route53",
		},
		{
			name: "unparsable query", method: "GET", url: "https://route53.amazonaws.com/?Action=%zz",
			service: "route53",
		},
		{name: "unknown service", method: "GET", url: "https://nope.amazonaws.com/", service: "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			d := aws.NewDocumenter(hintSource(t))
			h := d.Hint(t.Context(), hintView(t, c.method, c.url, c.hdr, c.body), c.service)
			if len(h.Candidates) != len(c.want) || h.Operation != c.op {
				t.Fatalf("hint = %+v", h)
			}
			for i, w := range c.want {
				if !strings.Contains(h.Candidates[i], w) {
					t.Errorf("candidate %q lacks %q", h.Candidates[i], w)
				}
			}
			for _, w := range c.also {
				if !strings.Contains(h.Candidates[0], w) {
					t.Errorf("candidate %q lacks %q", h.Candidates[0], w)
				}
			}
		})
	}
}

func TestDocumenterHint_NoReference(t *testing.T) {
	t.Parallel()

	for service, want := range map[string]bool{"ec2x": true, "route53": false, "iam": false} {
		d := aws.NewDocumenter(hintSource(t))
		h := d.Hint(t.Context(), hintView(t, "GET", "https://"+service+".amazonaws.com/zzz/yyy", nil, ""), service)
		if h.NoReference != want {
			t.Errorf("%s: NoReference = %v, want %v", service, h.NoReference, want)
		}
	}
}

func TestDocumenterHint_RawModelFailure(t *testing.T) {
	t.Parallel()

	f := hintSource(t)
	f.rawErr = aws.ErrSmithyUnavailable
	h := aws.NewDocumenter(f).Hint(t.Context(), hintView(t, "POST", "https://iam.amazonaws.com/",
		http.Header{"X-Amz-Target": {"Svc.ListRoles"}}, "{}"), "iam")
	if len(h.Candidates) != 0 || h.Operation != "" {
		t.Errorf("hint = %+v", h)
	}
}
