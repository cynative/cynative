package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
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

type docProvider struct {
	authtest.FailingProvider

	name string
	res  apiref.Result
}

func (p *docProvider) Name() string { return p.name }

func (p *docProvider) Reference(context.Context, apiref.Query) apiref.Result { return p.res }

func (p *docProvider) Hint(context.Context, authreq.View, *authreq.UnmatchedRequestError) apiref.Hint {
	return apiref.Hint{}
}

var _ auth.OperationDocumenter = (*docProvider)(nil)

type apiRefSource struct {
	models map[string][]*aws.ServiceModel
}

func (s apiRefSource) Resolve(_ context.Context, p string) ([]*aws.ServiceModel, error) {
	ms, ok := s.models[p]
	if !ok {
		return nil, fmt.Errorf("%w: %q", aws.ErrUnsupportedService, p)
	}

	return ms, nil
}

func (apiRefSource) RawModel(context.Context, string) ([]byte, string, error) { return nil, "", nil }

func awsReference(t *testing.T, prefix, file, dir, op string) apiref.Result {
	t.Helper()
	raw, err := os.ReadFile("../auth/aws/testdata/smithy_docs/" + file)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := aws.ParseModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	sm.Dir = dir
	src := apiRefSource{models: map[string][]*aws.ServiceModel{prefix: {sm}}}
	// The fake's RawModel returns nothing, so serve the real bytes.
	return aws.NewDocumenter(rawSource{src, raw}).Reference(t.Context(), apiref.Query{
		Connector: "aws", Service: prefix, Operation: op,
	})
}

type rawSource struct {
	apiRefSource

	raw []byte
}

func (r rawSource) RawModel(context.Context, string) ([]byte, string, error) {
	return r.raw, "sha", nil
}

func githubReference(t *testing.T, op string) apiref.Result {
	t.Helper()
	raw, err := os.ReadFile("../auth/github/testdata/openapi-docs.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := github.DistillDocs(raw)
	if err != nil {
		t.Fatal(err)
	}

	return d.Reference(apiref.Query{Connector: "github", Operation: op})
}

type refOut struct {
	Outcome         string         `json:"outcome"`
	Reason          string         `json:"reason"`
	Choices         []string       `json:"choices"`
	Reference       map[string]any `json:"reference"`
	RequestTemplate map[string]any `json:"request_template"`
	Note            string         `json:"note"`
}

func runRef(t *testing.T, providers []auth.Provider, args string) (string, refOut, *audit.Failure) {
	t.Helper()
	ctx, fail := audit.WithFailure(t.Context())
	got, err := tools.NewAPIReferenceTool(providers).Run(ctx, args)
	if err != nil {
		t.Fatalf("Run returned a Go error: %v", err)
	}
	var out refOut
	if uerr := json.Unmarshal([]byte(got), &out); uerr != nil {
		t.Fatalf("output is not JSON: %v\n%s", uerr, got)
	}

	return got, out, fail
}

func templateArgs(t *testing.T, out refOut) transport.RequestArgs {
	t.Helper()
	var args transport.RequestArgs
	b, _ := json.Marshal(out.RequestTemplate)
	if err := json.Unmarshal(b, &args); err != nil {
		t.Fatal(err)
	}

	return args
}

func hasHeader(args transport.RequestArgs, k, v string) bool {
	for _, h := range args.Headers {
		if h.Key == k && h.Value == v {
			return true
		}
	}

	return false
}

func TestAPIReference_Info(t *testing.T) {
	t.Parallel()

	info := tools.NewAPIReferenceTool(nil).Info()
	if info.Name != "api_reference" {
		t.Errorf("name = %q", info.Name)
	}
	raw, _ := json.Marshal(info.Params)
	for _, want := range []string{"connector", "operation", "service", "model"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("schema missing %q: %s", want, raw)
		}
	}
	if _, ok := tools.NewAPIReferenceTool(nil).(schema.StructuredRunner); ok {
		t.Error("api_reference must not implement StructuredRunner")
	}
}

func TestAPIReference_RendersIAMTemplate(t *testing.T) {
	t.Parallel()

	res := awsReference(t, "iam", "iam.json", "iam", "ListRoles")
	p := &docProvider{name: "aws", res: res}
	got, out, fail := runRef(t, []auth.Provider{p}, `{"connector":"aws","service":"iam","operation":"ListRoles"}`)
	if out.Outcome != "found" || fail.Failed() || fail.Progress() == 0 {
		t.Fatalf("outcome %q progress %d: %s", out.Outcome, fail.Progress(), got)
	}
	if !strings.Contains(out.Note, "percent-encode query and form values and every path value") ||
		!strings.Contains(out.Note, "a '/' inside a path value becomes %2F") ||
		!strings.Contains(out.Note, "only a <Name+> path value spans segments") ||
		!strings.Contains(out.Note, "quotes included, with JSON.stringify(value)") ||
		!strings.Contains(out.Note, "under the wire_name and location its entry in inputs gives") ||
		!strings.Contains(out.Note, "<Name+:unrendered>") {
		t.Errorf("note = %q", out.Note)
	}
	args := templateArgs(t, out)
	if args.Method != http.MethodPost || args.URL != "https://iam.amazonaws.com/" || args.AuthProvider != "aws" ||
		args.AWSAuth == nil || args.AWSAuth.Service != "iam" ||
		args.Body != "Action=ListRoles&Version=2010-05-08" {
		t.Errorf("args = %+v", args)
	}
	if !hasHeader(args, "Content-Type", "application/x-www-form-urlencoded; charset=utf-8") {
		t.Errorf("headers = %+v", args.Headers)
	}
	if strings.Contains(got, "\\u003c") {
		t.Errorf("output escaped HTML: %s", got)
	}
}

func TestAPIReference_RendersRoute53Template(t *testing.T) {
	t.Parallel()

	res := awsReference(t, "route53", "route-53.json", "route-53", "ListHostedZones")
	p := &docProvider{name: "aws", res: res}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","service":"route53","operation":"ListHostedZones"}`)
	args := templateArgs(t, out)
	if args.URL != "https://route53.amazonaws.com/2013-04-01/hostedzone" || args.Body != "" {
		t.Errorf("args = %+v", args)
	}
}

func TestAPIReference_RendersGitHubTemplates(t *testing.T) {
	t.Parallel()

	cases := []struct{ op, url, body string }{
		{"repos/get", "https://api.github.com/repos/<owner>/<repo>", ""},
		{"markdown/render", "https://api.github.com/markdown", `{"text":"<text>"}`},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			t.Parallel()
			p := &docProvider{name: "github", res: githubReference(t, c.op)}
			_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"github","operation":"`+c.op+`"}`)
			args := templateArgs(t, out)
			if args.URL != c.url || args.Body != c.body || args.AuthProvider != "github" {
				t.Errorf("args = %+v", args)
			}
			if c.body != "" && !hasHeader(args, "Content-Type", "application/json") {
				t.Errorf("headers = %+v", args.Headers)
			}
		})
	}
}

func TestAPIReference_UnrenderedPlaceholder(t *testing.T) {
	t.Parallel()

	ref := &apiref.Reference{
		Connector: "aws", Operation: "Op", Method: "GET", PathTemplate: "/things/{Id}",
		Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyNone,
		Inputs: []apiref.Input{{
			Name: "Id", WireName: "Id", Location: apiref.LocationPath, Required: true,
		}},
		Gaps: []string{"Id cannot be rendered"},
	}
	p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: ref}}
	_, out, fail := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
	args := templateArgs(t, out)
	if args.URL != "https://ex.amazonaws.com/things/<Id:unrendered>" {
		t.Errorf("url = %q", args.URL)
	}
	if out.Reference["gaps"] == nil || fail.Progress() == 0 || fail.Failed() {
		t.Errorf("gaps %v progress %d failed %v", out.Reference["gaps"], fail.Progress(), fail.Failed())
	}
}

func TestAPIReference_JSONBodyPlaceholderTypes(t *testing.T) {
	t.Parallel()

	in := func(name, typ string, renderable bool) apiref.Input {
		return apiref.Input{
			Name:       name,
			WireName:   name,
			Location:   apiref.LocationBody,
			Required:   true,
			Type:       typ,
			Renderable: renderable,
		}
	}
	ref := &apiref.Reference{
		Connector: "aws", Operation: "Op", Method: "POST", PathTemplate: "/x",
		Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyJSON,
		Inputs: []apiref.Input{
			in("Name", "string", true), in("Count", "integer", true), in("On", "boolean", true),
			in("Mode", "enum", true), in("Lost", "integer", false), in("a<b", "double", true),
		},
	}
	p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeFound, Reference: ref}}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
	want := `{"Count":<Count>,"Lost":"<Lost:unrendered>","Mode":"<Mode>","Name":"<Name>","On":<On>,` +
		`"a<b":<a<b>}`
	if got := templateArgs(t, out).Body; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestAPIReference_Outcomes(t *testing.T) {
	t.Parallel()

	seven := []string{"g", "f", "e", "d", "c", "b", "a"}
	long := strings.Repeat("x", 900)
	cases := []struct {
		name      string
		providers []auth.Provider
		args      string
		outcome   string
		failed    bool
		choices   int
	}{
		{
			"not_found",
			[]auth.Provider{&docProvider{name: "aws", res: apiref.Result{
				Outcome: apiref.OutcomeNotFound, Reason: long,
			}}},
			`{"connector":"aws","operation":"Nope"}`, "not_found", true, 0,
		},
		{
			"ambiguous",
			[]auth.Provider{&docProvider{name: "aws", res: apiref.Result{
				Outcome: apiref.OutcomeAmbiguous, Choices: seven,
			}}},
			`{"connector":"aws","operation":"Op"}`, "ambiguous", true, apiref.MaxChoices,
		},
		{"unsupported", nil, `{"connector":"aws","operation":"Op"}`, "unsupported", true, 0},
		{
			"unavailable",
			[]auth.Provider{&docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeUnavailable}}},
			`{"connector":"aws","operation":"Op"}`, "unavailable", true, 0,
		},
		{"empty operation", nil, `{"connector":"aws"}`, "not_found", true, 0},
		{"invalid json", nil, `{`, "not_found", true, 0},
		{
			"found",
			[]auth.Provider{&docProvider{name: "aws", res: apiref.Result{
				Outcome:   apiref.OutcomeFound,
				Reference: &apiref.Reference{Connector: "aws", Operation: "Op", Method: "GET", PathTemplate: "/"},
			}}},
			`{"connector":"aws","operation":"Op"}`, "found", false, 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, out, fail := runRef(t, c.providers, c.args)
			if out.Outcome != c.outcome {
				t.Errorf("outcome = %q", out.Outcome)
			}
			if fail.Failed() != c.failed || (fail.Progress() > 0) == c.failed {
				t.Errorf("failed %v progress %d", fail.Failed(), fail.Progress())
			}
			if len(out.Choices) != c.choices {
				t.Errorf("choices = %v", out.Choices)
			}
			if len([]rune(out.Reason)) > apiref.MaxReason {
				t.Errorf("reason has %d runes", len([]rune(out.Reason)))
			}
		})
	}
}

func bigRef(required, optional, descLen, summaryLen int) *apiref.Reference {
	ref := &apiref.Reference{
		Connector: "aws", Service: "svc", Operation: "Op", Method: "GET", PathTemplate: "/",
		Endpoint: "https://svc.amazonaws.com", BodyEncoding: apiref.BodyNone,
		Summary: strings.Repeat("s", summaryLen),
	}
	desc := strings.Repeat("d", descLen)
	for i := range required {
		ref.Inputs = append(ref.Inputs, apiref.Input{
			Name: fmt.Sprintf("R%03d", i), WireName: fmt.Sprintf("R%03d", i), Location: apiref.LocationBody,
			Required: true, Renderable: true, Type: "string", Description: desc,
		})
	}
	for i := range optional {
		ref.Inputs = append(ref.Inputs, apiref.Input{
			Name: fmt.Sprintf("O%03d", i), WireName: fmt.Sprintf("O%03d", i), Location: apiref.LocationBody,
			Renderable: true, Type: "string", Description: desc,
		})
	}

	return ref
}

func checkOptionalStage(t *testing.T, _ *apiref.Reference, got string) {
	t.Helper()
	var out struct {
		Reference struct {
			Inputs    []apiref.Input `json:"inputs"`
			Truncated bool           `json:"inputs_truncated"`
		} `json:"reference"`
	}
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Reference.Inputs) != 2 || !out.Reference.Truncated {
		t.Errorf("inputs %d truncated %v", len(out.Reference.Inputs), out.Reference.Truncated)
	}
	for _, in := range out.Reference.Inputs {
		if in.Description == "" || !in.Required {
			t.Errorf("input %+v", in)
		}
	}
}

func checkDescriptionStage(t *testing.T, _ *apiref.Reference, got string) {
	t.Helper()
	if strings.Contains(got, `"description"`) || !strings.Contains(got, `"summary"`) {
		t.Errorf("descriptions or summary wrong: %.200s", got)
	}
	if strings.Contains(got, `"inputs_truncated":true`) {
		t.Errorf("inputs_truncated set though no optional input was dropped: %.200s", got)
	}
}

func checkPresetTruncatedStage(t *testing.T, _ *apiref.Reference, got string) {
	t.Helper()
	if !strings.Contains(got, `"inputs_truncated":true`) {
		t.Errorf("the provider's inputs_truncated was lost: %.200s", got)
	}
}

func checkSummaryStage(t *testing.T, _ *apiref.Reference, got string) {
	t.Helper()
	if strings.Contains(got, `"summary"`) {
		t.Errorf("summary kept: %.200s", got)
	}
}

func checkMinimalStage(t *testing.T, _ *apiref.Reference, got string) {
	t.Helper()
	want := `{"outcome":"incomplete","connector":"aws","service":"svc","operation":"Op",` +
		`"limitations":["reference exceeds the output budget"]}`
	if got != want {
		t.Errorf("got %s", got)
	}
}

func TestAPIReference_CapStages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		ref   *apiref.Reference
		check func(t *testing.T, ref *apiref.Reference, got string)
	}{
		{"optional", bigRef(2, 40, 300, 10), checkOptionalStage},
		{"description", bigRef(30, 0, 300, 10), checkDescriptionStage},
		{"preset flag", presetTruncated(bigRef(30, 0, 300, 10)), checkPresetTruncatedStage},
		{"summary", bigRef(2, 0, 10, 9000), checkSummaryStage},
		{"minimal", bigRef(400, 0, 10, 10), checkMinimalStage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			full, _ := json.Marshal(referenceForSize(c.ref))
			if len(full) <= apiref.MaxOutputBytes {
				t.Fatalf("precondition: uncapped output is %d bytes", len(full))
			}
			inputs, summary, flag := len(c.ref.Inputs), c.ref.Summary, c.ref.InputsTruncated
			desc := c.ref.Inputs[0].Description
			p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeFound, Reference: c.ref}}
			got, _, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
			if len(got) > apiref.MaxOutputBytes {
				t.Errorf("output is %d bytes", len(got))
			}
			c.check(t, c.ref, got)
			if len(c.ref.Inputs) != inputs || c.ref.Summary != summary || c.ref.Inputs[0].Description != desc ||
				c.ref.InputsTruncated != flag {
				t.Error("the provider's reference was modified")
			}
		})
	}
}

// presetTruncated marks a reference the way a provider that already dropped inputs would.
func presetTruncated(ref *apiref.Reference) *apiref.Reference {
	ref.InputsTruncated = true

	return ref
}

// referenceForSize marshals a result the way the tool would before any cap.
func referenceForSize(ref *apiref.Reference) any {
	return struct {
		Reference *apiref.Reference `json:"reference"`
	}{ref}
}

func TestAPIReference_RenderingBranches(t *testing.T) {
	t.Parallel()

	ref := &apiref.Reference{
		Connector: "aws", Operation: "Op", Method: "POST", PathTemplate: "/op/{Id}",
		Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyForm,
		FixedQuery: []apiref.Param{{Key: "list-type", Value: "2"}, {Key: "flag"}},
		FixedForm:  []apiref.Param{{Key: "Action", Value: "X"}},
		Inputs: []apiref.Input{
			{Name: "Id", WireName: "Id", Location: apiref.LocationPath, Required: true},
			{Name: "MaxKeys", WireName: "max-keys", Location: apiref.LocationQuery, Required: true, Renderable: true},
			{Name: "Tok", WireName: "x-tok", Location: apiref.LocationHeader, Required: true, Renderable: true},
			{Name: "Name", WireName: "Name", Location: apiref.LocationBody, Required: true, Renderable: true},
			{Name: "Skip", WireName: "Skip", Location: apiref.LocationBody, Renderable: true},
		},
		AuthField: "aws_auth", AuthArgs: map[string]string{"service": "ex"},
	}
	p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: ref}}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
	args := templateArgs(t, out)
	if args.URL != "https://ex.amazonaws.com/op/<Id:unrendered>?list-type=2&flag&max-keys=<MaxKeys>" ||
		!hasHeader(args, "x-tok", "<Tok>") || args.Body != "Action=X&Name=<Name>" {
		t.Errorf("args = %+v", args)
	}

	none := &apiref.Reference{
		Connector: "aws", Operation: "Op2", Method: "POST", PathTemplate: "/", Endpoint: "https://ex.amazonaws.com",
		BodyEncoding: apiref.BodyNone,
		Inputs:       []apiref.Input{{Name: "Doc", WireName: "Doc", Location: apiref.LocationBody, Required: true}},
	}
	p = &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: none}}
	_, out, _ = runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op2"}`)
	if got := templateArgs(t, out).Body; got != "<Doc:unrendered>" {
		t.Errorf("body = %q", got)
	}
}

func TestAPIReference_PlaceholdersKeyedByLocation(t *testing.T) {
	t.Parallel()

	ref := &apiref.Reference{
		Connector: "aws", Operation: "Op", Method: "POST", PathTemplate: "/op/{id}",
		Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyJSON,
		Inputs: []apiref.Input{
			{Name: "id", WireName: "id", Location: apiref.LocationPath, Required: true, Renderable: true},
			{Name: "id", WireName: "id", Location: apiref.LocationBody, Required: true, Type: "string"},
			{Name: "q", WireName: "q", Location: apiref.LocationQuery, Required: true, Renderable: true},
			{Name: "q", WireName: "q", Location: apiref.LocationHeader, Required: true},
		},
	}
	p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: ref}}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
	args := templateArgs(t, out)
	if args.URL != "https://ex.amazonaws.com/op/<id>?q=<q>" || args.Body != `{"id":"<id:unrendered>"}` ||
		!hasHeader(args, "q", "<q:unrendered>") {
		t.Errorf("args = %+v", args)
	}
}

func TestAPIReference_PathLabelWithoutInputFallsBack(t *testing.T) {
	t.Parallel()

	ref := &apiref.Reference{
		Connector: "aws", Operation: "Op", Method: "GET", PathTemplate: "/op/{Id}",
		Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyNone,
	}
	p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: ref}}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
	if got := templateArgs(t, out).URL; got != "https://ex.amazonaws.com/op/<Id>" {
		t.Errorf("url = %q", got)
	}
}

func TestAPIReference_GreedyPathLabels(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, template string
		inputs         []apiref.Input
		want           string
	}{
		{
			"ordinary and greedy", "/{Bucket}/{Key+}",
			[]apiref.Input{
				{Name: "Bucket", WireName: "Bucket", Location: apiref.LocationPath, Required: true, Renderable: true},
				{Name: "Key", WireName: "Key", Location: apiref.LocationPath, Required: true, Renderable: true},
			},
			"https://ex.amazonaws.com/<Bucket>/<Key+>",
		},
		{"greedy without input", "/op/{Key+}", nil, "https://ex.amazonaws.com/op/<Key+>"},
		{
			"greedy unrendered", "/op/{Key+}",
			[]apiref.Input{{Name: "Key", WireName: "Key", Location: apiref.LocationPath, Required: true}},
			"https://ex.amazonaws.com/op/<Key+:unrendered>",
		},
		{
			"first path input wins", "/op/{Key+}",
			[]apiref.Input{
				{Name: "Key", WireName: "Key", Location: apiref.LocationPath, Required: true, Renderable: true},
				{Name: "Key", WireName: "Key", Location: apiref.LocationPath, Required: true},
			},
			"https://ex.amazonaws.com/op/<Key+>",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ref := &apiref.Reference{
				Connector: "aws", Operation: "Op", Method: "GET", PathTemplate: c.template,
				Endpoint: "https://ex.amazonaws.com", BodyEncoding: apiref.BodyNone, Inputs: c.inputs,
			}
			p := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeIncomplete, Reference: ref}}
			_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"aws","operation":"Op"}`)
			if got := templateArgs(t, out).URL; got != c.want {
				t.Errorf("url = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAPIReference_GitHubMultiSegmentLabelsStayUnmarked(t *testing.T) {
	t.Parallel()

	ref := &apiref.Reference{
		Connector: "github", Operation: "repos/get-branch-protection", Method: "GET",
		PathTemplate: "/repos/{owner}/{repo}/branches/{branch}/protection",
		Endpoint:     "https://api.github.com", BodyEncoding: apiref.BodyNone,
	}
	p := &docProvider{name: "github", res: apiref.Result{Outcome: apiref.OutcomeFound, Reference: ref}}
	_, out, _ := runRef(t, []auth.Provider{p}, `{"connector":"github","operation":"repos/get-branch-protection"}`)
	const want = "https://api.github.com/repos/<owner>/<repo>/branches/<branch>/protection"
	if got := templateArgs(t, out).URL; got != want {
		t.Errorf("url = %q", got)
	}

	ref = &apiref.Reference{
		Connector: "github", Operation: "repos/get-content", Method: "GET",
		PathTemplate: "/repos/{owner}/{repo}/contents/{path}",
		Endpoint:     "https://api.github.com", BodyEncoding: apiref.BodyNone,
	}
	p = &docProvider{name: "github", res: apiref.Result{Outcome: apiref.OutcomeFound, Reference: ref}}
	_, out, _ = runRef(t, []auth.Provider{p}, `{"connector":"github","operation":"repos/get-content"}`)
	const wantTrailing = "https://api.github.com/repos/<owner>/<repo>/contents/<path>"
	if got := templateArgs(t, out).URL; got != wantTrailing {
		t.Errorf("trailing url = %q", got)
	}
}

func TestAPIReference_NeverReturnsGoError(t *testing.T) {
	t.Parallel()

	tl := tools.NewAPIReferenceTool(nil)
	for _, args := range []string{``, `null`, `[]`, `{"operation":1}`, `{"operation":"x"}`} {
		if _, err := tl.Run(t.Context(), args); err != nil {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func TestAPIReferenceTool_IsUngatedIO(t *testing.T) {
	t.Parallel()

	marker, ok := tools.NewAPIReferenceTool(nil).(interface{ UngatedIO() })
	if !ok {
		t.Fatal("api_reference must implement UngatedIO so the agent audits it as ungated")
	}
	marker.UngatedIO()
}
