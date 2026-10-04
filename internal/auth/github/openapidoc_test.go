package github_test

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/github"
)

func inputNamed(ref *apiref.Reference, name string) (apiref.Input, bool) {
	for _, in := range ref.Inputs {
		if in.Name == name {
			return in, true
		}
	}
	return apiref.Input{}, false
}

func fixtureDocs(t *testing.T) *github.OperationDocs {
	t.Helper()
	raw, err := os.ReadFile("testdata/openapi-docs.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := github.DistillDocs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func synthDocs(t *testing.T, doc string) *github.OperationDocs {
	t.Helper()
	d, err := github.DistillDocs([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ghView(t *testing.T, method, rawURL string) authreq.View {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return authreq.View{Method: method, Hostname: u.Hostname(), Path: u.Path, EscapedPath: u.EscapedPath()}
}

func TestDocsReference_ReposGet(t *testing.T) {
	t.Parallel()
	res := fixtureDocs(t).Reference(apiref.Query{Connector: "github", Operation: "repos/get"})
	ref := res.Reference
	if res.Outcome != apiref.OutcomeFound || ref.Method != http.MethodGet ||
		ref.PathTemplate != "/repos/{owner}/{repo}" ||
		ref.Endpoint != "https://api.github.com" ||
		ref.BodyEncoding != apiref.BodyNone {
		t.Fatalf("res = %+v ref = %+v", res, ref)
	}
	owner, ok := inputNamed(ref, "owner")
	if !ok || owner.Location != apiref.LocationPath || !owner.Required || !owner.Renderable {
		t.Errorf("owner = %+v", owner)
	}
	if ref.Pagination.Style != apiref.PaginationUnspecified || ref.Source.SHA256 == "" || ref.Source.Version == "" {
		t.Errorf("pagination %+v source %+v", ref.Pagination, ref.Source)
	}
	if !slices.Contains(ref.FixedHeaders, apiref.Param{Key: "Accept", Value: "application/vnd.github+json"}) {
		t.Errorf("headers = %+v", ref.FixedHeaders)
	}
	if ref.Source.Name != "github/rest-api-description" || ref.APIVersion != "" || ref.Protocol != "rest-json" ||
		ref.Connector != "github" || ref.Operation != "repos/get" {
		t.Errorf("ref = %+v", ref)
	}
	if !slices.Contains(ref.Limitations,
		"the connector strips X-GitHub-Api-Version, so the server's default API version applies") {
		t.Errorf("limitations = %+v", ref.Limitations)
	}
}

func TestDocsReference_ListForRepoIsLinkPaged(t *testing.T) {
	t.Parallel()
	ref := fixtureDocs(t).Reference(apiref.Query{Operation: "issues/list-for-repo"}).Reference
	if ref.Pagination.Style != "link-header" || ref.Pagination.PageSize != "per_page" ||
		ref.Pagination.InputToken != "page" {
		t.Errorf("pagination = %+v", ref.Pagination)
	}
	if len(ref.Limitations) != 2 {
		t.Errorf("limitations = %+v", ref.Limitations)
	}
	if ref.Response.Encoding != "json" || ref.Response.Parse != "JSON.parse(response.body)" {
		t.Errorf("response = %+v", ref.Response)
	}
}

func TestDocsReference_MarkdownRenderBody(t *testing.T) {
	t.Parallel()
	res := fixtureDocs(t).Reference(apiref.Query{Operation: "markdown/render"})
	in, ok := inputNamed(res.Reference, "text")
	if res.Outcome != apiref.OutcomeFound || res.Reference.BodyEncoding != apiref.BodyJSON ||
		!ok || in.Location != apiref.LocationBody || !in.Required {
		t.Errorf("res = %+v", res)
	}
	if res.Reference.Response.Encoding != "text/html" ||
		!strings.Contains(res.Reference.Response.Parse, "not JSON") {
		t.Errorf("response = %+v", res.Reference.Response)
	}
	if !slices.Contains(res.Reference.FixedHeaders, apiref.Param{Key: "Content-Type", Value: "application/json"}) {
		t.Errorf("headers = %+v", res.Reference.FixedHeaders)
	}
}

func TestDocsReference_IssuesCreateIsIncomplete(t *testing.T) {
	t.Parallel()
	// title is oneOf string/integer in the vendor document.
	res := fixtureDocs(t).Reference(apiref.Query{Operation: "issues/create"})
	title, ok := inputNamed(res.Reference, "title")
	if res.Outcome != apiref.OutcomeIncomplete || !ok || title.Renderable || title.Location != apiref.LocationBody {
		t.Errorf("res = %+v", res)
	}
	want := "required input title (unknown in body) cannot be rendered"
	if !slices.Contains(res.Reference.Gaps, want) {
		t.Errorf("gaps = %+v", res.Reference.Gaps)
	}
}

const synthHead = `{"info":{"version":"9"},"paths":{`

func TestDocsReference_RefBodySchema(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/things":{"post":{"operationId":"things/create","summary":"<b>Make</b> one",
	"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Thing"}}}},
	"responses":{"204":{"description":"none"}}}}},
	"components":{"schemas":{"Thing":{"type":"object","required":["name","size","tags","ghost"],
	"properties":{"name":{"type":"string","description":"The <i>name</i>"},"size":{"type":"integer"},
	"tags":{"type":"array"},"opt":{"type":"string"}}}}}}`)
	res := d.Reference(apiref.Query{Operation: "things/create"})
	name, ok := inputNamed(res.Reference, "name")
	if !ok || !name.Required || !name.Renderable || name.Description != "The name" {
		t.Errorf("name = %+v", name)
	}
	if _, found := inputNamed(res.Reference, "opt"); found {
		t.Errorf("optional body property listed")
	}
	if res.Outcome != apiref.OutcomeIncomplete || len(res.Reference.Gaps) != 2 ||
		res.Reference.Summary != "Make one" {
		t.Errorf("res = %+v", res)
	}
	if res.Reference.Response.Encoding != "none" || res.Reference.Response.Parse !=
		"no response body; read the status and headers" {
		t.Errorf("response = %+v", res.Reference.Response)
	}
}

func TestDocsReference_RefBodySchemaFound(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/things":{"post":{"operationId":"things/create",
	"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Thing"}}}}}}},
	"components":{"schemas":{"Thing":{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}}}}`)
	res := d.Reference(apiref.Query{Operation: "things/create"})
	if _, ok := inputNamed(res.Reference, "name"); !ok || res.Outcome != apiref.OutcomeFound {
		t.Errorf("res = %+v", res)
	}
}

func TestDocsReference_BodyGaps(t *testing.T) {
	t.Parallel()
	const gap = "request body is not a JSON object the template can render"
	cases := map[string]string{
		"text/plain required": `"requestBody":{"required":true,"content":{"text/plain":{}}}`,
		"ref body":            `"requestBody":{"required":true,"$ref":"#/components/requestBodies/X"}`,
		"non-object":          `"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"array"}}}}`,
		"missing schema ref": `"requestBody":{"required":true,"content":{"application/json":{"schema":` +
			`{"$ref":"#/components/schemas/Nope"}}}}`,
		"foreign schema ref": `"requestBody":{"required":true,"content":{"application/json":{"schema":` +
			`{"$ref":"#/other/Nope"}}}}`,
		"malformed schema ref": `"requestBody":{"required":true,"content":{"application/json":{"schema":` +
			`{"$ref":"#/components/schemas/Bad"}}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := synthDocs(t, synthHead+`"/x":{"post":{"operationId":"x/post",`+body+`}}},
			"components":{"schemas":{"Bad":{"required":"oops"}}}}`)
			res := d.Reference(apiref.Query{Operation: "x/post"})
			in, ok := inputNamed(res.Reference, "body")
			if res.Outcome != apiref.OutcomeIncomplete || !ok || in.Renderable || !in.Required ||
				in.Location != apiref.LocationBody || in.Type != "unknown" || !slices.Contains(res.Reference.Gaps, gap) {
				t.Errorf("res = %+v", res)
			}
			if res.Reference.BodyEncoding != apiref.BodyNone {
				t.Errorf("encoding = %s", res.Reference.BodyEncoding)
			}
		})
	}
}

func TestDocsReference_OptionalUnrenderedBodyIsNoGap(t *testing.T) {
	t.Parallel()
	const limit = "optional request body is not rendered"
	cases := map[string]string{
		"text/plain":     `"requestBody":{"content":{"text/plain":{}}}`,
		"ref body":       `"requestBody":{"$ref":"#/components/requestBodies/X"}`,
		"non-object":     `"requestBody":{"content":{"application/json":{"schema":{"type":"array"}}}}`,
		"untyped schema": `"requestBody":{"content":{"application/json":{"schema":{"description":"d"}}}}`,
		"malformed ref":  `"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Bad"}}}}`,
		"missing ref":    `"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Nope"}}}}`,
		"object with required scalar": `"requestBody":{"content":{"application/json":{"schema":{"type":"object",` +
			`"required":["a"],"properties":{"a":{"type":"string"}}}}}}`,
		"object with required non-scalar": `"requestBody":{"content":{"application/json":{"schema":{"type":"object",` +
			`"required":["a"],"properties":{"a":{"type":"array"}}}}}}`,
		"explicit false": `"requestBody":{"required":false,"content":{"application/json":{"schema":{"type":"array"}}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := synthDocs(t, synthHead+`"/x":{"get":{"operationId":"x/get",`+body+`}}},
			"components":{"schemas":{"Bad":{"required":"oops"}}}}`)
			res := d.Reference(apiref.Query{Operation: "x/get"})
			if res.Outcome != apiref.OutcomeFound || len(res.Reference.Inputs) != 0 || len(res.Reference.Gaps) != 0 ||
				!slices.Contains(res.Reference.Limitations, limit) || res.Reference.BodyEncoding != apiref.BodyNone {
				t.Errorf("res = %+v", res)
			}
		})
	}
}

func TestDocsReference_RequiredBodyWithoutRequiredFieldsIsJSON(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/x":{"post":{"operationId":"x/post",
	"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object",`+
		`"properties":{"a":{"type":"string"}}}}}}}}}}`)
	ref := d.Reference(apiref.Query{Operation: "x/post"}).Reference
	hasType := slices.Contains(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: "application/json"})
	if ref.BodyEncoding != apiref.BodyJSON || !hasType || len(ref.Inputs) != 0 {
		t.Errorf("ref = %+v", ref)
	}
}

func TestDocsReference_OptionalObjectBodyWithoutRequiredIsSilent(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/x":{"post":{"operationId":"x/post",
	"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"a":{"type":"string"}}}}}}}}}}`)
	res := d.Reference(apiref.Query{Operation: "x/post"})
	if res.Outcome != apiref.OutcomeFound || len(res.Reference.Limitations) != 1 {
		t.Errorf("res = %+v", res)
	}
}

func TestDocsDistill_MalformedInlineSchemaOnlyAffectsItsOperation(t *testing.T) {
	t.Parallel()
	const bad = `{"type":"object","required":"oops","properties":{"a":{"type":"string"}}}`
	d := synthDocs(t, synthHead+`
	"/req":{"post":{"operationId":"req/post",
		"requestBody":{"required":true,"content":{"application/json":{"schema":`+bad+`}}}}},
	"/opt":{"post":{"operationId":"opt/post",
		"requestBody":{"content":{"application/json":{"schema":`+bad+`}}}}},
	"/propdesc":{"post":{"operationId":"propdesc/post",
		"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object",
		"required":["a"],"properties":{"a":{"type":"string","description":7}}}}}}}},
	"/good":{"post":{"operationId":"good/post",
		"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object",
		"required":["a"],"properties":{"a":{"type":"string"}}}}}}}}}}`)
	for _, id := range []string{"req/post", "propdesc/post"} {
		res := d.Reference(apiref.Query{Operation: id})
		if res.Outcome != apiref.OutcomeIncomplete ||
			!slices.Contains(res.Reference.Gaps, "request body is not a JSON object the template can render") {
			t.Errorf("%s: res = %+v", id, res)
		}
	}
	res := d.Reference(apiref.Query{Operation: "opt/post"})
	if res.Outcome != apiref.OutcomeFound ||
		!slices.Contains(res.Reference.Limitations, "optional request body is not rendered") {
		t.Errorf("opt/post: res = %+v", res)
	}
	if good := d.Reference(apiref.Query{Operation: "good/post"}); good.Outcome != apiref.OutcomeFound ||
		good.Reference.BodyEncoding != apiref.BodyJSON {
		t.Errorf("good/post: res = %+v", good)
	}
}

func TestDocsDistill_OddParameterValuesDegradeOnlyThatField(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/x":{"get":{"operationId":"x/get","parameters":[
		{"name":"a","in":"query","required":true,"description":7,"schema":{"type":"string"}},
		{"name":"b","in":"query","description":"fine","schema":"oops"},
		{"name":5,"in":["q"],"required":"yes","schema":null}]}}}}`)
	res := d.Reference(apiref.Query{Operation: "x/get"})
	if res.Outcome != apiref.OutcomeFound {
		t.Fatalf("res = %+v", res)
	}
	a, ok := inputNamed(res.Reference, "a")
	if !ok || a.Description != "" || !a.Required || a.Type != "string" {
		t.Errorf("a = %+v", a)
	}
	b, ok := inputNamed(res.Reference, "b")
	if !ok || b.Description != "fine" || b.Type != "unknown" || b.Required {
		t.Errorf("b = %+v", b)
	}
}

func TestDocsDistill_MalformedUnreferencedSchemaIsIgnored(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/x":{"get":{"operationId":"x/get"}}},
	"components":{"schemas":{"Bad":{"required":"oops"}}}}`)
	if res := d.Reference(apiref.Query{Operation: "x/get"}); res.Outcome != apiref.OutcomeFound {
		t.Errorf("res = %+v", res)
	}
}

func TestDocsReference_OperationParamOverridesPathParam(t *testing.T) {
	t.Parallel()
	d := synthDocs(
		t,
		synthHead+`"/x":{"parameters":[{"name":"q","in":"query","description":"path","schema":{"type":"string"}},
	{"name":"keep","in":"query","schema":{"type":"string"}}],
	"get":{"operationId":"x/get","parameters":[{"name":"q","in":"query","schema":{"type":"integer"}},
	{"name":"q","in":"header","schema":{"type":"string"}}]}}}}`,
	)
	ref := d.Reference(apiref.Query{Operation: "x/get"}).Reference
	var qs []apiref.Input
	for _, in := range ref.Inputs {
		if in.Name == "q" && in.Location == apiref.LocationQuery {
			qs = append(qs, in)
		}
	}
	if len(qs) != 1 || qs[0].Type != "integer" || qs[0].Description != "" || len(ref.Inputs) != 3 ||
		ref.Inputs[0].Name != "q" {
		t.Errorf("inputs = %+v", ref.Inputs)
	}
}

func TestDocsReference_Params(t *testing.T) {
	t.Parallel()
	d := synthDocs(
		t,
		synthHead+`"/x/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
	{"$ref":"#/components/parameters/q"},{"$ref":"#/elsewhere/q"},{"$ref":"#/components/parameters/missing"}],
	"get":{"operationId":"x/get","parameters":[{"name":"X-Trace","in":"header","schema":{"type":"string"}},
	{"name":"ids","in":"query","required":true,"schema":{"type":"array"}},
	{"name":"c","in":"cookie","schema":{"type":"string"}},
	{"name":"typeless","in":"query","schema":{"type":["string","null"]}}]}}},
	"components":{"parameters":{"q":{"name":"q","in":"query","schema":{"type":"boolean"}}}}}`,
	)
	res := d.Reference(apiref.Query{Operation: "x/get"})
	ref := res.Reference
	hdr, ok := inputNamed(ref, "X-Trace")
	if !ok || hdr.Location != apiref.LocationHeader || !hdr.Renderable {
		t.Errorf("hdr = %+v", hdr)
	}
	if q, found := inputNamed(ref, "q"); !found || q.Location != apiref.LocationQuery || q.Type != "boolean" {
		t.Errorf("q = %+v", q)
	}
	if tl, found := inputNamed(ref, "typeless"); !found || tl.Type != "unknown" || tl.Renderable {
		t.Errorf("typeless = %+v", tl)
	}
	if _, found := inputNamed(ref, "c"); found {
		t.Errorf("cookie param listed")
	}
	if res.Outcome != apiref.OutcomeIncomplete ||
		!slices.Contains(ref.Gaps, "required input ids (array in query) cannot be rendered") {
		t.Errorf("res = %+v", res)
	}
	if ref.Inputs[0].Location != apiref.LocationPath ||
		ref.Inputs[len(ref.Inputs)-1].Location != apiref.LocationHeader {
		t.Errorf("inputs = %+v", ref.Inputs)
	}
}

func TestDocsReference_OptionalInputsTruncated(t *testing.T) {
	t.Parallel()
	var params []string
	for i := range 30 {
		params = append(params, `{"name":"p`+strconv.Itoa(i)+`","in":"query","schema":{"type":"string"}}`)
	}
	d := synthDocs(t, synthHead+`"/x":{"get":{"operationId":"x/get","parameters":[`+strings.Join(params, ",")+`]}}}}`)
	ref := d.Reference(apiref.Query{Operation: "x/get"}).Reference
	if len(ref.Inputs) != apiref.MaxOptionalInputs || !ref.InputsTruncated {
		t.Errorf("inputs = %d truncated = %v", len(ref.Inputs), ref.InputsTruncated)
	}
}

func TestDocsReference_ResponseTypes(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`
	"/scim":{"get":{"operationId":"scim/get","responses":{"200":{"content":{"application/scim+json":{}}}}}},
	"/created":{"get":{"operationId":"created/get","responses":{"204":{"description":"x"},
	"201":{"content":{"text/zeta":{},"text/alpha":{}}},"302":{"content":{"a/b":{}}}}}},
	"/empty200":{"get":{"operationId":"empty/get","responses":{"200":{"description":"x"},
	"202":{"content":{"application/json":{}}}}}},
	"/both":{"get":{"operationId":"both/get","responses":{"200":{"description":"x"},
	"201":{"content":{"application/json":{}}}}}},
	"/only201":{"get":{"operationId":"only201/get","responses":{"201":{"content":{"application/json":{}}}}}},
	"/nothing":{"get":{"operationId":"nothing/get","responses":{"404":{"content":{"a/b":{}}}}}},
	"/bare":{"get":{"operationId":"bare/get"}}}}`)
	cases := map[string][2]string{
		"scim/get":    {"json", "JSON.parse(response.body)"},
		"created/get": {"text/alpha", "the body is text/alpha text, not JSON; read response.body as a string"},
		"empty/get":   {"none", "no response body; read the status and headers"},
		"both/get":    {"none", "no response body; read the status and headers"},
		"only201/get": {"json", "JSON.parse(response.body)"},
		"nothing/get": {"none", "no response body; read the status and headers"},
		"bare/get":    {"none", "no response body; read the status and headers"},
	}
	for op, want := range cases {
		got := d.Reference(apiref.Query{Operation: op}).Reference.Response
		if got.Encoding != want[0] || got.Parse != want[1] {
			t.Errorf("%s: response = %+v", op, got)
		}
	}
}

func TestDocsReference_LinkNeedsBothParamsAndHeader(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`
	"/nolink":{"get":{"operationId":"nolink/get","parameters":[{"name":"per_page","in":"query"},{"name":"page","in":"query"}],
	"responses":{"200":{"headers":{"X":{}}}}}},
	"/noparams":{"get":{"operationId":"noparams/get","responses":{"200":{"headers":{"Link":{}}}}}},
	"/onlyper":{"get":{"operationId":"onlyper/get","parameters":[{"name":"per_page","in":"query"}],
	"responses":{"200":{"headers":{"Link":{}}}}}}}}`)
	for _, op := range []string{"nolink/get", "noparams/get", "onlyper/get"} {
		if s := d.Reference(apiref.Query{Operation: op}).Reference.Pagination.Style; s != apiref.PaginationUnspecified {
			t.Errorf("%s style = %s", op, s)
		}
	}
}

func TestDocsReference_Lookup(t *testing.T) {
	t.Parallel()
	d := fixtureDocs(t)
	if res := d.Reference(apiref.Query{Operation: "nope/none"}); res.Outcome != apiref.OutcomeNotFound ||
		res.Reason == "" {
		t.Errorf("res = %+v", res)
	}
	res := d.Reference(apiref.Query{Operation: "REPOS/GET"})
	if res.Outcome != apiref.OutcomeFound || res.Reference.Operation != "repos/get" {
		t.Errorf("res = %+v", res)
	}
	amb := synthDocs(t, synthHead+`"/a":{"get":{"operationId":"a/x"}},"/b":{"get":{"operationId":"A/X"}},
	"/c":{"get":{"operationId":"A/x"}},"/d":{"get":{"operationId":"a/Y"}},"/e":{"get":{"operationId":"A/Y"}},
	"/f":{"get":{"operationId":"a/z"}},"/g":{"get":{"operationId":"A/z"}},"/h":{"get":{"operationId":"a/W"}}}}`)
	res = amb.Reference(apiref.Query{Operation: "a/X"})
	if res.Outcome != apiref.OutcomeAmbiguous || !slices.Equal(res.Choices, []string{"A/X", "A/x", "a/x"}) {
		t.Errorf("res = %+v", res)
	}
	if exact := amb.Reference(apiref.Query{Operation: "a/x"}); exact.Outcome != apiref.OutcomeFound {
		t.Errorf("exact match must win: %+v", exact)
	}
}

func TestDocsReference_AmbiguousChoicesAreBounded(t *testing.T) {
	t.Parallel()
	var ops []string
	for i, id := range []string{"abcdefg", "Abcdefg", "aBcdefg", "abCdefg", "abcDefg", "abcdEfg", "abcdeFg"} {
		ops = append(ops, `"/p`+strconv.Itoa(i)+`":{"get":{"operationId":"`+id+`"}}`)
	}
	d := synthDocs(t, synthHead+strings.Join(ops, ",")+`}}`)
	res := d.Reference(apiref.Query{Operation: "ABCDEFG"})
	if res.Outcome != apiref.OutcomeAmbiguous || len(res.Choices) != apiref.MaxChoices {
		t.Errorf("res = %+v", res)
	}
}

func TestDocsReference_ChoicesTruncated(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", apiref.MaxChoice+10)
	d := synthDocs(t, synthHead+`"/p":{"get":{"operationId":"`+long+`"}},"/q":{"get":{"operationId":"`+
		strings.ToUpper(long)+`"}}}}`)
	res := d.Reference(apiref.Query{Operation: strings.ToUpper(long[:1]) + long[1:]})
	if res.Outcome != apiref.OutcomeAmbiguous || len([]rune(res.Choices[0])) != apiref.MaxChoice {
		t.Errorf("res = %+v", res)
	}
}

func TestDocs_RoundTrip(t *testing.T) {
	t.Parallel()
	d := fixtureDocs(t)
	back, err := github.UnmarshalDocs(d.Serialize())
	if err != nil || !reflect.DeepEqual(d, back) {
		t.Errorf("err = %v, round trip differs", err)
	}
	if d.Version == "" || len(d.SHA256) != 64 {
		t.Errorf("version %q sha %q", d.Version, d.SHA256)
	}
}

func TestDocs_Rejects(t *testing.T) {
	t.Parallel()
	if _, err := github.UnmarshalDocs([]byte("{")); !errors.Is(err, github.ErrDocsRejected) {
		t.Errorf("err = %v", err)
	}
	if err := github.AdmitDocs(&github.OperationDocs{}); !errors.Is(err, github.ErrDocsRejected) {
		t.Errorf("err = %v", err)
	}
	if err := github.AdmitDocs(fixtureDocs(t)); err != nil {
		t.Errorf("err = %v", err)
	}
	for _, raw := range []string{"not json", `{"paths":{}}`, `{"paths":{"/a":{"get":"x"}}}`, `{"paths":{"/a":{"get":{}}}}`} {
		if _, err := github.DistillDocs([]byte(raw)); !errors.Is(err, github.ErrDocsRejected) {
			t.Errorf("%s: err = %v", raw, err)
		}
	}
}

func TestDocsHint(t *testing.T) {
	t.Parallel()
	d := fixtureDocs(t)
	v := ghView(t, "DELETE", "https://api.github.com/repos/o/r")
	h := d.Hint(v)
	if !slices.Equal(h.Candidates, []string{"repos/get (GET /repos/{owner}/{repo})"}) || h.Operation != "repos/get" {
		t.Errorf("hint = %+v", h)
	}
	if none := d.Hint(ghView(t, "GET", "https://api.github.com/nope/x/y/z")); len(none.Candidates) != 0 ||
		none.Operation != "" {
		t.Errorf("hint = %+v", none)
	}
	h = d.Hint(ghView(t, "DELETE", "https://api.github.com/repos/o/r/issues"))
	if len(h.Candidates) != 2 || h.Operation != "" {
		t.Errorf("hint = %+v", h)
	}
}

func TestDocsHint_MultiSegmentTail(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/repos/{owner}/{repo}/contents/{path}":{"get":{"operationId":"repos/get-content",
	"parameters":[{"name":"owner","in":"path","required":true,"schema":{"type":"string"}},
	{"name":"path","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}],
	"responses":{"200":{"description":"ok"}}}},
	"/repos/{owner}/{repo}/tags/{tag}":{"get":{"operationId":"repos/get-tag",
	"responses":{"200":{"description":"ok"}}}}}}`)
	if !slices.Equal(d.MultiSegment, []string{"path"}) {
		t.Fatalf("MultiSegment = %v", d.MultiSegment)
	}
	h := d.Hint(ghView(t, "PUT", "https://api.github.com/repos/o/r/contents/a/b/c"))
	want := []string{"repos/get-content (GET /repos/{owner}/{repo}/contents/{path*})"}
	if !slices.Equal(h.Candidates, want) || h.Operation != "repos/get-content" {
		t.Errorf("hint = %+v", h)
	}
	if none := d.Hint(ghView(t, "PUT", "https://api.github.com/repos/o/r/tags/a/b")); len(none.Candidates) != 0 {
		t.Errorf("single-segment tail matched several segments: %+v", none)
	}
}

func TestDocsHint_HeadAndOptionsReadAsGet(t *testing.T) {
	t.Parallel()
	d := fixtureDocs(t)
	for _, m := range []string{"HEAD", "OPTIONS", "head", " Options "} {
		h := d.Hint(ghView(t, m, "https://api.github.com/repo/o/r"))
		if !slices.Equal(h.Candidates, []string{"repos/get (GET /repos/{owner}/{repo})"}) {
			t.Errorf("%q: hint = %+v", m, h)
		}
	}
}

func TestDocsHint_CatchAllTakesZeroSegments(t *testing.T) {
	t.Parallel()
	d := synthDocs(t, synthHead+`"/repos/{owner}/{repo}/contents/{path}":{"get":{"operationId":"repos/get-content",
	"parameters":[{"name":"path","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}],
	"responses":{"200":{"description":"ok"}}}}}}`)
	h := d.Hint(ghView(t, "PUT", "https://api.github.com/repos/o/r/contents"))
	want := []string{"repos/get-content (GET /repos/{owner}/{repo}/contents/{path*})"}
	if !slices.Equal(h.Candidates, want) {
		t.Errorf("hint = %+v", h)
	}
}

func TestDocsReference_ServerOverride(t *testing.T) {
	t.Parallel()
	d := synthDocs(
		t,
		synthHead+`"/p":{"servers":[{"url":"https://path.example/"}],
	"get":{"operationId":"p/get"},
	"post":{"operationId":"p/post","servers":[{"url":"https://op.example/{v}/"}]}},
	"/n":{"get":{"operationId":"n/get","servers":[]}}}}`,
	)
	cases := []struct{ op, endpoint string }{
		{"p/get", "https://path.example"},
		{"p/post", "https://op.example/{v}"},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			t.Parallel()
			res := d.Reference(apiref.Query{Operation: c.op})
			want := "operation is served from " + c.endpoint + ", which the github connector does not authorize"
			if res.Outcome != apiref.OutcomeIncomplete || res.Reference.Endpoint != c.endpoint ||
				!slices.Equal(res.Reference.Gaps, []string{want}) {
				t.Errorf("endpoint %q gaps %q outcome %q", res.Reference.Endpoint, res.Reference.Gaps, res.Outcome)
			}
		})
	}
	res := d.Reference(apiref.Query{Operation: "n/get"})
	if res.Outcome != apiref.OutcomeFound || res.Reference.Endpoint != "https://api.github.com" ||
		len(res.Reference.Gaps) != 0 {
		t.Errorf("default endpoint: %+v", res)
	}
}

func TestDocsReference_DocumentAndDefaultServers(t *testing.T) {
	t.Parallel()
	root := synthDocs(t, `{"info":{"version":"9"},"servers":[{"url":"https://ghe.example/api/v3"}],
	"paths":{"/r":{"get":{"operationId":"r/get"},
	"post":{"operationId":"r/post","servers":[{"url":"https://api.github.com/"}]}}}}`)
	res := root.Reference(apiref.Query{Operation: "r/get"})
	want := "operation is served from https://ghe.example/api/v3, which the github connector does not authorize"
	if res.Outcome != apiref.OutcomeIncomplete || res.Reference.Endpoint != "https://ghe.example/api/v3" ||
		!slices.Equal(res.Reference.Gaps, []string{want}) {
		t.Errorf("document server: %+v", res)
	}
	res = root.Reference(apiref.Query{Operation: "r/post"})
	if res.Outcome != apiref.OutcomeFound || res.Reference.Endpoint != "https://api.github.com" ||
		len(res.Reference.Gaps) != 0 {
		t.Errorf("explicit default server: %+v", res)
	}
}
