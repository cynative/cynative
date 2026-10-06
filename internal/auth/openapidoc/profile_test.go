package openapidoc_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// testProfile is a connector with no servers of its own: Distill ignores the document's servers.
func testProfile() openapidoc.Profile {
	return openapidoc.Profile{
		Connector:   "test",
		Protocol:    "rest-json",
		ScalarUnion: true,
		Paged:       func([]openapidoc.DocParam, []string) bool { return false },
		Refuse: func(loc apiref.Location, name string) bool {
			return (loc == apiref.LocationQuery && name == "token") || (loc == apiref.LocationHeader && name == "Sudo")
		},
	}
}

func distillTest(t *testing.T, doc string) *openapidoc.OperationDocs {
	t.Helper()
	d, err := openapidoc.Distill([]byte(doc), testProfile())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestProfile_ScalarUnion(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"paths":{"/x/{id}":{"get":{"operationId":"x","parameters":[
	{"name":"id","in":"path","required":true,"schema":{"oneOf":[{"type":"string"},{"type":"integer"}]}},
	{"name":"n","in":"query","schema":{"oneOf":[{"type":"integer","nullable":true},{"type":"string"}]}},
	{"name":"a","in":"query","schema":{"oneOf":[{"type":"array"},{"type":"string"}]}},
	{"name":"three","in":"query","schema":{"oneOf":[{"type":"string"},{"type":"integer"},{"type":"boolean"}]}},
	{"name":"one","in":"query","schema":{"oneOf":[{"type":"string"}]}},
	{"name":"odd","in":"query","schema":{"oneOf":"x"}}]}}}}`)
	ref := d.Reference(apiref.Query{Operation: "x"}, testProfile()).Reference
	want := map[string]string{
		"id": "string", "n": "string", "a": "unknown", "three": "unknown", "one": "unknown",
		"odd": "unknown",
	}
	for _, in := range ref.Inputs {
		if want[in.Name] != in.Type {
			t.Errorf("%s: type %q, want %q", in.Name, in.Type, want[in.Name])
		}
	}
	if len(ref.Inputs) != len(want) {
		t.Errorf("inputs = %+v", ref.Inputs)
	}
	off := testProfile()
	off.ScalarUnion = false
	d, err := openapidoc.Distill([]byte(`{"paths":{"/x":{"get":{"operationId":"x","parameters":[
	{"name":"id","in":"query","schema":{"oneOf":[{"type":"string"},{"type":"integer"}]}}]}}}}`), off)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Reference(apiref.Query{Operation: "x"}, off).Reference.Inputs[0].Type; got != "unknown" {
		t.Errorf("union rule applied while off: %q", got)
	}
}

func TestProfile_EmptyEndpointIgnoresServers(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"servers":[{"url":"https://{hostname}"}],"paths":{"/x":{"servers":[{"url":"https://p"}],
	"get":{"operationId":"x","servers":[{"url":"https://o"}]}}}}`)
	prof := testProfile()
	prof.Endpoint = "https://gitlab.example:8443"
	res := d.Reference(apiref.Query{Operation: "x"}, prof)
	if res.Outcome != apiref.OutcomeFound || res.Reference.Endpoint != "https://gitlab.example:8443" ||
		d.Ops["x"].Server != "" {
		t.Errorf("res = %+v op = %+v", res, d.Ops["x"])
	}
}

func TestProfile_RecordedGapsAndAltRoutes(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"paths":{"/a/{id}/b":{"get":{"operationId":"x"}}}}`)
	op := d.Ops["x"]
	op.Gaps = []string{"rendered path is not admitted"}
	op.Alt = []string{"/a/{id}/-/b"}
	d.Ops["x"] = op
	res := d.Reference(apiref.Query{Operation: "x"}, testProfile())
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, op.Gaps) {
		t.Errorf("res = %+v", res)
	}
	got := d.Routes()
	slices.SortFunc(got, func(a, b apiref.Route) int { return strings.Compare(a.Template, b.Template) })
	want := []apiref.Route{
		{Operation: "x", Method: "GET", Template: "/a/{id}/-/b"},
		{Operation: "x", Method: "GET", Template: "/a/{id}/b"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("routes = %+v", got)
	}
	back, err := openapidoc.Unmarshal(d.Serialize())
	if err != nil || !slices.Equal(back.Ops["x"].Alt, op.Alt) || !slices.Equal(back.Ops["x"].Gaps, op.Gaps) {
		t.Errorf("round trip lost Alt or Gaps: %+v %v", back, err)
	}
}

func TestProfile_RefusedInputs(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"paths":{"/r":{"delete":{"operationId":"x","parameters":[
	{"name":"token","in":"query","required":true,"schema":{"type":"string"}},
	{"name":"Sudo","in":"header","schema":{"type":"string"}},
	{"name":"keep","in":"query","schema":{"type":"string"}}]}}}}`)
	res := d.Reference(apiref.Query{Operation: "x"}, testProfile())
	want := "required input token is a credential the test connector refuses"
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, []string{want}) {
		t.Errorf("res = %+v", res)
	}
	if len(res.Reference.Inputs) != 1 || res.Reference.Inputs[0].Name != "keep" {
		t.Errorf("inputs = %+v", res.Reference.Inputs)
	}
}

func TestProfile_RefusedOptionalInputsDoNotCountTowardTheLimit(t *testing.T) {
	t.Parallel()
	params := make([]string, 0, apiref.MaxOptionalInputs+1)
	params = append(params, `{"name":"Sudo","in":"header","schema":{"type":"string"}}`)
	for i := range apiref.MaxOptionalInputs {
		params = append(params, `{"name":"p`+string(rune('a'+i))+`","in":"query","schema":{"type":"string"}}`)
	}
	d := distillTest(t, `{"paths":{"/r":{"get":{"operationId":"x","parameters":[`+strings.Join(params, ",")+`]}}}}`)
	ref := d.Reference(apiref.Query{Operation: "x"}, testProfile()).Reference
	if len(ref.Inputs) != apiref.MaxOptionalInputs || ref.InputsTruncated {
		t.Errorf("inputs = %d truncated = %v", len(ref.Inputs), ref.InputsTruncated)
	}
}

func TestProfile_UnspecifiedResponse(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"paths":{"/state":{"get":{"operationId":"bare","responses":{"200":{"description":"ok"}}}},
	"/json":{"get":{"operationId":"json","responses":{"200":{"content":{"application/json":{}}}}}}}}`)
	const limit = "the document does not describe this operation's response format; check the Content-Type " +
		"response header before parsing"
	prof := testProfile()
	prof.UnspecifiedResponse = true
	ref := d.Reference(apiref.Query{Operation: "bare"}, prof).Reference
	if ref.Response.Encoding != "unspecified" || !slices.Equal(ref.Limitations, []string{limit}) {
		t.Errorf("response %+v limitations %q", ref.Response, ref.Limitations)
	}
	if ref = d.Reference(apiref.Query{Operation: "json"}, prof).Reference; ref.Response.Encoding != "json" ||
		len(ref.Limitations) != 0 {
		t.Errorf("a described response changed: %+v %q", ref.Response, ref.Limitations)
	}
	// Off, as for GitHub, a contentless response still reads as no body.
	if ref = d.Reference(apiref.Query{Operation: "bare"}, testProfile()).Reference; ref.Response.Encoding != "none" {
		t.Errorf("response = %+v", ref.Response)
	}
}
