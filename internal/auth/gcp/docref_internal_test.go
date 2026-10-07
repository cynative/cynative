package gcp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// fixtureStems are the trimmed Discovery documents under testdata/discovery.
var fixtureStems = []string{ //nolint:gochecknoglobals // immutable test table.
	"aiplatform.v1", "cloudresourcemanager.v1", "cloudresourcemanager.v3", "compute.stable", "compute.v1",
	"storage.v1", "synth.v1",
}

func reference(t *testing.T, stem, id string) *apiref.Reference {
	t.Helper()
	d := distilled(t, stem)
	if _, ok := d.Methods[id]; !ok {
		t.Fatalf("%s has no method %s", stem, id)
	}
	return buildReference(d, id)
}

// pathInputs renders a reference's path inputs as "name|type|renderable|description" lines.
func pathInputs(ref *apiref.Reference) []string {
	var out []string
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationPath {
			if !in.Required {
				out = append(out, in.Name+" optional")
				continue
			}
			r := "renderable"
			if !in.Renderable {
				r = "unrendered"
			}
			out = append(out, in.Name+"|"+in.Type+"|"+r+"|"+in.Description)
		}
	}
	return out
}

func TestRenderPath(t *testing.T) {
	t.Parallel()
	const (
		ai       = "aiplatform.projects.locations.endpoints."
		location = "one segment of parent, which has the form projects/[^/]+/locations/[^/]+"
		endpoint = "one segment of endpoint, which has the form projects/[^/]+/locations/[^/]+/endpoints/[^/]+"
	)
	for _, tc := range []struct {
		stem, id, path string
		inputs         []string
	}{
		{"aiplatform.v1", ai + "list", "/v1/projects/{projectsId}/locations/{locationsId}/endpoints", []string{
			"projectsId|string|renderable|" + location, "locationsId|string|renderable|" + location,
		}},
		{"aiplatform.v1", ai + "predict", "/v1/projects/{projectsId}/locations/{locationsId}/endpoints/" +
			"{endpointsId}:predict", []string{
			"projectsId|string|renderable|" + endpoint, "locationsId|string|renderable|" + endpoint,
			"endpointsId|string|renderable|" + endpoint,
		}},
		// Two reserved expansions: {+endpoint} is replaced by synthetic labels and not listed, while {+invokeId},
		// which flatPath keeps as {invokeId}, is a declared input with its own type and description.
		{"aiplatform.v1", ai + "deployedModels.invoke.invoke", "/v1/projects/{projectsId}/locations/{locationsId}/" +
			"endpoints/{endpointsId}/deployedModels/{deployedModelId}/invoke/{invokeId}", []string{
			"projectsId|string|renderable|" + endpoint, "locationsId|string|renderable|" + endpoint,
			"endpointsId|string|renderable|" + endpoint,
			"deployedModelId|string|renderable|ID of the DeployedModel that serves the invoke request.",
			"invokeId|string|renderable|",
		}},
		{
			"compute.v1", "compute.instances.get", "/compute/v1/projects/{project}/zones/{zone}/instances/{instance}",
			[]string{
				"project|string|renderable|Project ID for this request.",
				"zone|string|renderable|The name of the zone for this request.",
				"instance|string|renderable|Name of the instance resource to return.",
			},
		},
		// storage has no flatPath: servicePath plus path, every label a declared parameter.
		{"storage.v1", "storage.objects.get", "/storage/v1/b/{bucket}/o/{object}", []string{
			"bucket|string|renderable|Name of the bucket in which the object resides.",
			"object|string|renderable|Name of the object. For information about how to URL encode object names to be p...",
		}},
		{"synth.v1", "synth.things.reserved", "/synth/v1/things/{name}", []string{"name|string|unrendered|"}},
		{"synth.v1", "synth.things.misaligned", "/synth/v1/things/{thingsId}/other", []string{
			"thingsId|string|renderable|a path segment",
		}},
	} {
		ref := reference(t, tc.stem, tc.id)
		if ref.PathTemplate != tc.path {
			t.Errorf("%s path = %s, want %s", tc.id, ref.PathTemplate, tc.path)
		}
		if got := pathInputs(ref); !slices.Equal(got, tc.inputs) {
			t.Errorf("%s inputs:\n%s\nwant:\n%s", tc.id, strings.Join(got, "\n"), strings.Join(tc.inputs, "\n"))
		}
	}
}

func TestReference_VersionBeforeAVerb(t *testing.T) {
	t.Parallel()
	// "v3:fetchResourceSemantics" carries the version in front of a custom verb; it is not a wire-fidelity gap.
	ref := reference(t, "cloudresourcemanager.v3", "cloudresourcemanager.fetchResourceSemantics")
	if ref.PathTemplate != "/v3:fetchResourceSemantics" || len(ref.Gaps) != 0 || len(pathInputs(ref)) != 0 {
		t.Errorf("fetchResourceSemantics = %s gaps %q inputs %+v", ref.PathTemplate, ref.Gaps, ref.Inputs)
	}
}

func TestRenderPath_ReservedWithoutFlatPathIsAGap(t *testing.T) {
	t.Parallel()
	ref := reference(t, "synth.v1", "synth.things.reserved")
	if want := "reserved-expansion path parameter name has no flat path to render"; !slices.Contains(ref.Gaps, want) ||
		apiref.OutcomeOf(ref) != apiref.OutcomeIncomplete {
		t.Errorf("gaps = %q, want %q", ref.Gaps, want)
	}
}

func TestAlignLabels(t *testing.T) {
	t.Parallel()
	params := map[string]DocParam{"name": {Name: "name", Description: "The name."}}
	for _, tc := range []struct {
		path, flat string
		want       map[string]string
		ok         bool
	}{
		{"v1/{name}", "v1/{namesId}", map[string]string{"namesId": "The name."}, true},
		{"v1/{+name}", "v1/a/{aId}/b/{bId}", map[string]string{
			"aId": "one segment of name", "bId": "one segment of name",
		}, true},
		{"v1/{+name}/x", "v1/x", nil, false},       // the run is empty
		{"v1/{+name}/x", "v1/a/{aId}", nil, false}, // the next literal is missing
		{"v1/{+name}/x", "v1", nil, false},         // flatPath ends before the run: nothing left to search
		{"v1/{+name}", "v1", nil, false},           // flatPath ends before a run that goes to the end
		{"v1/{name}/x", "v1", nil, false},          // flatPath ends early at a placeholder
		{"v1/{name}", "v1/name", nil, false},       // a literal where a placeholder belongs
		{"v1/x", "v1", nil, false},                 // flatPath ends early at a literal
		{"v1/x", "v1/y", nil, false},               // literals differ
		{"v1", "v1/extra", map[string]string{}, false},
	} {
		got, ok := alignLabels(tc.path, tc.flat, params)
		if ok != tc.ok || (ok && !equalMaps(got, tc.want)) {
			t.Errorf("alignLabels(%s, %s) = %v %v, want %v %v", tc.path, tc.flat, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRenderPath_FlatPathShorterThanPath(t *testing.T) {
	t.Parallel()
	// path "v1/{+name}/x" against flatPath "v1" used to slice past the end of flatPath while aligning.
	d := &APIDoc{Name: "a", Version: "v1", RootURL: "https://a.googleapis.com/", Methods: map[string]DocMethod{
		"a.b.get": {
			HTTPMethod: "GET", Path: "v1/{+name}/x", FlatPath: "v1/{v1Id}",
			Params: []DocParam{{Name: "name", Location: "path", Type: "string", Required: true}},
		},
		"a.c.get": {HTTPMethod: "GET", Path: "v1/{+name}/x", FlatPath: "v1"},
	}}
	if ref := buildReference(
		d,
		"a.b.get",
	); !slices.Equal(
		pathInputs(ref),
		[]string{"v1Id|string|renderable|" + docSegment},
	) {
		t.Errorf("a.b.get inputs = %q, want the label described as a path segment", pathInputs(ref))
	}
	if ref := buildReference(d, "a.c.get"); ref.PathTemplate != "/v1" || len(pathInputs(ref)) != 0 {
		t.Errorf("a.c.get = %s %q", ref.PathTemplate, pathInputs(ref))
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestSegmentOf_TruncatesTheForm(t *testing.T) {
	t.Parallel()
	got := segmentOf("name", "^"+strings.Repeat("a/", 200)+"$")
	if len([]rune(got)) != apiref.MaxInputDescription || !strings.HasSuffix(got, "...") {
		t.Errorf("segmentOf = %q, want it bounded at %d runes", got, apiref.MaxInputDescription)
	}
}

func TestReference_LocationalEndpoints(t *testing.T) {
	t.Parallel()
	const tail = "; the template uses the global endpoint, and gcp_auth.location, if supplied, must match the host"
	for stem, want := range map[string]string{
		"compute.v1": "the API also serves locational endpoints (https://compute.<location>.rep.googleapis.com)" + tail,
		"synth.v1": "the API also serves locational endpoints (https://<location>-synth.googleapis.com, " +
			"https://synth-<location>.googleapis.com, https://synth-global.googleapis.com)" + tail,
	} {
		d := distilled(t, stem)
		for id := range d.Methods {
			if ref := buildReference(d, id); !slices.Contains(ref.Limitations, want) {
				t.Errorf("%s limitations = %q, want %q", id, ref.Limitations, want)
			}
		}
	}
	ref := reference(t, "cloudresourcemanager.v1", "cloudresourcemanager.projects.get")
	if slices.ContainsFunc(ref.Limitations, func(l string) bool { return strings.Contains(l, "locational") }) {
		t.Errorf("an API with no endpoints[] got %q", ref.Limitations)
	}
}

// TestRenderedTemplatesClassify fills every label of every fixture template and requires the gcp classifier,
// over a catalog built from the same fixture, to name the method the template came from.
func TestRenderedTemplatesClassify(t *testing.T) {
	t.Parallel()
	for _, stem := range fixtureStems {
		raw := fixture(t, stem)
		var rd restDoc
		if err := json.Unmarshal(raw, &rd); err != nil {
			t.Fatal(err)
		}
		idx := serviceDocFrom(rd).Methods
		d := distilled(t, stem)
		for id := range d.Methods {
			ref := buildReference(d, id)
			path := docLabel.ReplaceAllString(ref.PathTemplate, "x")
			got, err := Classify(idx, authreq.View{Method: ref.Method, Path: path, EscapedPath: path})
			if err != nil || got != id {
				t.Errorf("%s: %s %s classified as %q, %v", id, ref.Method, path, got, err)
			}
		}
	}
}

// inputLines renders a reference's query and body inputs as "location name|type|required|description" lines.
func inputLines(ref *apiref.Reference) []string {
	var out []string
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationPath {
			continue
		}
		req := "optional"
		if in.Required {
			req = "required"
		}
		out = append(out, string(in.Location)+" "+in.Name+"|"+in.Type+"|"+req+"|"+in.Description)
	}
	return out
}

func TestReference_QueryAndBody(t *testing.T) {
	t.Parallel()
	const ai = "aiplatform.projects.locations.endpoints."
	for _, tc := range []struct {
		stem, id string
		inputs   []string
		gaps     []string
	}{
		// annotations.required names the method; read-only properties (id, kind) are dropped.
		{"compute.v1", "compute.instances.insert", []string{
			"query requestId|string|optional|An optional request ID to identify requests. Specify a unique request ID so that...",
			"body labels|object|optional|Labels to apply to this instance. These can be later modified by the setLabels m...",
			"body machineType|string|optional|Full or partial URL of the machine type resource to use for this instance, in th...",
			"body name|string|required|The name of the resource, provided by the client when initially creating the res...",
			"body tags|object|optional|Tags to apply to this instance. Tags are used to identify valid sources or targe...",
		}, nil},
		// A description that starts with "Required." makes the property required and says so.
		{"aiplatform.v1", ai + "create", []string{
			"query endpointId|string|optional|Immutable. The ID to use for endpoint, which will become the final component of...",
			"body description|string|optional|The description of the Endpoint.",
			"body displayName|string|required|required per the field documentation: Required. The display name of the " +
				"Endpoint. The name can be up to 128 characters...",
			"body name|string|optional|Identifier. The resource name of the Endpoint.",
		}, nil},
		{"aiplatform.v1", ai + "predict", []string{
			"body instances|array|required|required per the field documentation: Required. The instances that are the " +
				"input to the prediction call. A DeployedMod...",
			"body parameters|any|optional|The parameters that govern the prediction. The schema of the parameters may be s...",
		}, []string{"required input instances (array in body) cannot be rendered"}},
		{"storage.v1", "storage.buckets.update", []string{
			"body acl|array|required|Access controls on the bucket.",
			"body kind|string|optional|The kind of item this is. For buckets, this is always storage#bucket.",
			"body location|string|optional|The location of the bucket. Object data for objects in the bucket resides in phy...",
			"body name|string|optional|The name of the bucket.",
		}, []string{"required input acl (array in body) cannot be rendered"}},
		{"synth.v1", "synth.things.create", []string{
			"body misc|unknown|optional|Anything.",
			"body name|string|required|required per the field documentation: Required. The thing's name.",
			"body note|string|optional|Optional. A note.",
			"body shape|object|required|",
			"body size|string|required|",
		}, []string{"required input shape (object in body) cannot be rendered"}},
		{"synth.v1", "synth.things.list", []string{
			"query maxResults|integer|optional|",
			"query pageSize|integer|optional|",
			"query pageToken|string|optional|",
			"query parent|string|required|",
			"query tag|string|optional|(repeatable) Tags to match.",
		}, nil},
	} {
		ref := reference(t, tc.stem, tc.id)
		if got := inputLines(ref); !slices.Equal(got, tc.inputs) {
			t.Errorf("%s inputs:\n%s\nwant:\n%s", tc.id, strings.Join(got, "\n"), strings.Join(tc.inputs, "\n"))
		}
		if !slices.Equal(ref.Gaps, tc.gaps) {
			t.Errorf("%s gaps = %q, want %q", tc.id, ref.Gaps, tc.gaps)
		}
		if !slices.Contains(ref.Limitations, docStandardParams) {
			t.Errorf("%s limitations = %q, want the standard-parameter note", tc.id, ref.Limitations)
		}
	}
}

func TestReference_BodyEncoding(t *testing.T) {
	t.Parallel()
	jsonHeader := []apiref.Param{{Key: "Content-Type", Value: "application/json"}}
	for _, tc := range []struct {
		id       string
		encoding apiref.BodyEncoding
		headers  []apiref.Param
		gap      bool
	}{
		{"synth.things.list", apiref.BodyNone, nil, false},
		{"synth.things.empty", apiref.BodyJSON, jsonHeader, false},
		{"synth.things.create", apiref.BodyJSON, jsonHeader, false},
		{"synth.things.unresolved", apiref.BodyNone, nil, true},
		{"synth.things.scalar", apiref.BodyNone, nil, true},
		{"synth.things.inline", apiref.BodyNone, nil, true},
	} {
		ref := reference(t, "synth.v1", tc.id)
		if ref.BodyEncoding != tc.encoding || !slices.Equal(ref.FixedHeaders, tc.headers) {
			t.Errorf("%s = %s %v, want %s %v", tc.id, ref.BodyEncoding, ref.FixedHeaders, tc.encoding, tc.headers)
		}
		if got := slices.Contains(ref.Gaps, docBodyGap); got != tc.gap {
			t.Errorf("%s body gap = %v, want %v (gaps %q)", tc.id, got, tc.gap, ref.Gaps)
		}
		body := slices.IndexFunc(ref.Inputs, func(in apiref.Input) bool { return in.Name == "body" })
		if tc.gap && (body < 0 || ref.Inputs[body].Renderable || !ref.Inputs[body].Required || len(ref.Gaps) != 1) {
			t.Errorf("%s inputs %+v gaps %q, want one unrenderable body input and only the body gap", tc.id,
				ref.Inputs, ref.Gaps)
		}
	}
}

func TestReference_OptionalInputsAreBounded(t *testing.T) {
	t.Parallel()
	m := DocMethod{HTTPMethod: "GET", Path: "things"}
	for i := range apiref.MaxOptionalInputs + 5 {
		m.Params = append(m.Params, DocParam{Name: "p" + string(rune('a'+i)), Location: "query", Type: "string"})
	}
	m.Params = append(m.Params, DocParam{Name: "z", Location: "query", Type: "string", Required: true})
	d := &APIDoc{
		Name: "synth", Version: "v1", RootURL: "https://synth.googleapis.com/", ServicePath: "v1/",
		Methods: map[string]DocMethod{"synth.things.list": m},
	}
	ref := buildReference(d, "synth.things.list")
	if !ref.InputsTruncated || len(ref.Inputs) != apiref.MaxOptionalInputs+1 ||
		ref.Inputs[len(ref.Inputs)-1].Name != "z" {
		t.Errorf("inputs = %d (truncated %v), want %d optional plus the required z", len(ref.Inputs),
			ref.InputsTruncated, apiref.MaxOptionalInputs)
	}
}

func TestReference_Pagination(t *testing.T) {
	t.Parallel()
	pageToken := func(size string) apiref.Pagination {
		return apiref.Pagination{
			Style:       "page-token",
			InputToken:  "pageToken",
			OutputToken: "nextPageToken",
			PageSize:    size,
		}
	}
	unspecified := apiref.Pagination{Style: apiref.PaginationUnspecified}
	for _, tc := range []struct {
		stem, id string
		want     apiref.Pagination
		notes    []string
	}{
		{"compute.v1", "compute.instances.list", pageToken("maxResults"), []string{docPagingNote}},
		{"storage.v1", "storage.buckets.list", pageToken("maxResults"), []string{docPagingNote}},
		{"aiplatform.v1", "aiplatform.projects.locations.endpoints.list", pageToken("pageSize"), []string{docPagingNote}},
		{"cloudresourcemanager.v1", "cloudresourcemanager.projects.list", pageToken("pageSize"), []string{docPagingNote}},
		{"synth.v1", "synth.things.list", pageToken(""), []string{docPagingNote, docBothSizes}},
		{"compute.v1", "compute.instances.get", unspecified, nil},
	} {
		ref := reference(t, tc.stem, tc.id)
		if ref.Pagination != tc.want {
			t.Errorf("%s pagination = %+v, want %+v", tc.id, ref.Pagination, tc.want)
		}
		for _, n := range []string{docPagingNote, docBothSizes} {
			if slices.Contains(ref.Limitations, n) != slices.Contains(tc.notes, n) {
				t.Errorf("%s limitations = %q, want %q", tc.id, ref.Limitations, tc.notes)
			}
		}
	}
	// A pageToken parameter alone is not pagination: the response must carry nextPageToken.
	d := &APIDoc{
		Name: "synth", Version: "v1", RootURL: "https://synth.googleapis.com/", ServicePath: "v1/",
		Methods: map[string]DocMethod{"synth.things.list": {
			HTTPMethod: "GET", Path: "things", Response: "Things",
			Params: []DocParam{{Name: "pageToken", Location: "query", Type: "string"}},
		}},
	}
	if ref := buildReference(d, "synth.things.list"); ref.Pagination != unspecified {
		t.Errorf("pageToken without nextPageToken = %+v, want unspecified", ref.Pagination)
	}
}

func TestReference_Response(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stem, id, encoding string
		note               string
	}{
		{"compute.v1", "compute.instances.get", "json", ""},
		{"aiplatform.v1", "aiplatform.projects.locations.endpoints.rawPredict", "raw", docHTTPBodyNote},
		{"storage.v1", "storage.buckets.delete", "none", ""},
		{"storage.v1", "storage.objects.get", "json", docMediaNote},
	} {
		ref := reference(t, tc.stem, tc.id)
		if ref.Response.Encoding != tc.encoding {
			t.Errorf("%s response = %+v, want %s", tc.id, ref.Response, tc.encoding)
		}
		for _, n := range []string{docHTTPBodyNote, docMediaNote} {
			if slices.Contains(ref.Limitations, n) != (n == tc.note) {
				t.Errorf("%s limitations = %q, want note %q", tc.id, ref.Limitations, tc.note)
			}
		}
	}
	if ref := reference(t, "storage.v1", "storage.buckets.delete"); ref.Response.Parse !=
		"no modeled body fields; read the status and headers" {
		t.Errorf("no response schema parse = %q", ref.Response.Parse)
	}
}
