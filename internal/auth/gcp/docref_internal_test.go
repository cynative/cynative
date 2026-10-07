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
	if ref := reference(t, "cloudresourcemanager.v1", "cloudresourcemanager.projects.get"); len(ref.Limitations) != 0 {
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
