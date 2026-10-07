package gcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

// fixture returns a trimmed Discovery document from testdata/discovery, by its <name>.<version> stem.
func fixture(t *testing.T, stem string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "discovery", stem+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func distilled(t *testing.T, stem string) *APIDoc {
	t.Helper()
	d, err := DistillDoc(fixture(t, stem))
	if err != nil {
		t.Fatalf("DistillDoc(%s): %v", stem, err)
	}
	return d
}

func propNamed(t *testing.T, s DocSchema, name string) DocProp {
	t.Helper()
	i := slices.IndexFunc(s.Props, func(p DocProp) bool { return p.Name == name })
	if i < 0 {
		t.Fatalf("no property %q in %+v", name, s.Props)
	}
	return s.Props[i]
}

func TestDistillDoc_Compute(t *testing.T) {
	t.Parallel()
	raw := fixture(t, "compute.v1")
	d := distilled(t, "compute.v1")
	sum := sha256.Sum256(raw)
	if d.Name != "compute" || d.Version != "v1" || d.Revision != "20260922" ||
		d.RootURL != "https://compute.googleapis.com/" || d.ServicePath != "compute/v1/" ||
		d.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("header = %s %s %s %s %s %s", d.Name, d.Version, d.Revision, d.RootURL, d.ServicePath, d.SHA256)
	}
	if want := []string{"https://compute.<location>.rep.googleapis.com"}; !slices.Equal(d.Endpoints, want) {
		t.Errorf("endpoints = %q, want %q", d.Endpoints, want)
	}
	if len(d.Methods) != 4 {
		t.Fatalf("methods = %d, want 4", len(d.Methods))
	}
	list := d.Methods["compute.instances.list"]
	var names []string
	for _, p := range list.Params {
		names = append(names, p.Name)
	}
	if want := []string{"filter", "maxResults", "pageToken", "project", "zone"}; !slices.Equal(names, want) {
		t.Errorf("list params = %q, want %q (sorted)", names, want)
	}
	if list.HTTPMethod != "GET" || list.Response != "InstanceList" || !list.NextPageToken || list.Body {
		t.Errorf("list = %+v", list)
	}
	insert := d.Methods["compute.instances.insert"]
	if !insert.Body || insert.Request != "Instance" || insert.Response != "Operation" || insert.NextPageToken {
		t.Errorf("insert = %+v", insert)
	}
	inst := d.Schemas["Instance"]
	if !inst.Object {
		t.Fatalf("Instance not an object: %+v", inst)
	}
	if p := propNamed(t, inst, "id"); !p.ReadOnly || p.Type != "string" {
		t.Errorf("id = %+v, want read-only string", p)
	}
	if p := propNamed(t, inst, "name"); !slices.Equal(p.RequiredBy, []string{"compute.instances.insert"}) || p.Prose {
		t.Errorf("name = %+v, want required by compute.instances.insert", p)
	}
	if p := propNamed(t, inst, "tags"); p.Type != "object" || p.ReadOnly {
		t.Errorf("tags = %+v, want a writable object", p)
	}
	if _, ok := d.Schemas["InstanceList"]; ok {
		t.Error("response schema InstanceList was kept; only request schemas are")
	}
}

func TestDistillDoc_Shapes(t *testing.T) {
	t.Parallel()
	ai := distilled(t, "aiplatform.v1")
	if m := ai.Methods["aiplatform.projects.locations.endpoints.rawPredict"]; !m.HTTPBody ||
		m.Response != "GoogleApiHttpBody" {
		t.Errorf("rawPredict = %+v, want an HttpBody response", m)
	}
	if m := ai.Methods["aiplatform.projects.locations.endpoints.predict"]; m.HTTPBody {
		t.Errorf("predict = %+v, want a JSON response", m)
	}
	st := distilled(t, "storage.v1")
	if m := st.Methods["storage.objects.get"]; !m.MediaDownload || m.FlatPath != "" ||
		m.Path != "b/{bucket}/o/{object}" {
		t.Errorf("objects.get = %+v", m)
	}
	if m := st.Methods["storage.buckets.delete"]; m.Response != "" || m.Body {
		t.Errorf("buckets.delete = %+v, want no request and no response", m)
	}
	sy := distilled(t, "synth.v1")
	if m := sy.Methods["synth.things.inline"]; !m.Body || m.Request != "" {
		t.Errorf("inline = %+v, want a body with no schema name", m)
	}
	if m := sy.Methods["synth.things.unresolved"]; !m.Body || m.Request != "Missing" {
		t.Errorf("unresolved = %+v", m)
	}
	if _, ok := sy.Schemas["Missing"]; ok {
		t.Error("an unresolved request schema was invented")
	}
	if s := sy.Schemas["Name"]; s.Object || len(s.Props) != 0 {
		t.Errorf("Name = %+v, want a non-object schema", s)
	}
	thing := sy.Schemas["Thing"]
	for name, want := range map[string]DocProp{
		"name":  {Name: "name", Type: "string", Description: "Required. The thing's name.", Prose: true},
		"size":  {Name: "size", Type: "string", RequiredBy: []string{"synth.things.create"}},
		"shape": {Name: "shape", Type: "object", RequiredBy: []string{"synth.things.create"}},
		"etag":  {Name: "etag", Type: "string", ReadOnly: true},
		"state": {Name: "state", Type: "string", Description: "Output only. The state.", ReadOnly: true},
		"zone":  {Name: "zone", Type: "string", Description: "[Output Only] The zone.", ReadOnly: true},
		"note":  {Name: "note", Type: "string", Description: "Optional. A note."},
		"misc":  {Name: "misc", Type: "unknown", Description: "Anything."},
	} {
		if got := propNamed(t, thing, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	want := []string{
		"https://<location>-synth.googleapis.com", "https://synth-<location>.googleapis.com",
		"https://synth-global.googleapis.com", "https://synth.<location>.rep.googleapis.com",
	}
	if !slices.Equal(sy.Endpoints, want) {
		t.Errorf("endpoints = %q, want %q", sy.Endpoints, want)
	}
}

// TestEndpointForms_ReplacesTheLocationLabel pins the location replaced only as a whole host label: logging's "in"
// location must not turn "logging" into "logg<location>g".
func TestEndpointForms_ReplacesTheLocationLabel(t *testing.T) {
	t.Parallel()
	doc := discoveryDoc{Endpoints: []discoveryEndpoint{
		{EndpointURL: "https://logging.in.rep.googleapis.com/", Location: "in"},
		{EndpointURL: "https://in-discoveryengine.googleapis.com/", Location: "in"},
		{EndpointURL: "https://us-east1-aiplatform.googleapis.com/", Location: "us-east1"},
		{EndpointURL: "https://nolabel.googleapis.com/", Location: "in"},
	}}
	want := []string{
		"https://<location>-aiplatform.googleapis.com", "https://<location>-discoveryengine.googleapis.com",
		"https://logging.<location>.rep.googleapis.com", "https://nolabel.googleapis.com",
	}
	if got := endpointForms(doc); !slices.Equal(got, want) {
		t.Errorf("forms = %q\nwant %q", got, want)
	}
}

func TestDistillDoc_RejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := DistillDoc([]byte(`{"name": 1}`)); !errors.Is(err, ErrDocsRejected) {
		t.Fatalf("err = %v, want ErrDocsRejected", err)
	}
}

func TestAPIDoc_SerializeRoundTrip(t *testing.T) {
	t.Parallel()
	d := distilled(t, "synth.v1")
	back, err := UnmarshalDoc(d.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, d) {
		t.Errorf("round trip changed the document:\n%+v\n%+v", back, d)
	}
	if _, uerr := UnmarshalDoc([]byte("{")); !errors.Is(uerr, ErrDocsRejected) {
		t.Errorf("UnmarshalDoc({) err = %v, want ErrDocsRejected", uerr)
	}
}

func TestAdmitDoc(t *testing.T) {
	t.Parallel()
	d := &APIDoc{Name: "compute", Version: "v1"}
	if err := admitDoc("compute", "v1")(d); err != nil {
		t.Errorf("matching document refused: %v", err)
	}
	for _, nv := range [][2]string{{"compute", "beta"}, {"Compute", "v1"}} {
		if err := admitDoc(nv[0], nv[1])(d); !errors.Is(err, ErrDocsRejected) {
			t.Errorf("admitDoc(%s %s) = %v, want ErrDocsRejected", nv[0], nv[1], err)
		}
	}
}

func TestReadCapped(t *testing.T) {
	t.Parallel()
	if got, err := readCapped(strings.NewReader("abcd"), 4); err != nil || string(got) != "abcd" {
		t.Errorf("at the limit = %q, %v", got, err)
	}
	if _, err := readCapped(strings.NewReader("abcde"), 4); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("over the limit err = %v, want ErrDocumentTooLarge", err)
	}
	boom := errors.New("boom")
	if _, err := readCapped(iotest.ErrReader(boom), 4); !errors.Is(err, boom) {
		t.Errorf("reader error = %v, want boom", err)
	}
	if maxDocumentBytes != 32<<20 {
		t.Errorf("maxDocumentBytes = %d, want 32 MiB", maxDocumentBytes)
	}
	over := bytes.NewReader(make([]byte, maxDocumentBytes+1))
	if _, err := readCapped(over, maxDocumentBytes); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("a 32 MiB + 1 byte body err = %v, want ErrDocumentTooLarge", err)
	}
}
