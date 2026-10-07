package gcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// fixtureIndex builds the gate's method index for one service from fixtures, merged in the given order the way
// the catalog merges directory versions.
func fixtureIndex(t *testing.T, service string, stems ...string) MethodIndex {
	t.Helper()
	var docs []fetchedDoc
	for _, stem := range stems {
		var rd restDoc
		if err := json.Unmarshal(fixture(t, stem), &rd); err != nil {
			t.Fatal(err)
		}
		docs = append(docs, fetchedDoc{name: strings.Split(stem, ".")[0], doc: rd, ok: true})
	}
	data, err := assembleCatalog(docs)
	if err != nil {
		t.Fatal(err)
	}
	return data.Services[service].Methods
}

func hintView(method, path string) authreq.View {
	return authreq.View{Method: method, Path: path, EscapedPath: path}
}

func TestHint(t *testing.T) {
	t.Parallel()
	crm := fixtureIndex(t, "cloudresourcemanager", "cloudresourcemanager.v1", "cloudresourcemanager.v3")
	ai := fixtureIndex(t, "aiplatform", "aiplatform.v1")
	const endpoints = "/v1/projects/p/locations/us-central1/endpoints/"
	for _, tc := range []struct {
		name       string
		idx        MethodIndex
		method     string
		path       string
		candidates []string
		operation  string
	}{
		// projects.list sits at /v1/projects and /v3/projects; each request shows only the route it matched.
		{
			"near miss in v3", crm, "GET", "/v3/projectz",
			[]string{"cloudresourcemanager.projects.list (GET /v3/projects)"},
			"cloudresourcemanager.projects.list",
		},
		{
			"other method in v1", crm, "POST", "/v1/projects",
			[]string{"cloudresourcemanager.projects.list (GET /v1/projects)"},
			"cloudresourcemanager.projects.list",
		},
		{
			"custom verb near miss", ai, "POST", endpoints + "123:predcit",
			[]string{"aiplatform.projects.locations.endpoints.predict (POST /v1/projects/{projectsId}/locations/" +
				"{locationsId}/endpoints/{endpointsId}:predict)"},
			"aiplatform.projects.locations.endpoints.predict",
		},
		{
			"custom verb under another method", ai, "GET", endpoints + "123:rawPredict",
			[]string{"aiplatform.projects.locations.endpoints.rawPredict (POST /v1/projects/{projectsId}/locations/" +
				"{locationsId}/endpoints/{endpointsId}:rawPredict)"},
			"aiplatform.projects.locations.endpoints.rawPredict",
		},
		// Only routes whose last segment carries a verb are matched against a request whose last segment does, so
		// /v1/projects/{projectId} cannot match the split ":serch" through its label.
		{
			"verb on a literal segment", crm, "GET", "/v3/projects:serch",
			[]string{"cloudresourcemanager.projects.search (GET /v3/projects:search)"},
			"cloudresourcemanager.projects.search",
		},
		// And a request with no verb never reaches a verb route: ":predict" is one edit from "predict".
		{"no verb against a verb route", ai, "POST", endpoints + "123/predict", nil, ""},
		{"near miss on a literal", crm, "GET", "/v1/projectz/p", []string{
			"cloudresourcemanager.projects.get (GET /v1/projects/{projectId})",
		}, "cloudresourcemanager.projects.get"},
		{"nothing close", crm, "GET", "/v9/nothing/here", nil, ""},
	} {
		h := Hint(func() MethodIndex { return tc.idx }, hintView(tc.method, tc.path))
		if !slices.Equal(h.Candidates, tc.candidates) || h.Operation != tc.operation || h.Note != HintNote {
			t.Errorf("%s: %+v\nwant candidates %q operation %q", tc.name, h, tc.candidates, tc.operation)
		}
	}
}

func TestHint_OverLongPathReadsNoRoutes(t *testing.T) {
	t.Parallel()
	methods := func() MethodIndex {
		t.Error("an over-long path read the method index")
		return nil
	}
	h := Hint(methods, hintView("GET", "/v3/projectz"+strings.Repeat("/x", 1100)))
	if h.Candidates != nil || h.Note != HintNote {
		t.Errorf("over-long path = %+v, want only the note", h)
	}
}

// TestHint_VerbFilterRunsBeforeTheMatcher pins that routes are filtered by verb before the shared matcher sees them:
// four routes ending in a bare {sub} would otherwise match the split ":get" under other methods, take precedence
// over the near miss and, being more than three, leave no candidate at all.
func TestHint_VerbFilterRunsBeforeTheMatcher(t *testing.T) {
	t.Parallel()
	idx := MethodIndex{"svc.a.got": {ID: "svc.a.got", HTTPMethod: "GET", FlatPath: "v1/things/{thing}:got"}}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		idx["svc.a."+m] = MethodDescriptor{
			ID:         "svc.a." + strings.ToLower(m),
			HTTPMethod: m,
			FlatPath:   "v1/things/{thing}/{sub}",
		}
	}
	h := Hint(func() MethodIndex { return idx }, hintView("GET", "/v1/things/1:get"))
	if want := []string{"svc.a.got (GET /v1/things/{thing}:got)"}; !slices.Equal(h.Candidates, want) ||
		h.Operation != "svc.a.got" {
		t.Errorf("hint = %+v, want %q", h, want)
	}
}

func TestHint_BoundsRoutesNotIDs(t *testing.T) {
	t.Parallel()
	idx := MethodIndex{}
	for _, m := range []string{"PUT", "POST", "PATCH", "DELETE"} {
		idx["svc.a."+m] = MethodDescriptor{ID: "svc.a." + strings.ToLower(m), HTTPMethod: m, FlatPath: "v1/a"}
	}
	if h := Hint(
		func() MethodIndex { return idx },
		hintView("GET", "/v1/a"),
	); h.Candidates != nil ||
		h.Operation != "" {
		t.Errorf("four routes = %+v, want no candidates", h)
	}
	// One id at two versions' paths is two routes, and a candidate shows the route that matched.
	two := MethodIndex{
		"svc.a.list":           {ID: "svc.a.list", HTTPMethod: "GET", FlatPath: "v1/things"},
		"svc.a.list\x00GET v2": {ID: "svc.a.list", HTTPMethod: "GET", FlatPath: "v2/things"},
		"svc.b.list":           {ID: "svc.b.list", HTTPMethod: "GET", FlatPath: "v1/thinks"},
	}
	h := Hint(func() MethodIndex { return two }, hintView("POST", "/v1/things"))
	if want := []string{
		"svc.a.list (GET /v1/things)",
	}; !slices.Equal(h.Candidates, want) ||
		h.Operation != "svc.a.list" {
		t.Errorf("one route = %+v, want %q", h, want)
	}
	h = Hint(func() MethodIndex { return two }, hintView("GET", "/v1/thingz"))
	want := []string{"svc.a.list (GET /v1/things)", "svc.b.list (GET /v1/thinks)"}
	if !slices.Equal(h.Candidates, want) || h.Operation != "" {
		t.Errorf("two ids = %+v, want %q and no operation", h, want)
	}
}

func TestSplitVerb(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"/v1/{name}:cancel":        "/v1/{name}/:cancel",
		"/v1:evaluateDataset":      "/v1/:evaluateDataset",
		"/v1/a:b/c":                "/v1/a:b/c",
		"/v1/things":               "/v1/things",
		"/v1/x:a:b":                "/v1/x/:a:b",
		"/compute/v1/projects/p/x": "/compute/v1/projects/p/x",
	} {
		if got := splitVerb(in); got != want {
			t.Errorf("splitVerb(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestCatalog_PeekMethodIndex(t *testing.T) {
	t.Parallel()
	c := newCatalog(func(_ context.Context) (DiscoveryData, error) {
		t.Error("PeekMethodIndex fetched")
		return DiscoveryData{}, nil
	})
	if idx, ok := c.PeekMethodIndex("compute"); ok || idx != nil {
		t.Errorf("no snapshot = %v %v, want none", idx, ok)
	}
	data := &DiscoveryData{Services: map[string]ServiceDoc{"compute": {Methods: computeIndex()}}}
	c.peek = func() *DiscoveryData { return data }
	if idx, ok := c.PeekMethodIndex("compute"); !ok || len(idx) != len(computeIndex()) {
		t.Errorf("loaded snapshot = %d methods %v", len(idx), ok)
	}
	if _, ok := c.PeekMethodIndex("storage"); ok {
		t.Error("a service the snapshot lacks was found")
	}
}
