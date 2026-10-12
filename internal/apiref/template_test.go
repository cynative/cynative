package apiref_test

import (
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

// TestTemplateURL pins every branch of the builder the tool and the azure tests share: a whole-segment label, a
// label inside a segment, a greedy label, an unrendered path input (plain and greedy), an undeclared label, an
// unclosed brace, a fixed pair with and without a value, and required query inputs, rendered and not.
func TestTemplateURL(t *testing.T) {
	t.Parallel()
	ref := &apiref.Reference{
		Endpoint:     "https://h.example",
		PathTemplate: "/a/{Id}/{file}.tgz/{Key+}/{Gone}/{Undeclared}/{open",
		FixedQuery:   []apiref.Param{{Key: "api-version", Value: "2024-01-01"}, {Key: "flag"}},
		Inputs: []apiref.Input{
			{Name: "Id", Location: apiref.LocationPath, Required: true, Renderable: true},
			{Name: "file", Location: apiref.LocationPath, Required: true, Renderable: true},
			{Name: "Key", Location: apiref.LocationPath, Required: true},
			{Name: "Gone", Location: apiref.LocationPath, Required: true},
			{Name: "q", WireName: "q", Location: apiref.LocationQuery, Required: true, Renderable: true},
			{Name: "r", WireName: "r", Location: apiref.LocationQuery, Required: true},
			{Name: "opt", WireName: "opt", Location: apiref.LocationQuery, Renderable: true},
		},
	}
	want := "https://h.example/a/<Id>/<file>.tgz/<Key+:unrendered>/<Gone:unrendered>/<Undeclared>/{open" +
		"?api-version=2024-01-01&flag&q=<q>&r=<r:unrendered>"
	if got := apiref.TemplateURL(ref); got != want {
		t.Fatalf("TemplateURL =\n%s\nwant\n%s", got, want)
	}
	if got := apiref.TemplateURL(&apiref.Reference{Endpoint: "https://h.example", PathTemplate: "/x"}); got !=
		"https://h.example/x" {
		t.Fatalf("no query = %s", got)
	}
}

// TestRequiredAtAndPlaceholder pins the two helpers the tool also uses for headers and bodies.
func TestRequiredAtAndPlaceholder(t *testing.T) {
	t.Parallel()
	ref := &apiref.Reference{Inputs: []apiref.Input{
		{Name: "h", Location: apiref.LocationHeader, Required: true, Renderable: true},
		{Name: "o", Location: apiref.LocationHeader},
		{Name: "q", Location: apiref.LocationQuery, Required: true},
	}}
	got := apiref.RequiredAt(ref, apiref.LocationHeader)
	if len(got) != 1 || got[0].Name != "h" || apiref.Placeholder(got[0]) != "<h>" ||
		apiref.Placeholder(ref.Inputs[2]) != "<q:unrendered>" {
		t.Fatalf("RequiredAt = %+v", got)
	}
	if pairs := apiref.ParamPairs([]apiref.Param{{Key: "k", Value: "v"}, {Key: "bare"}}); !slices.Equal(pairs,
		[]string{"k=v", "bare"}) {
		t.Fatalf("ParamPairs = %v", pairs)
	}
}
