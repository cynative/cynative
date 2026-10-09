package k8s

import (
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

// TestParseDocument_OutOfRangeNumbersInUnreadSubtrees puts 1e400, which does not fit a float64, under an x-
// extension and in a component schema annotation, two subtrees no decode reads. The streaming pass keeps numbers
// as text, so the lookup still answers found.
func TestParseDocument_OutOfRangeNumbersInUnreadSubtrees(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	d, err := ParseDocument(t.Context(), []byte(`{"x-limit":1e400,"paths":{"/apis/apps/v1/a":{"get":{
	"operationId":"a","x-weight":1e400}}},"components":{"schemas":{"A":{"type":"object","maximum":1e400,
	"properties":{"n":{"type":"number","x-max":1e400}}}}}}`), v)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if res := lookup(d, "a"); res.Outcome != apiref.OutcomeFound {
		t.Errorf("lookup: %+v", res)
	}
}

// TestParseDocument_NothingAdmitted pins spec 4.2: a document whose indexed ids are all duplicate or unrenderable
// is not unavailable. The core is skipped, and those ids answer ambiguous or unsupported.
func TestParseDocument_NothingAdmitted(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	cases := []struct {
		doc, id string
		outcome apiref.Outcome
	}{
		{`{"paths":{"/apis/apps/v1/a":{"get":{"operationId":"dupThing"}},"/apis/apps/v1/b":{"get":` +
			`{"operationId":"dupThing"}}}}`, "dupThing", apiref.OutcomeAmbiguous},
		{`{"paths":{"/apis/apps/v1/..":{"get":{"operationId":"badThing"}}}}`, "badThing", apiref.OutcomeUnsupported},
		{`{"paths":{"/apis/apps/v1/..":{"get":{"operationId":"badThing"}}}}`, "otherThing", apiref.OutcomeNotFound},
	}
	for _, tc := range cases {
		d, err := ParseDocument(t.Context(), []byte(tc.doc), v)
		if err != nil {
			t.Fatalf("%s: ParseDocument: %v", tc.doc, err)
		}
		if res := lookup(d, tc.id); res.Outcome != tc.outcome {
			t.Errorf("%s in %s: %+v", tc.id, tc.doc, res)
		}
	}
	d, _ := ParseDocument(t.Context(), []byte(cases[0].doc), v)
	if res := lookup(d, "dupThing"); len(res.Choices) != 2 || res.Choices[0] != "GET /apis/apps/v1/a" {
		t.Errorf("choices = %q", res.Choices)
	}
}

// TestLookup_AmbiguityChoicesPassTheWholePathForm keeps a duplicate route whose label is undeclared or outside the
// name grammar out of the choices, which are cluster text shown to the model.
func TestLookup_AmbiguityChoicesPassTheWholePathForm(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	d, err := ParseDocument(t.Context(), []byte(`{"paths":{
	"/apis/apps/v1/ok":{"get":{"operationId":"sibling"},"put":{"operationId":"dup"}},
	"/apis/apps/v1/{missing}":{"get":{"operationId":"dup"}},
	"/apis/apps/v1/{bad?x}":{"parameters":[{"name":"bad?x","in":"path"}],"get":{"operationId":"dup"}}}}`), v)
	if err != nil {
		t.Fatal(err)
	}
	if res := lookup(d, "dup"); res.Outcome != apiref.OutcomeAmbiguous || len(res.Choices) != 1 ||
		res.Choices[0] != "PUT /apis/apps/v1/ok" {
		t.Errorf("res = %+v", res)
	}
}
