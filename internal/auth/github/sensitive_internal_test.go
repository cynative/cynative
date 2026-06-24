package github

import (
	"errors"
	"net/http"
	"testing"
)

func TestAdmitTable(t *testing.T) {
	t.Parallel()

	// A table that correctly classifies secret-scanning is admitted.
	good, err := DistillOpenAPI([]byte(`{"paths":{
		"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category": "secret-scanning", "subcategory": "secret-scanning"}}}
	}}`))
	if err != nil {
		t.Fatalf("distill good: %v", err)
	}
	admitGoodErr := AdmitTable(good)
	if admitGoodErr != nil {
		t.Fatalf("AdmitTable(good) = %v, want nil", admitGoodErr)
	}

	// A tampered table mapping a secret-scanning route into "repos" is rejected.
	bad, err := DistillOpenAPI([]byte(`{"paths":{
		"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category": "repos", "subcategory": "contents"}}}
	}}`))
	if err != nil {
		t.Fatalf("distill bad: %v", err)
	}
	admitBadErr := AdmitTable(bad)
	if !errors.Is(admitBadErr, ErrTableRejected) {
		t.Fatalf("AdmitTable(bad) = %v, want ErrTableRejected", admitBadErr)
	}
}

// TestClassifyRequest_NoOverride verifies that a user-controlled path segment
// named "secret-scanning" (e.g. an owner or repo named "secret-scanning") is NOT
// mis-classified as the secret-scanning category — it routes through the table
// to its real category (e.g. repos/contents).
func TestClassifyRequest_NoOverride(t *testing.T) {
	t.Parallel()

	// Build a table where {owner} can be "secret-scanning" — a contents route.
	tbl, err := DistillOpenAPI([]byte(`{"paths":{
		"/repos/{owner}/{repo}/contents/{path}": {"get": {"x-github": {"category": "repos", "subcategory": "contents"}}}
	}}`))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}

	// A request where {owner} = "secret-scanning" — a user-controlled segment.
	// The route is repos/contents, NOT secret-scanning.
	got, err := ClassifyRequest(tbl, http.MethodGet, "/repos/secret-scanning/myrepo/contents/README.md")
	if err != nil {
		t.Fatalf("ClassifyRequest: unexpected error: %v", err)
	}
	if got.Route.Category != "repos" {
		t.Errorf(
			"category = %q, want %q (user-controlled segment must not override table)",
			got.Route.Category, "repos",
		)
	}
}
