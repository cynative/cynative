package auth //nolint:testpackage // shell test accesses unexported bootstrap glue.

import (
	"context"
	"net/http"
	"testing"
)

// TestNewGithubOpenAPIFetcher_nonNil constructs the fetcher and asserts the
// returned func is non-nil. It does NOT invoke the func — invoking would hit the
// network and the dial guard blocks loopback.
func TestNewGithubOpenAPIFetcher_nonNil(t *testing.T) {
	fn := newGithubOpenAPIFetcher()
	if fn == nil {
		t.Fatal("newGithubOpenAPIFetcher() = nil, want non-nil func")
	}
}

// TestNewGithubOpenAPIRequest_noToken builds the request and verifies method,
// scheme, no Authorization header, and Accept header. No network is involved.
func TestNewGithubOpenAPIRequest_noToken(t *testing.T) {
	req, err := newGithubOpenAPIRequest(context.Background())
	if err != nil {
		t.Fatalf("newGithubOpenAPIRequest: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.Method)
	}
	if req.URL.Scheme != "https" {
		t.Errorf("scheme = %s, want https", req.URL.Scheme)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty (no token to the CDN)", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want application/json", got)
	}
}
