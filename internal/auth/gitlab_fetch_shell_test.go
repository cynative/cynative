package auth //nolint:testpackage // shell test accesses unexported bootstrap glue.

import "testing"

// TestNewGitLabOpenAPIFetcher_Constructs builds the fetcher and asserts the
// returned func is non-nil. It does NOT invoke the func — invoking would hit the
// network and the dial guard blocks loopback. It references the auth-package
// bootstrap symbols so `unused` is satisfied until the cut-over (B1) wires them.
func TestNewGitLabOpenAPIFetcher_Constructs(t *testing.T) {
	t.Parallel()
	if newGitLabOpenAPIFetcher() == nil {
		t.Fatal("fetcher is nil")
	}
}
