package aws_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	awsh "github.com/cynative/cynative/internal/auth/aws"
)

func TestNewModelArchiveFetcher_returnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tarball-bytes"))
	}))
	t.Cleanup(srv.Close)

	raw, err := awsh.NewModelArchiveFetcher(srv.Client(), srv.URL)(t.Context())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(raw) != "tarball-bytes" {
		t.Errorf("unexpected body %q", raw)
	}
}

func TestNewModelArchiveFetcher_nonOKStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	if _, err := awsh.NewModelArchiveFetcher(srv.Client(), srv.URL)(t.Context()); err == nil {
		t.Error("expected error on non-200")
	}
}

func TestNewModelArchiveFetcher_networkFailureFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // Close immediately so Do fails.
	if _, err := awsh.NewModelArchiveFetcher(srv.Client(), srv.URL)(t.Context()); err == nil {
		t.Error("expected network error")
	}
}
