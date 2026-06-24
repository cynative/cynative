package gcp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestNewIAMDatasetFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"api":{"compute":{"methods":{}}}}`))
	}))
	defer srv.Close()

	fetch := gcphardening.NewIAMDatasetFetcher(srv.Client(), srv.URL)
	body, err := fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}

	// Non-200 → error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	if _, badErr := gcphardening.NewIAMDatasetFetcher(
		bad.Client(),
		bad.URL,
	)(
		context.Background(),
	); !errors.Is(
		badErr,
		gcphardening.ErrIAMDatasetUnavailable,
	) {
		t.Errorf("non-200 error should wrap ErrIAMDatasetUnavailable, got %v", badErr)
	}
}
