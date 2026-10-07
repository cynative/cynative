package gcp_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestDocsFetcher(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the docs fetch sent an Authorization header")
		}
		_, _ = w.Write([]byte(`{"name":"compute"}`))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{' '}, 32<<20+1))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	fetch := gcphardening.NewDocsFetcher(srv.Client())

	if got, err := fetch(t.Context(), srv.URL+"/ok"); err != nil || string(got) != `{"name":"compute"}` {
		t.Errorf("ok = %q, %v", got, err)
	}
	if _, err := fetch(t.Context(), srv.URL+"/missing"); err == nil {
		t.Error("a 404 returned no error")
	}
	if _, err := fetch(t.Context(), srv.URL+"/big"); !errors.Is(err, gcphardening.ErrDocumentTooLarge) {
		t.Errorf("a 32 MiB + 1 byte body err = %v, want ErrDocumentTooLarge", err)
	}
	if _, err := fetch(t.Context(), "http://[::1"); err == nil {
		t.Error("an unparseable URL returned no error")
	}
	if _, err := fetch(t.Context(), "http://127.0.0.1:0/"); err == nil {
		t.Error("a failed dial returned no error")
	}
}
