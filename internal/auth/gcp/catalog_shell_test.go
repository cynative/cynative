package gcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/cache"
)

func TestCatalogShellFetchAndCache(t *testing.T) {
	t.Parallel()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"items":[{"name":"compute","version":"v1","discoveryRestUrl":"DOC/compute"}]}`))
	})
	mux.HandleFunc("/DOC/compute", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://compute.googleapis.com/","servicePath":"compute/v1/",` +
			`"methods":{"list":{"id":"compute.instances.list","httpMethod":"GET","flatPath":"projects/{project}/zones/{zone}/instances"}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	})

	svc, err := cat.ResolveService(
		context.Background(),
		gcphardening.ParsedHost{Service: "compute"},
		"compute.googleapis.com",
	)
	if err != nil || svc != "compute" {
		t.Fatalf("resolve = %q err=%v", svc, err)
	}
	// Second call must come from cache (directory not re-fetched).
	if _, miErr := cat.MethodIndex(context.Background(), "compute"); miErr != nil {
		t.Fatalf("MethodIndex: %v", miErr)
	}
	if hits != 1 {
		t.Errorf("directory fetched %d times, want 1 (cache miss + reuse)", hits)
	}
}

func TestCatalogShellMergesMultiVersionDocs(t *testing.T) {
	t.Parallel()
	// Two directory items (iam v1 + v2) share a rootUrl, so they collide on the
	// "iam" short name. Without mergeServiceDocs the later (v2) doc overwrites v1
	// and drops its methods; the merged MethodIndex must carry methods from BOTH.
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[` +
			`{"name":"iam","version":"v1","discoveryRestUrl":"DOC/iam-v1"},` +
			`{"name":"iam","version":"v2","discoveryRestUrl":"DOC/iam-v2"}]}`))
	})
	mux.HandleFunc("/DOC/iam-v1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://iam.googleapis.com/","servicePath":"",` +
			`"methods":{"get":{"id":"iam.roles.get","httpMethod":"GET","flatPath":"v1/roles/{rolesId}"}}}`))
	})
	mux.HandleFunc("/DOC/iam-v2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://iam.googleapis.com/","servicePath":"",` +
			`"methods":{"get":{"id":"iam.policies.get","httpMethod":"GET","flatPath":"v2/policies/{policiesId}"}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	})

	idx, err := cat.MethodIndex(context.Background(), "iam")
	if err != nil {
		t.Fatalf("MethodIndex: %v", err)
	}
	if _, ok := idx["iam.roles.get"]; !ok {
		t.Error("v1 method iam.roles.get missing — later version overwrote it")
	}
	if _, ok := idx["iam.policies.get"]; !ok {
		t.Error("v2 method iam.policies.get missing from merged index")
	}
}

func TestCatalogShellStaleCacheFallback(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	unavailable := false
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		if unavailable {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"name":"storage","version":"v1","discoveryRestUrl":"DOC/storage"}]}`))
	})
	mux.HandleFunc("/DOC/storage", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://storage.googleapis.com/","servicePath":"storage/v1/","methods":{}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	// First call: cache populated.
	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Millisecond, Clock: time.Now}, // expire immediately.
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	})
	if _, err := cat.ResolveService(
		context.Background(),
		gcphardening.ParsedHost{Service: "storage"},
		"storage.googleapis.com",
	); err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// Second catalog instance (new fetch closures) — TTL already expired so it will
	// attempt a fresh fetch; server now returns 503 so it should fall back to stale cache.
	unavailable = true
	cat2 := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Millisecond, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	})
	if _, err := cat2.ResolveService(
		context.Background(),
		gcphardening.ParsedHost{Service: "storage"},
		"storage.googleapis.com",
	); err != nil {
		t.Fatalf("stale-cache fallback: %v", err)
	}
}

// TestCatalogShellPartialFetchIsCachedUntilTTL documents the accepted
// behavior change: a transient doc failure yields a PARTIAL catalog that IS
// cached and served for the whole TTL — the dropped service is denied (not in
// catalog) until refresh, never over-permitted.
func TestCatalogShellPartialFetchIsCachedUntilTTL(t *testing.T) {
	t.Parallel()
	storageCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[` +
			`{"name":"compute","version":"v1","discoveryRestUrl":"DOC/compute"},` +
			`{"name":"storage","version":"v1","discoveryRestUrl":"DOC/storage"}]}`))
	})
	mux.HandleFunc("/DOC/compute", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://compute.googleapis.com/","servicePath":"compute/v1/","methods":{}}`))
	})
	mux.HandleFunc("/DOC/storage", func(w http.ResponseWriter, _ *http.Request) {
		storageCalls++
		http.Error(w, "down", http.StatusServiceUnavailable) // transiently down.
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfg := gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	}

	cat := gcphardening.NewCatalog(cfg)
	if _, err := cat.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "compute"}, "compute.googleapis.com",
	); err != nil {
		t.Fatalf("compute resolve: %v", err)
	}
	// Dropped service is denied and STAYS denied within the TTL (partial cached).
	if _, err := cat.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "storage"}, "storage.googleapis.com",
	); err == nil {
		t.Errorf("storage resolve = nil err, want denial (dropped service cached out)")
	}
	// A fresh instance sharing the dir reads the cached partial from disk — no
	// re-fetch, so storage's doc is requested exactly once.
	cat2 := gcphardening.NewCatalog(cfg)
	if _, err := cat2.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "compute"}, "compute.googleapis.com",
	); err != nil {
		t.Fatalf("fresh instance compute resolve (from disk): %v", err)
	}
	if storageCalls != 1 {
		t.Errorf("storage doc fetched %d times, want 1 (partial cached, not retried within TTL)", storageCalls)
	}
}

// TestCatalogShellPermanentDocMissingStillCaches verifies that a permanently
// missing doc (404 — a listed API whose discovery doc is gone) does NOT block
// caching: the catalog is still complete-enough to persist, the dead service is
// silently skipped, and a fresh instance serves from the cache without re-fetching.
func TestCatalogShellPermanentDocMissingStillCaches(t *testing.T) {
	t.Parallel()
	directoryHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		directoryHits++
		_, _ = w.Write([]byte(`{"items":[` +
			`{"name":"compute","version":"v1","discoveryRestUrl":"DOC/compute"},` +
			`{"name":"deadapi","version":"v1","discoveryRestUrl":"DOC/deadapi"}]}`))
	})
	mux.HandleFunc("/DOC/compute", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rootUrl":"https://compute.googleapis.com/","servicePath":"compute/v1/","methods":{}}`))
	})
	mux.HandleFunc("/DOC/deadapi", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound) // permanent: a retired API still listed in the directory.
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	}
	cat := gcphardening.NewCatalog(cfg)
	if _, err := cat.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "compute"}, "compute.googleapis.com",
	); err != nil {
		t.Fatalf("compute resolve: %v", err)
	}

	// A fresh instance must resolve from the persisted cache (no re-fetch), proving
	// the 404'd service did not block the catalog from being cached as complete.
	cat2 := gcphardening.NewCatalog(cfg)
	if _, err := cat2.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "compute"}, "compute.googleapis.com",
	); err != nil {
		t.Fatalf("fresh instance compute resolve (should hit disk cache): %v", err)
	}
	if directoryHits != 1 {
		t.Errorf("directory fetched %d times, want 1 (catalog cached despite the dead API)", directoryHits)
	}
}

func TestCatalogShellEmptyDirectoryError(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		HTTPClient:   srv.Client(),
	})
	_, err := cat.ResolveService(
		context.Background(),
		gcphardening.ParsedHost{Service: "compute"},
		"compute.googleapis.com",
	)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestCatalogShellDirectoryFetchError(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		HTTPClient:   srv.Client(),
	})
	_, err := cat.ResolveService(
		context.Background(),
		gcphardening.ParsedHost{Service: "compute"},
		"compute.googleapis.com",
	)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// TestCatalogShellAllDocsTransientErrors pins that when every doc fails
// transiently the catalog is empty and ResolveService surfaces the
// empty-directory error rather than serving a hollow catalog.
func TestCatalogShellAllDocsTransientErrors(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/apis", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"name":"storage","version":"v1","discoveryRestUrl":"DOC/storage"}]}`))
	})
	mux.HandleFunc("/DOC/storage", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable) // transient.
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := gcphardening.NewCatalog(gcphardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		DirectoryURL: srv.URL + "/discovery/v1/apis",
		BaseURL:      srv.URL + "/",
		HTTPClient:   srv.Client(),
	})
	if _, err := cat.ResolveService(
		context.Background(), gcphardening.ParsedHost{Service: "storage"}, "storage.googleapis.com",
	); err == nil {
		t.Fatal("expected empty-directory error when all docs fail transiently")
	}
}
