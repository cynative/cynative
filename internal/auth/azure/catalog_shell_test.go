package azure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
	"github.com/cynative/cynative/internal/cache"
)

// armEndpointsBody is the 2022 object shape for one cloud's /metadata/endpoints.
func armEndpointsBody(rm string) string {
	return `{"resourceManager":"https://` + rm + `/","authentication":{"audiences":["https://management.core.windows.net/"]},` +
		`"suffixes":{"storage":"core.windows.net","keyVaultDns":"vault.azure.net"}}`
}

func TestCatalogShellFetchAndProbe(t *testing.T) {
	t.Parallel()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Query().Get("api-version") != "2022-09-01" {
			http.Error(w, "bad api-version", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(armEndpointsBody("management.azure.com")))
	})
	mux.HandleFunc("/providers/Microsoft.Authorization/providerOperations",
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"value":[{"name":"Microsoft.Compute","resourceTypes":[` +
				`{"name":"virtualMachines","operations":[` +
				`{"name":"Microsoft.Compute/virtualMachines/read","isDataAction":false}]}]}]}`))
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := azurehardening.NewCatalog(azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:     cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		HTTPClient: srv.Client(),
		// Point all three clouds at the test server (public used; gov/china may 404
		// gracefully — the catalog stands on the reachable cloud).
		MetadataURLs: map[string]string{"AzureCloud": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	})

	got, err := cat.ResolveCloud(context.Background(), azurehardening.ParsedHost{Host: "management.azure.com"})
	if err != nil || got.Cloud != "AzureCloud" {
		t.Fatalf("ResolveCloud = %+v err=%v", got, err)
	}
	// Second call must come from cache (endpoints not re-fetched).
	_, err = cat.ResolveCloud(context.Background(), azurehardening.ParsedHost{Host: "management.azure.com"})
	if err != nil {
		t.Fatalf("second ResolveCloud: %v", err)
	}
	if hits != 1 {
		t.Errorf("/metadata/endpoints fetched %d times, want 1 (cache miss + reuse)", hits)
	}
}

func TestCatalogShellRejects2019ArrayShape(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		// The 2019 array shape — startup probe must fail closed.
		_, _ = w.Write([]byte(`[{"resourceManager":"https://management.azure.com/"}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := azurehardening.NewCatalog(azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		HTTPClient:   srv.Client(),
		MetadataURLs: map[string]string{"AzureCloud": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	})

	_, err := cat.ResolveCloud(context.Background(), azurehardening.ParsedHost{Host: "management.azure.com"})
	if err == nil || !strings.Contains(err.Error(), "azure_hardening") {
		t.Fatalf("2019 array shape: expected fail-closed catalog error, got %v", err)
	}
}

func TestCatalogShellStaleCacheFallback(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	unavailable := false
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		if unavailable {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(armEndpointsBody("management.azure.com")))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfg := azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Millisecond, Clock: time.Now},
		HTTPClient:   srv.Client(),
		MetadataURLs: map[string]string{"AzureCloud": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	}
	cat := azurehardening.NewCatalog(cfg)
	if _, err := cat.ResolveCloud(
		context.Background(),
		azurehardening.ParsedHost{Host: "management.azure.com"},
	); err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// New instance, TTL expired, server down → stale cache must answer.
	unavailable = true
	cat2 := azurehardening.NewCatalog(cfg)
	if _, err := cat2.ResolveCloud(
		context.Background(),
		azurehardening.ParsedHost{Host: "management.azure.com"},
	); err != nil {
		t.Fatalf("stale-cache fallback: %v", err)
	}
}

// TestCatalogShellProviderOpsFailureIsCachedUntilTTL documents the accepted
// behavior change: a providerOps failure yields an empty-Providers catalog that
// IS cached and authoritative for the TTL. Layer-3 host pinning still works
// (Clouds populated); Layer-2 action checks deny until refresh — never
// over-permitted.
func TestCatalogShellProviderOpsFailureIsCachedUntilTTL(t *testing.T) {
	t.Parallel()
	poCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(armEndpointsBody("management.azure.com")))
	})
	mux.HandleFunc("/providers/Microsoft.Authorization/providerOperations",
		func(w http.ResponseWriter, _ *http.Request) {
			poCalls++
			http.Error(w, "unauthorized", http.StatusUnauthorized) // always fails.
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		HTTPClient:   srv.Client(),
		MetadataURLs: map[string]string{"AzureCloud": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	}

	cat := azurehardening.NewCatalog(cfg)
	// Layer-3 host pinning survives the providerOps failure.
	if _, err := cat.ResolveCloud(
		context.Background(), azurehardening.ParsedHost{Host: "management.azure.com"},
	); err != nil {
		t.Fatalf("ResolveCloud (Layer-3 must survive): %v", err)
	}
	// Layer-2 is denied and STAYS denied within the TTL (empty catalog cached).
	if _, err := cat.ResourceTypes(context.Background(), "Microsoft.Compute"); err == nil {
		t.Errorf("ResourceTypes = nil err, want denial (empty catalog cached)")
	}
	// A fresh instance sharing the cache dir reads the persisted empty catalog from
	// disk: Layer-3 still resolves (Clouds persisted), Layer-2 still denies, and no
	// providerOps re-fetch happens within the TTL.
	cat2 := azurehardening.NewCatalog(cfg)
	if _, err := cat2.ResolveCloud(
		context.Background(), azurehardening.ParsedHost{Host: "management.azure.com"},
	); err != nil {
		t.Fatalf("fresh instance ResolveCloud (Layer-3 from disk): %v", err)
	}
	if _, err := cat2.ResourceTypes(context.Background(), "Microsoft.Compute"); err == nil {
		t.Errorf("fresh instance ResourceTypes = nil err, want denial (empty catalog persisted)")
	}
	// poCalls is shared by cat and cat2: 1 = cat's first fetch only; cat2 must add
	// zero (it reads the persisted empty catalog from disk, no re-fetch).
	if poCalls != 1 {
		t.Errorf("providerOperations fetched %d times, want 1 (empty cached, not retried within TTL)", poCalls)
	}
}

func TestCatalogShellFetchError(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cat := azurehardening.NewCatalog(azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		HTTPClient:   srv.Client(),
		MetadataURLs: map[string]string{"AzureCloud": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	})
	if _, err := cat.ResolveCloud(
		context.Background(),
		azurehardening.ParsedHost{Host: "management.azure.com"},
	); err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// TestCatalogShellCloudScoped pins the cloud-scoping: a catalog resolved to one
// sovereign cloud resolves only that cloud's host (host-pin narrowed) and writes
// its cache to a cloud-scoped path.
func TestCatalogShellCloudScoped(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(armEndpointsBody("management.usgovcloudapi.net")))
	})
	mux.HandleFunc("/providers/Microsoft.Authorization/providerOperations",
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"value":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cat := azurehardening.NewCatalog(azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		HTTPClient:   srv.Client(),
		Cloud:        "AzureUSGovernment",
		MetadataURLs: map[string]string{"AzureUSGovernment": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	})
	got, err := cat.ResolveCloud(context.Background(),
		azurehardening.ParsedHost{Host: "management.usgovcloudapi.net"})
	if err != nil || got.Cloud != "AzureUSGovernment" {
		t.Fatalf("gov resolve = %+v err=%v", got, err)
	}
	// Host pinning is narrowed to the resolved cloud: a public host fails closed.
	if _, herr := cat.ResolveCloud(context.Background(),
		azurehardening.ParsedHost{Host: "management.azure.com"}); herr == nil {
		t.Error("public host accepted under gov-scoped catalog, want rejection")
	}
	// The on-disk cache is scoped by cloud name.
	if _, serr := os.Stat(filepath.Join(dir, "catalog", "azure-AzureUSGovernment.json")); serr != nil {
		t.Errorf("expected cloud-scoped cache file: %v", serr)
	}
}

// TestCatalogShellRejectsCrossCloudCache proves the validate-in-Parse defense: a
// fresh on-disk cache whose Clouds set is not the resolved cloud is rejected at
// parse, forcing a fresh fetch (not a stuck-until-TTL deny).
func TestCatalogShellRejectsCrossCloudCache(t *testing.T) {
	t.Parallel()
	fetches := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/endpoints", func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		_, _ = w.Write([]byte(armEndpointsBody("management.usgovcloudapi.net")))
	})
	mux.HandleFunc("/providers/Microsoft.Authorization/providerOperations",
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"value":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	catDir := filepath.Join(dir, "catalog")
	if err := os.MkdirAll(catDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Pre-write a fresh but WRONG-cloud cache at the gov-scoped path.
	stale, err := json.Marshal(azurehardening.CatalogData{
		Clouds: map[string]azurehardening.CloudEndpoints{
			"AzureCloud": {ResourceManager: "management.azure.com", Suffixes: map[string]string{"x": "y"}},
		},
		Providers: map[string]azurehardening.ProviderOps{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(filepath.Join(catDir, "azure-AzureUSGovernment.json"), stale, 0o600); werr != nil {
		t.Fatal(werr)
	}
	meta := `{"fetched_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`
	if werr := os.WriteFile(
		filepath.Join(catDir, "azure-AzureUSGovernment.json.meta"),
		[]byte(meta),
		0o600,
	); werr != nil {
		t.Fatal(werr)
	}

	cat := azurehardening.NewCatalog(azurehardening.CatalogConfig{ //nolint:exhaustruct // optional fields omitted.
		Config:       cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		HTTPClient:   srv.Client(),
		Cloud:        "AzureUSGovernment",
		MetadataURLs: map[string]string{"AzureUSGovernment": srv.URL + "/metadata/endpoints"},
		BaseURL:      srv.URL,
	})
	got, rerr := cat.ResolveCloud(context.Background(),
		azurehardening.ParsedHost{Host: "management.usgovcloudapi.net"})
	if rerr != nil || got.Cloud != "AzureUSGovernment" {
		t.Fatalf("gov resolve after stale-cache reject = %+v err=%v", got, rerr)
	}
	if fetches == 0 {
		t.Error("expected a fresh fetch after rejecting the cross-cloud cache (validate-in-Parse)")
	}
}
