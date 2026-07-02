package github

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

// newTestTableCache wires DistillOpenAPI/Serialize/UnmarshalTable/AdmitTable
// into cache.NewTableCache exactly as the production construction site
// (registration.go) does, over a temp cache dir and fixed clock.
func newTestTableCache(dir string, now time.Time, fetch func(context.Context) ([]byte, error)) *cache.TTLCache[Table] {
	return cache.NewTableCache(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now }},
		fetch, DistillOpenAPI, (*Table).Serialize, UnmarshalTable, AdmitTable,
	)
}

// TestTableCache_poisonedCacheRejected pins the admit-before-activate ordering
// with the REAL distill/admit functions: a fresh-but-poisoned cached blob that
// downgrades a secret-scanning template must fail AdmitTable on the disk-load
// path, and the loader must fall through to the clean fetched table.
func TestTableCache_poisonedCacheRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	// Hand-write a "fresh" but poisoned cache that downgrades secret-scanning.
	poison, err := DistillOpenAPI([]byte(`{"paths":{
		"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"repos","subcategory":"contents"}}}
	}}`))
	if err != nil {
		t.Fatalf("distill poison: %v", err)
	}
	mustWriteCache(t, dir, poison.Serialize(), now)

	clean := `{"paths":{
		"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}}
	}}`
	src := newTestTableCache(dir, now, func(context.Context) ([]byte, error) { return []byte(clean), nil })

	tbl := src.Get(context.Background())
	if tbl == nil {
		t.Fatal("Get = nil, want the clean fetched table")
	}
	if r, ok := tbl.Lookup("GET", "/repos/o/r/secret-scanning/alerts"); !ok || r.Category != "secret-scanning" {
		t.Fatalf("poisoned route survived: %+v ok=%v", r, ok)
	}
}

// mustWriteCache writes a TTLCache data+meta pair so the disk load sees it fresh.
func mustWriteCache(t *testing.T, dir string, blob []byte, ts time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "table.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"fetched_at":"` + ts.UTC().Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "table.meta"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
}
