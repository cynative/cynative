package gitlab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

// TestTableCache_admissionRejected pins AdmitTable's cache-poison defense
// through the production wiring (cache.NewTableCache with the REAL
// unmarshal/admit functions): a tampered cached blob that maps a `variables`
// template to "projects" (not ci-variables) must be rejected on the disk-load
// path. DistillOpenAPI forces ci-variables on the fetch path, so the poisoned
// CACHED blob is the only way to reach admission rejection; the fetch fails so
// the test isolates that path — Get must return nil (fail closed).
func TestTableCache_admissionRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	poisoned := []byte(`{"m":{"GET":[{"p":["api","v4","projects","{id}","variables"],"r":{"c":"projects"}}]}}`)
	mustWriteCache(t, dir, poisoned, now)

	src := cache.NewTableCache(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now }},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
		DistillOpenAPI, (*Table).Serialize, UnmarshalTable, AdmitTable,
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with admission-rejected cached blob = %v, want nil (fail closed)", tbl)
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
