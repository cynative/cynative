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

// fixtureGitLabOpenAPI is a minimal OpenAPI v3 whose one operation tags Projects,
// so the distilled table maps GET /api/v4/projects to the "projects" category.
const fixtureGitLabOpenAPI = "openapi: \"3.0.0\"\npaths:\n  /api/v4/projects:\n    get:\n      tags: [\"Projects\"]\n"

func fixedClock(ts time.Time) func() time.Time { return func() time.Time { return ts } }

func TestTableSource_FetchDistillCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	src := NewTableSource(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(now)},
		func(context.Context) ([]byte, error) { return []byte(fixtureGitLabOpenAPI), nil },
	)

	tbl := src.Get(context.Background())
	if tbl == nil {
		t.Fatal("Get returned nil, want a table")
	}
	if r, ok := tbl.Lookup("GET", "/api/v4/projects"); !ok || r.Category != "projects" {
		t.Fatalf("lookup = %+v ok=%v", r, ok)
	}

	// The cached file is the small distilled form, not the raw OpenAPI.
	blob, readErr := os.ReadFile(filepath.Join(dir, "table.json"))
	if readErr != nil {
		t.Fatalf("read cached table: %v", readErr)
	}
	if _, parseErr := UnmarshalTable(blob); parseErr != nil {
		t.Fatalf("cached blob is not a distilled table: %v", parseErr)
	}
}

func TestTableSource_failClosedWhenFetchFailsAndNoCache(t *testing.T) {
	t.Parallel()

	src := NewTableSource(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: fixedClock(time.Unix(1, 0))},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with no cache + failing fetch = %v, want nil (fail closed)", tbl)
	}
}

func TestTableSource_fetchDistillError(t *testing.T) {
	t.Parallel()

	src := NewTableSource(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: fixedClock(time.Unix(1, 0))},
		// Invalid YAML — DistillOpenAPI returns an error.
		func(context.Context) ([]byte, error) { return []byte("\t: not: valid: yaml:"), nil },
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with distill error = %v, want nil (fail closed)", tbl)
	}
}

func TestTableSource_parseMalformedBlob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	// Write a malformed blob (not a valid distilled table) to the cache, so the
	// disk-load path drives parseAndAdmit's UnmarshalTable error branch.
	mustWriteCache(t, dir, []byte(`{bad json`), now)

	// Fetch also fails so the test isolates the parse error path.
	src := NewTableSource(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(now)},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with malformed cache + no fetch = %v, want nil", tbl)
	}
}

func TestTableSource_admissionRejected(t *testing.T) {
	t.Parallel()

	// A tampered cached blob that maps a `variables` template to "projects" (not
	// ci-variables). DistillOpenAPI now forces ci-variables on the fetch path, so
	// admission rejection is reachable only via a poisoned CACHED blob loaded from
	// disk through parseAndAdmit's UnmarshalTable → AdmitTable. Write it directly to
	// the cache file (fresh timestamp) and fail the fetch so the test isolates the
	// disk-load admission path.
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	poisoned := []byte(`{"m":{"GET":[{"p":["api","v4","projects","{id}","variables"],"r":{"c":"projects"}}]}}`)
	mustWriteCache(t, dir, poisoned, now)
	src := NewTableSource(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(now)},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with admission-rejected cached blob = %v, want nil (fail closed)", tbl)
	}
}

// mustWriteCache writes a TTLCache data+meta pair so tryLoadDisk sees it fresh.
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
