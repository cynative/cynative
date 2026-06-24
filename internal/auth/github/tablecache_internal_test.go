package github

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

const fixtureOpenAPI = `{"paths":{
	"/user": {"get": {"x-github": {"category":"users","subcategory":"users"}}},
	"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}}
}}`

func fixedClock(ts time.Time) func() time.Time { return func() time.Time { return ts } }

func TestTableSource_fetchDistillCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	src := NewTableSource(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(now)},
		func(context.Context) ([]byte, error) { return []byte(fixtureOpenAPI), nil },
	)

	tbl := src.Get(context.Background())
	if tbl == nil {
		t.Fatal("Get returned nil, want a table")
	}
	if r, ok := tbl.Lookup("GET", "/user"); !ok || r.Category != "users" {
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

func TestTableSource_poisonedCacheRejected(t *testing.T) {
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
	blob := poison.Serialize()
	mustWriteCache(t, dir, blob, now)

	// Fetch yields a clean table; because the poisoned disk fails Parse(admit),
	// the loader must fall through to the fetched-and-admitted table.
	src := NewTableSource(
		cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(now)},
		func(context.Context) ([]byte, error) { return []byte(fixtureOpenAPI), nil },
	)
	tbl := src.Get(context.Background())
	if tbl == nil {
		t.Fatal("Get = nil, want the clean fetched table")
	}
	if r, ok := tbl.Lookup("GET", "/repos/o/r/secret-scanning/alerts"); !ok || r.Category != "secret-scanning" {
		t.Fatalf("poisoned route survived: %+v ok=%v", r, ok)
	}
}

func TestTableSource_fetchDistillError(t *testing.T) {
	t.Parallel()

	src := NewTableSource(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: fixedClock(time.Unix(1, 0))},
		// Invalid JSON — DistillOpenAPI returns an error.
		func(context.Context) ([]byte, error) { return []byte(`not json`), nil },
	)
	if tbl := src.Get(context.Background()); tbl != nil {
		t.Fatalf("Get with distill error = %v, want nil (fail closed)", tbl)
	}
}

func TestTableSource_parseMalformedBlob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	// Write a malformed blob (not a valid distilled table) to the cache.
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
