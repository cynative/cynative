package cache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// strDoc is a trivial parsed type for exercising TTLCache[T].
type strDoc struct {
	V string `json:"V"`
}

func parseStr(raw []byte) (*strDoc, error) {
	var d strDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d.V == "" {
		return nil, errors.New("empty V")
	}
	return &d, nil
}

const goodRaw = `{"V":"ok"}`

func newCache(dir string, clock func() time.Time,
	fetch func(context.Context) ([]byte, error),
) *TTLCache[strDoc] {
	return &TTLCache[strDoc]{
		DataPath: filepath.Join(dir, "sub", "data.json"),
		MetaPath: filepath.Join(dir, "sub", "data.meta"),
		TTL:      time.Hour,
		Clock:    clock,
		Fetch:    fetch,
		Parse:    parseStr,
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedDisk persists goodRaw to a fresh dir via a working cache, returns the dir.
func seedDisk(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { return []byte(goodRaw), nil })
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Fatalf("seed Get = %v, want ok", got)
	}
	return dir
}

func TestTTLCache_lazyFetchAndMemoize(t *testing.T) {
	t.Parallel()
	calls := 0
	c := newCache(t.TempDir(), time.Now,
		func(context.Context) ([]byte, error) { calls++; return []byte(goodRaw), nil })
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Fatalf("first Get = %v, want ok", got)
	}
	_ = c.Get(t.Context())
	if calls != 1 {
		t.Errorf("Fetch called %d times, want 1 (memoized)", calls)
	}
}

func TestTTLCache_fetchFailureReturnsNil(t *testing.T) {
	t.Parallel()
	c := newCache(t.TempDir(), time.Now,
		func(context.Context) ([]byte, error) { return nil, errors.New("network") })
	if got := c.Get(t.Context()); got != nil {
		t.Errorf("Get on fetch failure = %v, want nil", got)
	}
}

func TestTTLCache_retriesAfterTransientFailure(t *testing.T) {
	t.Parallel()
	calls := 0
	c := newCache(t.TempDir(), time.Now,
		func(context.Context) ([]byte, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("transient")
			}
			return []byte(goodRaw), nil
		})
	if got := c.Get(t.Context()); got != nil {
		t.Fatalf("first Get = %v, want nil on transient failure", got)
	}
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Fatalf("second Get = %v, want recovery after retry", got)
	}
	if calls != 2 {
		t.Errorf("Fetch called %d times, want 2 (retry after transient)", calls)
	}
}

func TestTTLCache_corruptFetchedReturnsNil(t *testing.T) {
	t.Parallel()
	c := newCache(t.TempDir(), time.Now,
		func(context.Context) ([]byte, error) { return []byte("{bad"), nil })
	if got := c.Get(t.Context()); got != nil {
		t.Errorf("Get on corrupt fetched = %v, want nil", got)
	}
}

func TestTTLCache_corruptFetchedAllowsRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	c := newCache(t.TempDir(), time.Now,
		func(context.Context) ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("{bad"), nil // Corrupt parse: must not memoize.
			}
			return []byte(goodRaw), nil
		})
	if got := c.Get(t.Context()); got != nil {
		t.Fatalf("first Get = %v, want nil on parse failure", got)
	}
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Fatalf("second Get = %v, want retry after parse failure", got)
	}
	if calls != 2 {
		t.Errorf("Fetch called %d times, want 2 (parse failure not memoized)", calls)
	}
}

func TestTTLCache_diskHitSkipsFetch(t *testing.T) {
	t.Parallel()
	dir := seedDisk(t)
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { return nil, errors.New("should not fetch") })
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Errorf("Get = %v, want disk hit", got)
	}
}

func TestTTLCache_staleDiskFallsBackOnFetchFailure(t *testing.T) {
	t.Parallel()
	dir := seedDisk(t)
	c := newCache(dir,
		func() time.Time { return time.Now().Add(48 * time.Hour) },
		func(context.Context) ([]byte, error) { return nil, errors.New("network") })
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Errorf("Get = %v, want stale disk fallback", got)
	}
}

func TestTTLCache_missingMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "sub"))
	mustWrite(t, filepath.Join(dir, "sub", "data.json"), []byte(goodRaw))
	called := false
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { called = true; return []byte(goodRaw), nil })
	_ = c.Get(t.Context())
	if !called {
		t.Errorf("expected fetch when .meta is absent")
	}
}

func TestTTLCache_corruptMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "sub"))
	mustWrite(t, filepath.Join(dir, "sub", "data.json"), []byte(goodRaw))
	mustWrite(t, filepath.Join(dir, "sub", "data.meta"), []byte("{bad"))
	called := false
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { called = true; return []byte(goodRaw), nil })
	_ = c.Get(t.Context())
	if !called {
		t.Errorf("expected fetch when meta is corrupt")
	}
}

func TestTTLCache_corruptDiskDataFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "sub"))
	mustWrite(t, filepath.Join(dir, "sub", "data.json"), []byte("{bad"))
	mustWrite(t, filepath.Join(dir, "sub", "data.meta"),
		[]byte(`{"fetched_at":"2024-01-01T00:00:00Z"}`))
	called := false
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { called = true; return []byte(goodRaw), nil })
	_ = c.Get(t.Context())
	if !called {
		t.Errorf("expected fetch when disk data is corrupt")
	}
}

func TestTTLCache_persistMkdirFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	mustWrite(t, blocker, []byte("file-not-dir"))
	c := &TTLCache[strDoc]{
		DataPath: filepath.Join(blocker, "data.json"), // MkdirAll(blocker) fails: blocker is a file.
		MetaPath: filepath.Join(blocker, "data.meta"),
		TTL:      time.Hour,
		Clock:    time.Now,
		Fetch:    func(context.Context) ([]byte, error) { return []byte(goodRaw), nil },
		Parse:    parseStr,
	}
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Errorf("Get = %v, want parsed despite persist mkdir failure", got)
	}
}

func TestTTLCache_dataWriteFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Place a directory where data.json should be written so os.WriteFile fails.
	mustMkdir(t, filepath.Join(dir, "sub", "data.json"))
	c := newCache(dir, time.Now,
		func(context.Context) ([]byte, error) { return []byte(goodRaw), nil })
	if got := c.Get(t.Context()); got == nil || got.V != "ok" {
		t.Errorf("Get = %v, want parsed despite data write failure", got)
	}
}

// distillStr is the "distill" step (parse raw → *strDoc; empty V errors).
func distillStr(raw []byte) (*strDoc, error) { return parseStr(raw) }

// serializeStr is the "serialize" step: re-marshal the parsed doc.
func serializeStr(d *strDoc) []byte { b, _ := json.Marshal(d); return b }

func admitOK(*strDoc) error     { return nil }
func admitReject(*strDoc) error { return errors.New("rejected") }

func TestNewTableCache_FetchDistillSerializeParse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := NewTableCache(
		Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		func(context.Context) ([]byte, error) { return []byte(goodRaw), nil },
		distillStr, serializeStr, parseStr, admitOK,
	)
	got := c.Get(context.Background())
	if got == nil || got.V != "ok" {
		t.Fatalf("Get = %+v, want {V:ok}", got)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "table.json"))
	if err != nil {
		t.Fatalf("read cached table: %v", err)
	}
	if _, parseErr := parseStr(blob); parseErr != nil {
		t.Fatalf("cached blob not parseable: %v", parseErr)
	}
}

func TestNewTableCache_DistillErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c := NewTableCache(
		Config{Dir: t.TempDir(), TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		func(context.Context) ([]byte, error) { return []byte(`{}`), nil }, // empty V → distill error
		distillStr, serializeStr, parseStr, admitOK,
	)
	if got := c.Get(context.Background()); got != nil {
		t.Fatalf("Get with distill error = %+v, want nil", got)
	}
}

func TestNewTableCache_FetchErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c := NewTableCache(
		Config{Dir: t.TempDir(), TTL: time.Hour, Clock: func() time.Time { return time.Unix(1, 0) }},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
		distillStr, serializeStr, parseStr, admitOK,
	)
	if got := c.Get(context.Background()); got != nil {
		t.Fatalf("Get with fetch error + no cache = %+v, want nil", got)
	}
}

func TestNewTableCache_AdmitRejectionFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "table.json"), []byte(goodRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"fetched_at":"` + now.UTC().Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "table.meta"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewTableCache(
		Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now }},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
		distillStr, serializeStr, parseStr, admitReject,
	)
	if got := c.Get(context.Background()); got != nil {
		t.Fatalf("Get with admit-rejected cached blob = %+v, want nil", got)
	}
}

func TestNewTableCache_UnmarshalErrorFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Write a blob that is syntactically invalid JSON so unmarshal (parseStr) fails.
	if err := os.WriteFile(filepath.Join(dir, "table.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"fetched_at":"` + now.UTC().Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "table.meta"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewTableCache(
		Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now }},
		func(context.Context) ([]byte, error) { return nil, errors.New("offline") },
		distillStr, serializeStr, parseStr, admitOK,
	)
	if got := c.Get(context.Background()); got != nil {
		t.Fatalf("Get with unmarshal-error cached blob = %+v, want nil", got)
	}
}
