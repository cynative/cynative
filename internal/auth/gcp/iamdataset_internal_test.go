package gcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "iam_dataset", "map-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func mustMkdirGCP(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWriteGCP(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedIAMDatasetDisk persists the fixture to a fresh cache dir via a registry
// with a working fetcher, returning the dir for a second registry to read.
func seedIAMDatasetDisk(t *testing.T, fixture []byte) string {
	t.Helper()
	dir := t.TempDir()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return fixture, nil },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) == 0 {
		t.Fatalf("seed lookup returned nothing")
	}
	return dir
}

func TestParseIAMDataset(t *testing.T) {
	t.Parallel()

	d, err := ParseIAMDataset(readFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// insert: high-confidence create + manual actAs; restcrawlv1 subnetworks.use dropped. Sorted.
	insert := d.Lookup("compute.instances.insert")
	want := []string{"compute.instances.create", "iam.serviceAccounts.actAs"}
	if len(insert) != len(want) || insert[0] != want[0] || insert[1] != want[1] {
		t.Errorf("insert perms = %v, want %v", insert, want)
	}
	if perms := d.Lookup("compute.instances.get"); len(perms) != 1 || perms[0] != "compute.instances.get" {
		t.Errorf("get perms = %v, want [compute.instances.get]", perms)
	}
	// Low-confidence-only and empty methods produce no entry → nil.
	if perms := d.Lookup("compute.instances.lowconf"); perms != nil {
		t.Errorf("lowconf should be nil (filtered), got %v", perms)
	}
	if perms := d.Lookup("compute.instances.empty"); perms != nil {
		t.Errorf("empty should be nil, got %v", perms)
	}
	if perms := d.Lookup("compute.instances.unknown"); perms != nil {
		t.Errorf("unknown should be nil, got %v", perms)
	}
}

func TestParseIAMDatasetErrors(t *testing.T) {
	t.Parallel()

	if _, err := ParseIAMDataset([]byte("not json")); !errors.Is(err, ErrIAMDatasetUnavailable) {
		t.Errorf("malformed json: want ErrIAMDatasetUnavailable, got %v", err)
	}
	if _, err := ParseIAMDataset([]byte(`{"api":{}}`)); !errors.Is(err, ErrIAMDatasetUnavailable) {
		t.Errorf("empty api map: want ErrIAMDatasetUnavailable, got %v", err)
	}
}

func TestIAMDatasetRegistry(t *testing.T) {
	t.Parallel()

	fixture := readFixture(t)
	clock := func() time.Time { return time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC) }

	t.Run("fetch and cache", func(t *testing.T) {
		t.Parallel()
		calls := 0
		reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
			Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: clock},
			Fetcher: func(context.Context) ([]byte, error) { calls++; return fixture, nil },
		})
		if got := reg.Lookup(context.Background(), "compute.instances.get"); len(got) != 1 {
			t.Fatalf("Lookup = %v, want 1 perm", got)
		}
		_ = reg.Lookup(context.Background(), "compute.instances.get")
		if calls != 1 {
			t.Errorf("fetcher called %d times, want 1 (memoized after success)", calls)
		}
	})

	t.Run("retries after a transient failure", func(t *testing.T) {
		t.Parallel()
		calls := 0
		reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
			Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: clock},
			Fetcher: func(context.Context) ([]byte, error) {
				calls++
				if calls == 1 {
					return nil, errors.New("transient") // first load fails, no disk → nil.
				}
				return fixture, nil
			},
		})
		// First Lookup fails (nil), but must NOT lock in the nil; the second Lookup
		// re-fetches and succeeds. (sync.Once would have returned nil forever.)
		if got := reg.Lookup(context.Background(), "compute.instances.get"); got != nil {
			t.Fatalf("first Lookup = %v, want nil on transient failure", got)
		}
		if got := reg.Lookup(context.Background(), "compute.instances.get"); len(got) != 1 {
			t.Fatalf("second Lookup = %v, want recovery after retry", got)
		}
		if calls != 2 {
			t.Errorf("fetcher called %d times, want 2 (retry after transient failure)", calls)
		}
	})

	t.Run("fetch error no disk", func(t *testing.T) {
		t.Parallel()
		reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
			Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: clock},
			Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("boom") },
		})
		if got := reg.Lookup(context.Background(), "compute.instances.get"); got != nil {
			t.Errorf("degraded Lookup = %v, want nil", got)
		}
	})

	t.Run("fetch parse error", func(t *testing.T) {
		t.Parallel()
		reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
			Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: clock},
			Fetcher: func(context.Context) ([]byte, error) { return []byte("bad"), nil },
		})
		if got := reg.Lookup(context.Background(), "x"); got != nil {
			t.Errorf("parse-error Lookup = %v, want nil", got)
		}
	})
}

func TestIAMDatasetRegistry_diskHitSkipsFetch(t *testing.T) {
	t.Parallel()
	dir := seedIAMDatasetDisk(t, readFixture(t))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("should not fetch") },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) != 1 {
		t.Errorf("Lookup = %v, want disk hit", got)
	}
}

func TestIAMDatasetRegistry_staleDiskFallsBackOnFetchFailure(t *testing.T) {
	t.Parallel()
	dir := seedIAMDatasetDisk(t, readFixture(t))
	aheadClock := func() time.Time { return time.Now().Add(48 * time.Hour) }
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: aheadClock},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("network") },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) != 1 {
		t.Errorf("Lookup = %v, want stale disk fallback", got)
	}
}

func TestIAMDatasetRegistry_missingMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdirGCP(t, filepath.Join(dir, "iam-dataset"))
	mustWriteGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.json"), readFixture(t))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "compute.instances.get")
	if !called {
		t.Errorf("expected fetch when .meta file is absent")
	}
}

func TestIAMDatasetRegistry_corruptMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdirGCP(t, filepath.Join(dir, "iam-dataset"))
	mustWriteGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.json"), readFixture(t))
	mustWriteGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.meta"), []byte("{bad"))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "compute.instances.get")
	if !called {
		t.Errorf("expected fetch when meta is corrupt")
	}
}

func TestIAMDatasetRegistry_corruptDiskMapFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdirGCP(t, filepath.Join(dir, "iam-dataset"))
	mustWriteGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.json"), []byte("{bad"))
	mustWriteGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.meta"),
		[]byte(`{"fetched_at":"2024-01-01T00:00:00Z"}`))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "compute.instances.get")
	if !called {
		t.Errorf("expected fetch when disk map is corrupt")
	}
}

func TestIAMDatasetRegistry_persistMkdirFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	mustWriteGCP(t, blocker, []byte("file-not-dir"))
	// MkdirAll(blocker/iam-dataset) fails: blocker is a file.
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: blocker, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readFixture(t), nil },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) != 1 {
		t.Errorf("Lookup = %v, want parsed despite persist mkdir failure", got)
	}
}

func TestIAMDatasetRegistry_mapWriteFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Place a directory where gcp-map.json should be written so os.WriteFile fails.
	mustMkdirGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.json"))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readFixture(t), nil },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) != 1 {
		t.Errorf("Lookup = %v, want parsed despite map write failure", got)
	}
}

func TestIAMDatasetRegistry_metaWriteFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Place a directory where gcp-map.meta should be written so os.WriteFile fails.
	mustMkdirGCP(t, filepath.Join(dir, "iam-dataset", "gcp-map.meta"))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readFixture(t), nil },
	})
	if got := reg.Lookup(t.Context(), "compute.instances.get"); len(got) != 1 {
		t.Errorf("Lookup = %v, want parsed despite meta write failure", got)
	}
}
