package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

func readMapFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "iam_dataset", "map-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
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

// seedIAMDatasetDisk persists the fixture to a fresh cache dir via a registry
// with a working fetcher, returning the dir for a second registry to read.
func seedIAMDatasetDisk(t *testing.T, fixture []byte) string {
	t.Helper()
	dir := t.TempDir()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return fixture, nil },
	})
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); len(got) == 0 {
		t.Fatalf("seed lookup returned nothing")
	}
	return dir
}

func TestParseIAMDataset_malformedJSON(t *testing.T) {
	t.Parallel()
	if _, err := ParseIAMDataset([]byte("{bad")); !errors.Is(err, ErrIAMDatasetUnavailable) {
		t.Errorf("err = %v, want ErrIAMDatasetUnavailable", err)
	}
}

func TestParseIAMDataset_emptyMappings(t *testing.T) {
	t.Parallel()
	if _, err := ParseIAMDataset([]byte(`{"sdk_method_iam_mappings":{}}`)); !errors.Is(err, ErrIAMDatasetUnavailable) {
		t.Errorf("err = %v, want ErrIAMDatasetUnavailable", err)
	}
}

// TestIAMDataset_Lookup exercises the data-driven service join and, by parsing
// the fixture, the index-building in ParseIAMDataset.
func TestIAMDataset_Lookup(t *testing.T) {
	t.Parallel()
	d, err := ParseIAMDataset(readMapFixture(t))
	if err != nil {
		t.Fatalf("ParseIAMDataset: %v", err)
	}
	tests := []struct {
		name     string
		service  string
		sdkNames []string
		op       string
		want     []string
	}{
		{
			"exact-fold s3", "s3",
			[]string{"s3", "s3control"},
			"PutBucketLifecycleConfiguration",
			[]string{"s3:PutLifecycleConfiguration"},
		},
		{"override logs", "logs", []string{"logs"}, "StartLiveTail", []string{"logs:StartLiveTail"}},
		{
			"fold apigw", "execute-api",
			[]string{"apigatewaymanagementapi"},
			"GetConnection",
			[]string{"execute-api:ManageConnections"},
		},
		{
			"prefer exact-fold rds over docdb", "rds",
			[]string{"rds"},
			"DescribeDBInstances",
			[]string{"rds:DescribeDBInstances"},
		},
		{"service-name fallback when sdkNames empty", "logs", nil, "StartLiveTail", []string{"logs:StartLiveTail"}},
		{"miss returns nil", "s3", []string{"s3"}, "NoSuchOp", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := d.Lookup(tt.service, tt.sdkNames, tt.op)
			if !equalStrings(got, tt.want) {
				t.Errorf("Lookup(%q,%v,%q) = %v, want %v", tt.service, tt.sdkNames, tt.op, got, tt.want)
			}
		})
	}
}

func TestIAMDatasetRegistry_lazyFetchOnceAndLookup(t *testing.T) {
	t.Parallel()
	fixture := readMapFixture(t)
	calls := 0
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			calls++
			return fixture, nil
		},
	})
	got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail")
	if len(got) != 1 || got[0] != "logs:StartLiveTail" {
		t.Errorf("Lookup = %v, want [logs:StartLiveTail]", got)
	}
	_ = reg.Lookup(t.Context(), "s3", []string{"s3"}, "PutBucketLifecycleConfiguration")
	if calls != 1 {
		t.Errorf("Fetcher called %d times, want 1 (parsed dataset memoized)", calls)
	}
}

func TestIAMDatasetRegistry_retriesAfterTransientFailure(t *testing.T) {
	t.Parallel()
	fixture := readMapFixture(t)
	calls := 0
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("transient") // first load fails, no disk → nil.
			}
			return fixture, nil
		},
	})
	// First access fails (nil) but must NOT lock in the nil; the second access
	// re-fetches and succeeds. (sync.Once would have returned nil forever.)
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); got != nil {
		t.Fatalf("first Lookup = %v, want nil on transient failure", got)
	}
	got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail")
	if len(got) != 1 || got[0] != "logs:StartLiveTail" {
		t.Fatalf("second Lookup = %v, want recovery after retry", got)
	}
	if calls != 2 {
		t.Errorf("Fetcher called %d times, want 2 (retry after transient failure)", calls)
	}
}

func TestIAMDatasetRegistry_fetchFailureReturnsNil(t *testing.T) {
	t.Parallel()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("network") },
	})
	if got := reg.Lookup(t.Context(), "s3", []string{"s3"}, "PutBucketLifecycleConfiguration"); got != nil {
		t.Errorf("Lookup on fetch failure = %v, want nil", got)
	}
}

func TestIAMDatasetRegistry_diskHitSkipsFetch(t *testing.T) {
	t.Parallel()
	dir := seedIAMDatasetDisk(t, readMapFixture(t))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("should not fetch") },
	})
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); len(got) != 1 {
		t.Errorf("Lookup = %v, want disk hit", got)
	}
}

func TestIAMDatasetRegistry_staleDiskFallsBackOnFetchFailure(t *testing.T) {
	t.Parallel()
	dir := seedIAMDatasetDisk(t, readMapFixture(t))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{
			Dir:   dir,
			TTL:   time.Hour,
			Clock: func() time.Time { return time.Now().Add(48 * time.Hour) },
		},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("network") },
	})
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); len(got) != 1 {
		t.Errorf("Lookup = %v, want stale disk fallback", got)
	}
}

func TestIAMDatasetRegistry_corruptFetchedReturnsNil(t *testing.T) {
	t.Parallel()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return []byte("{bad"), nil },
	})
	if got := reg.Lookup(t.Context(), "s3", []string{"s3"}, "PutBucketLifecycleConfiguration"); got != nil {
		t.Errorf("Lookup on corrupt fetched = %v, want nil", got)
	}
}

func TestIAMDatasetRegistry_missingMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "iam-dataset"))
	mustWrite(t, filepath.Join(dir, "iam-dataset", "map.json"), readMapFixture(t))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readMapFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail")
	if !called {
		t.Errorf("expected fetch when .meta file is absent")
	}
}

func TestIAMDatasetRegistry_corruptMetaFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "iam-dataset"))
	mustWrite(t, filepath.Join(dir, "iam-dataset", "map.json"), readMapFixture(t))
	mustWrite(t, filepath.Join(dir, "iam-dataset", "map.meta"), []byte("{bad"))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readMapFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail")
	if !called {
		t.Errorf("expected fetch when meta is corrupt")
	}
}

func TestIAMDatasetRegistry_corruptDiskMapFallsThroughToFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "iam-dataset"))
	mustWrite(t, filepath.Join(dir, "iam-dataset", "map.json"), []byte("{bad"))
	mustWrite(t, filepath.Join(dir, "iam-dataset", "map.meta"),
		[]byte(`{"service":"iam-dataset","sha256":"deadbeef","fetched_at":"2024-01-01T00:00:00Z"}`))
	called := false
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) {
			called = true
			return readMapFixture(t), nil
		},
	})
	_ = reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail")
	if !called {
		t.Errorf("expected fetch when disk map is corrupt")
	}
}

func TestIAMDatasetRegistry_persistMkdirFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	mustWrite(t, blocker, []byte("file-not-dir"))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		// MkdirAll(blocker/iam-dataset) fails: blocker is a file.
		Config:  cache.Config{Dir: blocker, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readMapFixture(t), nil },
	})
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); len(got) != 1 {
		t.Errorf("Lookup = %v, want parsed despite persist mkdir failure", got)
	}
}

func TestIAMDatasetRegistry_mapWriteFailureStillReturnsParsed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Place a directory where map.json should be written so os.WriteFile fails.
	mustMkdir(t, filepath.Join(dir, "iam-dataset", "map.json"))
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readMapFixture(t), nil },
	})
	if got := reg.Lookup(t.Context(), "logs", []string{"logs"}, "StartLiveTail"); len(got) != 1 {
		t.Errorf("Lookup = %v, want parsed despite map write failure", got)
	}
}

func TestIAMDataset_LookupSDKID(t *testing.T) {
	t.Parallel()
	d, err := ParseIAMDataset(readMapFixture(t))
	if err != nil {
		t.Fatalf("ParseIAMDataset: %v", err)
	}
	tests := []struct {
		name, sdkID, op string
		want            []string
	}{
		{"smithy spelling joins", "S3 Control", "GetPublicAccessBlock", []string{"s3:GetAccountPublicAccessBlock"}},
		{"dataset spelling", "S3Control", "GetPublicAccessBlock", []string{"s3:GetAccountPublicAccessBlock"}},
		{"hyphen-free lower", "s3control", "GetPublicAccessBlock", []string{"s3:GetAccountPublicAccessBlock"}},
		{"primary S3", "S3", "GetPublicAccessBlock", []string{"s3:GetBucketPublicAccessBlock"}},
		// IoT/Iot normalize together → union of both ids' actions, candidates sorted
		// ("IoT" < "Iot"), shared "iot:Describe" de-duplicated to first-seen.
		{"casing-dup union", "IoT", "GetThing", []string{"iot:Describe", "iot:GetThingShadow", "iot:DescribeThing"}},
		{"miss returns nil", "S3 Control", "NoSuchOp", nil},
		{"unknown sdkID returns nil", "NotAService", "GetPublicAccessBlock", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := d.LookupSDKID(tt.sdkID, tt.op)
			if !equalStrings(got, tt.want) {
				t.Errorf("LookupSDKID(%q,%q) = %v, want %v", tt.sdkID, tt.op, got, tt.want)
			}
		})
	}
}

func TestIAMDatasetRegistry_LookupSDKID(t *testing.T) {
	t.Parallel()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return readMapFixture(t), nil },
	})
	got := reg.LookupSDKID(t.Context(), "S3 Control", "GetPublicAccessBlock")
	if len(got) != 1 || got[0] != "s3:GetAccountPublicAccessBlock" {
		t.Errorf("LookupSDKID = %v, want [s3:GetAccountPublicAccessBlock]", got)
	}
}

func TestIAMDatasetRegistry_LookupSDKID_unavailableReturnsNil(t *testing.T) {
	t.Parallel()
	reg := NewIAMDatasetRegistry(IAMDatasetRegistryConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("network") },
	})
	if got := reg.LookupSDKID(t.Context(), "S3 Control", "GetPublicAccessBlock"); got != nil {
		t.Errorf("LookupSDKID on unavailable dataset = %v, want nil", got)
	}
}
