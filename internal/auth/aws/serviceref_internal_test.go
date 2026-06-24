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

func readSRFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "serviceref", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestParseServiceRef_s3(t *testing.T) {
	t.Parallel()
	m, err := ParseServiceRef(readSRFixture(t))
	if err != nil {
		t.Fatalf("ParseServiceRef: %v", err)
	}
	if m.Service != "s3" {
		t.Errorf("Service = %q, want s3", m.Service)
	}
	lb, ok := m.Operations["ListBuckets"]
	if !ok {
		t.Fatalf("ListBuckets missing")
	}
	if got := lb.AuthorizedActions; len(got) != 1 || got[0] != "s3:ListAllMyBuckets" {
		t.Errorf("ListBuckets actions = %v, want [s3:ListAllMyBuckets]", got)
	}
	// Duplicate (Service,Name) entries must dedup: ListObjectsV2 has ListBucket twice.
	lo := m.Operations["ListObjectsV2"]
	if got := lo.AuthorizedActions; len(got) != 2 {
		t.Errorf("ListObjectsV2 deduped actions = %v, want 2 (GetObjectAcl, ListBucket)", got)
	}
	// Empty AuthorizedActions but SDK names retained for the tier-2 join.
	plc := m.Operations["PutBucketLifecycleConfiguration"]
	if len(plc.AuthorizedActions) != 0 {
		t.Errorf("PutBucketLifecycleConfiguration actions = %v, want empty", plc.AuthorizedActions)
	}
	if want := []string{"s3", "s3control"}; !equalStrings(plc.SDKNames, want) {
		t.Errorf("SDKNames = %v, want %v", plc.SDKNames, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseServiceRef_malformedJSON(t *testing.T) {
	t.Parallel()
	if _, err := ParseServiceRef([]byte("{not-json")); !errors.Is(err, ErrServiceRefUnavailable) {
		t.Errorf("err = %v, want ErrServiceRefUnavailable", err)
	}
}

func TestParseServiceRef_missingName(t *testing.T) {
	t.Parallel()
	if _, err := ParseServiceRef([]byte(`{"Operations":[]}`)); !errors.Is(err, ErrServiceRefUnavailable) {
		t.Errorf("err = %v, want ErrServiceRefUnavailable", err)
	}
}

func TestParseServiceRef_emptyOperations(t *testing.T) {
	t.Parallel()
	m, err := ParseServiceRef([]byte(`{"Name":"s3","Operations":[]}`))
	if err != nil {
		t.Fatalf("ParseServiceRef: %v", err)
	}
	if len(m.Operations) != 0 {
		t.Errorf("Operations = %v, want empty", m.Operations)
	}
}

func TestServiceRefRegistry_inMemoryCacheHit(t *testing.T) {
	t.Parallel()
	fixture := readSRFixture(t)
	calls := 0
	reg := NewServiceRefRegistry(ServiceRefRegistryConfig{
		Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(_ context.Context, _ string) ([]byte, error) {
			calls++
			return fixture, nil
		},
	})
	if m := reg.Get(t.Context(), "s3"); m == nil {
		t.Fatal("first Get: got nil, want model")
	}
	if m := reg.Get(t.Context(), "s3"); m == nil {
		t.Fatal("second Get: got nil, want model")
	}
	if calls != 1 {
		t.Errorf("Fetcher called %d times, want 1", calls)
	}
}

func TestServiceRefRegistry_missAndFetchFailureReturnsNil(t *testing.T) {
	t.Parallel()
	reg := NewServiceRefRegistry(ServiceRefRegistryConfig{
		Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(_ context.Context, _ string) ([]byte, error) {
			return nil, errors.New("simulated network failure")
		},
	})
	if m := reg.Get(t.Context(), "s3"); m != nil {
		t.Fatalf("expected nil on fetch failure, got %v", m)
	}
}

func TestServiceRefRegistry_perServiceCaches(t *testing.T) {
	t.Parallel()
	fixture := readSRFixture(t)
	reg := NewServiceRefRegistry(ServiceRefRegistryConfig{
		Config: cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(_ context.Context, service string) ([]byte, error) {
			if service == "missing" {
				return nil, errors.New("no such service")
			}
			return fixture, nil
		},
	})
	if m := reg.Get(t.Context(), "s3"); m == nil {
		t.Fatal("Get s3: got nil, want model")
	}
	if m := reg.Get(t.Context(), "missing"); m != nil {
		t.Fatalf("Get missing: got %v, want nil", m)
	}
}
