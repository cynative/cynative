package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

var errHandoffFetch = errors.New("fetch failed")

type countedFetch struct {
	calls atomic.Int32
	// failFirst makes call number 1 fail.
	failFirst bool
}

func (c *countedFetch) fetch(context.Context) ([]byte, error) {
	n := c.calls.Add(1)
	if c.failFirst && n == 1 {
		return nil, errHandoffFetch
	}

	return []byte("doc"), nil
}

func idCache(dir, name string, fetch func(context.Context) ([]byte, error)) *cache.TTLCache[string] {
	return cache.NewNamedCache(cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now}, name, fetch,
		func(b []byte) (*string, error) { s := string(b); return &s, nil },
		func(s *string) []byte { return []byte(*s) },
		func(b []byte) (*string, error) { s := string(b); return &s, nil },
		func(*string) error { return nil })
}

func TestOpenAPIHandoff_TableThenDocsFetchesOnce(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{}
	table, docs := h.record(f.fetch), h.take(f.fetch)
	if _, err := table(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := docs(t.Context())
	if err != nil || string(got) != "doc" || f.calls.Load() != 1 {
		t.Errorf("got %q %v calls=%d", got, err, f.calls.Load())
	}
}

func TestOpenAPIHandoff_DocsFirstFetchesTwice(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{}
	table, docs := h.record(f.fetch), h.take(f.fetch)
	if _, err := docs(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := table(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", f.calls.Load())
	}
}

func TestOpenAPIHandoff_SlotIsOneShot(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{}
	table, docs := h.record(f.fetch), h.take(f.fetch)
	for _, fn := range []func(context.Context) ([]byte, error){table, docs, docs} {
		if _, err := fn(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", f.calls.Load())
	}
}

func TestOpenAPIHandoff_ErrorsAreNotRecorded(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{failFirst: true}
	table, docs := h.record(f.fetch), h.take(f.fetch)
	if _, err := table(t.Context()); !errors.Is(err, errHandoffFetch) {
		t.Fatalf("err = %v", err)
	}
	if _, err := docs(t.Context()); err != nil || f.calls.Load() != 2 {
		t.Errorf("err=%v calls=%d, want nil and 2", err, f.calls.Load())
	}
}

func TestOpenAPIHandoff_TableAlwaysFetches(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{}
	table := h.record(f.fetch)
	for range 2 {
		if _, err := table(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", f.calls.Load())
	}
}

func TestOpenAPIHandoff_TableRecovery(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{failFirst: true}
	dir := t.TempDir()
	tableCache := idCache(dir, "table", h.record(f.fetch))
	docsCache := idCache(dir, "docs", h.take(f.fetch))
	if tableCache.Get(t.Context()) != nil {
		t.Fatal("table must fail on the first fetch")
	}
	if docsCache.Get(t.Context()) == nil || f.calls.Load() != 2 {
		t.Fatalf("docs must fetch itself, calls=%d", f.calls.Load())
	}
	if tableCache.Get(t.Context()) == nil || f.calls.Load() != 3 {
		t.Errorf("table must retry its own fetch, calls=%d", f.calls.Load())
	}
}

func TestOpenAPIHandoff_DocsFirstRecovery(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{failFirst: true}
	dir := t.TempDir()
	tableCache := idCache(dir, "table", h.record(f.fetch))
	docsCache := idCache(dir, "docs", h.take(f.fetch))
	if docsCache.Get(t.Context()) != nil {
		t.Fatal("docs must fail on the first fetch")
	}
	if tableCache.Get(t.Context()) == nil {
		t.Fatal("table must succeed")
	}
	if docsCache.Get(t.Context()) == nil {
		t.Error("docs must recover")
	}
}

func TestOpenAPIHandoff_ConcurrentColdStart(t *testing.T) {
	t.Parallel()
	h, f := newOpenAPIHandoff(time.Now, time.Hour), &countedFetch{}
	dir := t.TempDir()
	tableCache := idCache(dir, "table", h.record(f.fetch))
	docsCache := idCache(dir, "docs", h.take(f.fetch))
	var wg sync.WaitGroup
	var tableOK, docsOK atomic.Bool
	wg.Add(2)
	go func() { defer wg.Done(); tableOK.Store(tableCache.Get(t.Context()) != nil) }()
	go func() { defer wg.Done(); docsOK.Store(docsCache.Get(t.Context()) != nil) }()
	wg.Wait()
	if !tableOK.Load() || !docsOK.Load() {
		t.Fatalf("table=%v docs=%v", tableOK.Load(), docsOK.Load())
	}
	if n := f.calls.Load(); n < 1 || n > 2 {
		t.Errorf("calls = %d, want 1 or 2", n)
	}
}

func TestOpenAPIHandoff_ExpiresStaleBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		age       time.Duration
		wantCalls int32
	}{
		{"fresh bytes are served", time.Hour, 1},
		{"stale bytes are discarded and refetched", time.Hour + time.Nanosecond, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.Unix(1_000_000, 0)
			h, f := newOpenAPIHandoff(func() time.Time { return now }, time.Hour), &countedFetch{}
			table, docs := h.record(f.fetch), h.take(f.fetch)
			if _, err := table(t.Context()); err != nil {
				t.Fatal(err)
			}
			now = now.Add(tc.age)
			if got, err := docs(t.Context()); err != nil || string(got) != "doc" {
				t.Fatalf("got %q %v", got, err)
			}
			if f.calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", f.calls.Load(), tc.wantCalls)
			}
		})
	}
}
