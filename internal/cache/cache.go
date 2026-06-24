// Package cache holds a generic on-disk TTL cache primitive shared by the
// aws/gcp/azure auth subpackages, plus the Config that namespaces it per
// provider. It is a pure standard-library leaf — it imports nothing from
// internal/auth — so the auth subpackages may depend on it without an import
// cycle.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DirPerm and FilePerm are the permission bits for the on-disk cache directory
// and files. They unify the per-cloud drift (aws used 0o750, gcp 0o700) onto a
// single owner-only posture.
const (
	DirPerm  = 0o700
	FilePerm = 0o600
)

// Config bundles the cache knobs every consumer shares: the (already
// per-provider-namespaced) cache root directory, the freshness TTL, and the
// clock. Consumers embed it to drop the repeated {Dir, TTL, Clock} triple.
type Config struct {
	Dir   string
	TTL   time.Duration
	Clock func() time.Time
}

// diskMeta is the sidecar written next to each cached payload; FetchedAt drives
// the TTL freshness check on load.
type diskMeta struct {
	FetchedAt time.Time `json:"fetched_at"`
}

// TTLCache is a generic on-disk TTL cache: in-memory → on-disk (per TTL) →
// Fetch, with stale-disk fallback on a Fetch error. A transient load failure
// returns nil AND leaves the cache unloaded, so a later Get retries — not
// [sync.Once], which would lock in the nil for the whole process. Errors are
// never memoized.
type TTLCache[T any] struct {
	DataPath string
	MetaPath string
	TTL      time.Duration
	Clock    func() time.Time
	Fetch    func(ctx context.Context) ([]byte, error)
	Parse    func([]byte) (*T, error)

	mu     sync.Mutex
	loaded bool
	data   *T // nil until a successful load.
}

// Get loads and memoizes the parsed payload on first success. A transient load
// failure (nil) leaves the cache unloaded so a later Get retries.
func (c *TTLCache[T]) Get(ctx context.Context) *T {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		if d := c.load(ctx); d != nil {
			c.data = d
			c.loaded = true
		}
	}
	return c.data
}

// load resolves the payload: fresh disk → Fetch (with stale-disk fallback on
// error). Returns nil on any unrecoverable failure; never memoizes a failure.
func (c *TTLCache[T]) load(ctx context.Context) *T {
	if disk, age, ok := c.tryLoadDisk(); ok && age <= c.TTL {
		return disk
	}
	raw, err := c.Fetch(ctx)
	if err != nil {
		if disk, _, ok := c.tryLoadDisk(); ok {
			return disk // Stale fallback.
		}
		return nil
	}
	parsed, err := c.Parse(raw)
	if err != nil {
		return nil
	}
	_ = c.persistDisk(raw) // Best-effort; parsed result is returned regardless.
	return parsed
}

// tryLoadDisk reads + parses the persisted payload and returns its age.
func (c *TTLCache[T]) tryLoadDisk() (*T, time.Duration, bool) {
	raw, err := os.ReadFile(c.DataPath)
	if err != nil {
		return nil, 0, false
	}
	metaRaw, err := os.ReadFile(c.MetaPath)
	if err != nil {
		return nil, 0, false
	}
	var meta diskMeta
	if metaErr := json.Unmarshal(metaRaw, &meta); metaErr != nil {
		return nil, 0, false
	}
	parsed, err := c.Parse(raw)
	if err != nil {
		return nil, 0, false
	}
	return parsed, c.Clock().Sub(meta.FetchedAt), true
}

// persistDisk writes the raw payload + meta sidecar best-effort.
func (c *TTLCache[T]) persistDisk(raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(c.DataPath), DirPerm); err != nil {
		return fmt.Errorf("mkdir cache: %w", err)
	}
	meta := diskMeta{FetchedAt: c.Clock()}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ") //nolint:errchkjson // infallible for diskMeta.
	if err := os.WriteFile(c.DataPath, raw, FilePerm); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return os.WriteFile(c.MetaPath, metaBytes, FilePerm)
}

// NewTableCache builds a TTLCache that resolves a distilled category table:
// fresh on-disk → live fetch (distill+serialize) → stale on-disk → nil (fail
// closed). cfg.Dir must already be namespaced to the connector (e.g.
// <cache>/github). The wired Fetch runs fetch→distill→serialize so the cache
// persists the compact distilled form, not the raw spec; the wired Parse runs
// unmarshal→admit so a poisoned/corrupted source (fetched OR cached) is rejected
// by admit before it can become active policy — the ordering is load-bearing.
func NewTableCache[T any](
	cfg Config,
	fetch func(ctx context.Context) ([]byte, error),
	distill func(raw []byte) (*T, error),
	serialize func(*T) []byte,
	unmarshal func([]byte) (*T, error),
	admit func(*T) error,
) *TTLCache[T] {
	return &TTLCache[T]{ //nolint:exhaustruct // mu/loaded/data zero-valued by design.
		DataPath: filepath.Join(cfg.Dir, "table.json"),
		MetaPath: filepath.Join(cfg.Dir, "table.meta"),
		TTL:      cfg.TTL,
		Clock:    cfg.Clock,
		Fetch: func(ctx context.Context) ([]byte, error) {
			raw, err := fetch(ctx)
			if err != nil {
				return nil, err
			}
			tbl, err := distill(raw)
			if err != nil {
				return nil, err
			}
			return serialize(tbl), nil
		},
		Parse: func(b []byte) (*T, error) {
			tbl, err := unmarshal(b)
			if err != nil {
				return nil, err
			}
			if admitErr := admit(tbl); admitErr != nil {
				return nil, admitErr
			}
			return tbl, nil
		},
	}
}
