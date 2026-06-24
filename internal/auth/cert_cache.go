package auth

import (
	"context"
	"sync"

	"golang.org/x/sync/singleflight"
)

// syncCache is a concurrency-safe, success-only cache for any data.
// It uses singleflight to coalesce concurrent lookups for the same key and a
// mutex-protected map to store results. Errors are NOT cached — a transient
// failure will be retried on the next call.
type syncCache[T any] struct {
	mu    sync.Mutex
	items map[string]T
	sfg   singleflight.Group
}

// get returns the cached value for key, or calls fetch to populate it.
// The fetch function is called at most once per key concurrently.
func (c *syncCache[T]) get(
	ctx context.Context,
	key string,
	fetch func(ctx context.Context) (T, error),
) (T, error) {
	c.mu.Lock()
	if c.items == nil {
		c.items = make(map[string]T)
	}

	if data, ok := c.items[key]; ok {
		c.mu.Unlock()

		return data, nil
	}

	c.mu.Unlock()

	v, err, _ := c.sfg.Do(key, func() (any, error) {
		return fetch(ctx)
	})
	if err != nil {
		var zero T
		return zero, err
	}

	data, _ := v.(T)

	c.mu.Lock()
	if _, ok := c.items[key]; !ok {
		c.items[key] = data
	}
	c.mu.Unlock()

	return data, nil
}
