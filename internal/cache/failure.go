package cache

import (
	"context"
	"sync"
)

// LoadFailure keeps the last error a cache's fetch returned, because [TTLCache.Get] reports a failed load only as
// nil. A fetch that distills, as NewNamedCache wires it, records a distill error too.
type LoadFailure struct {
	mu  sync.Mutex
	err error
}

// RecordLoadFailure wraps c's fetch so its outcome is kept. Call it before c is shared.
func RecordLoadFailure[T any](c *TTLCache[T]) *LoadFailure {
	f := new(LoadFailure)
	fetch := c.Fetch
	c.Fetch = func(ctx context.Context) ([]byte, error) {
		raw, err := fetch(ctx)
		f.mu.Lock()
		f.err = err
		f.mu.Unlock()

		return raw, err
	}

	return f
}

// Err returns the last fetch error: nil before any fetch, after a successful one, or for a nil recorder.
func (f *LoadFailure) Err() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.err
}
