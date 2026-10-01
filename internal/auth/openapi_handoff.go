package auth

import (
	"context"
	"sync"
	"time"
)

// openAPIHandoff passes one successful table download to the docs cache, so a
// cold start fetches the GitHub OpenAPI once. The table's fetch is never served
// from it and errors are never recorded, so the table keeps its own retry and
// stale-fallback behavior. Bytes older than ttl are discarded, because the
// docs cache stamps what it takes with the time it takes it.
type openAPIHandoff struct {
	clock func() time.Time
	ttl   time.Duration
	mu    sync.Mutex
	raw   []byte
	at    time.Time
}

func newOpenAPIHandoff(clock func() time.Time, ttl time.Duration) *openAPIHandoff {
	return &openAPIHandoff{clock: clock, ttl: ttl, mu: sync.Mutex{}, raw: nil, at: time.Time{}}
}

// record wraps fetch so a successful download is kept for the next take.
func (h *openAPIHandoff) record(fetch func(context.Context) ([]byte, error)) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		raw, err := fetch(ctx)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.raw, h.at = raw, h.clock()
		h.mu.Unlock()

		return raw, nil
	}
}

// take wraps fetch so a recorded download is served once, then cleared.
func (h *openAPIHandoff) take(fetch func(context.Context) ([]byte, error)) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		h.mu.Lock()
		raw, at := h.raw, h.at
		h.raw = nil
		h.mu.Unlock()
		if raw != nil && h.clock().Sub(at) <= h.ttl {
			return raw, nil
		}

		return fetch(ctx)
	}
}
