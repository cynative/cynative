package auth

import (
	"context"
	"sync"
)

// openAPIHandoff passes one successful table download to the docs cache, so a
// cold start fetches the GitHub OpenAPI once. The table's fetch is never served
// from it and errors are never recorded, so the table keeps its own retry and
// stale-fallback behavior.
type openAPIHandoff struct {
	mu  sync.Mutex
	raw []byte
}

// record wraps fetch so a successful download is kept for the next take.
func (h *openAPIHandoff) record(fetch func(context.Context) ([]byte, error)) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		raw, err := fetch(ctx)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.raw = raw
		h.mu.Unlock()

		return raw, nil
	}
}

// take wraps fetch so a recorded download is served once, then cleared.
func (h *openAPIHandoff) take(fetch func(context.Context) ([]byte, error)) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		h.mu.Lock()
		raw := h.raw
		h.raw = nil
		h.mu.Unlock()
		if raw != nil {
			return raw, nil
		}

		return fetch(ctx)
	}
}
