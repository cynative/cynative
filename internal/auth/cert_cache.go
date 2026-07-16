package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// syncCache is a concurrency-safe, success-only cache for K8s bootstrap facts
// (cluster TLS material, view policies). It uses singleflight to coalesce
// concurrent lookups for the same key and a mutex-protected map to store
// results. Errors are NOT cached — a transient failure will be retried on the
// next call. Each fetch is bounded by timeout (defaulting to
// k8sBootstrapFetchTimeout when zero): a fixed whole-operation ceiling that keeps
// a stalled cluster endpoint from wedging the run.
type syncCache[T any] struct {
	mu      sync.Mutex
	items   map[string]T
	sfg     singleflight.Group
	timeout time.Duration
}

// get returns the cached value for key, or calls fetch to populate it. The fetch
// runs at most once per key concurrently, in its own goroutine (singleflight
// DoChan) under a cache-owned deadline (timeout) that is DETACHED from any single
// caller's cancellation, so one caller giving up cannot cut short the shared
// fetch for the others. Each caller then waits under its own deadline plus the
// same timeout as a backstop: the backstop is what bounds a fetch that ignores
// its context and blocks (e.g. an oauth2 token refresh inside a cloud SDK call),
// which a synchronous fetch could not escape. The caller's own deadline, when
// tighter, still wins.
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

	var zero T

	// Return before launching the detached fetch when the caller is already
	// cancelled: WithoutCancel would otherwise start a background cluster
	// resolve / ClusterRole fetch for an interrupted request or probe.
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = k8sBootstrapFetchTimeout
	}

	ch := c.sfg.DoChan(key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()

		return fetch(fctx)
	})

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-timer.C:
		// The fetch exceeded the cache-owned ceiling, so it is ignoring its
		// context and still running. Forget the key so the next lookup starts a
		// fresh fetch instead of coalescing onto the stuck one (which would make
		// every later request for this cluster time out until it unblocks).
		c.sfg.Forget(key)

		return zero, fmt.Errorf("k8s_hardening: bootstrap fetch %q exceeded %s", key, timeout)
	case res := <-ch:
		if res.Err != nil {
			return zero, res.Err
		}

		data, _ := res.Val.(T)

		c.mu.Lock()
		if _, ok := c.items[key]; !ok {
			c.items[key] = data
		}
		c.mu.Unlock()

		return data, nil
	}
}
