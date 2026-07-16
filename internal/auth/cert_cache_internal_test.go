package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestSyncCache_BoundsStalledFetch pins that get() bounds a fetch that stalls
// while observing its context: the cache-owned deadline ends it, so a stalled K8s
// bootstrap fetch cannot wedge the run even under a deadline-free caller context.
func TestSyncCache_BoundsStalledFetch(t *testing.T) {
	t.Parallel()

	c := &syncCache[int]{timeout: 60 * time.Millisecond} //nolint:exhaustruct // only timeout.

	start := time.Now()
	_, err := c.get(context.Background(), "k", func(ctx context.Context) (int, error) {
		<-ctx.Done() // stalled fetch that observes its context.

		return 0, ctx.Err()
	})
	if err == nil {
		t.Fatal("expected a timeout error from the bounded fetch, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fetch took %v; syncCache did not bound it", elapsed)
	}
}

// TestSyncCache_BoundsContextIgnoringFetch pins the backstop: a fetch that
// ignores its context and blocks (modelling an oauth2 token refresh inside a
// cloud-SDK call that a synchronous fetch could not escape) is still cut off, so
// the caller never wedges.
func TestSyncCache_BoundsContextIgnoringFetch(t *testing.T) {
	t.Parallel()

	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	c := &syncCache[int]{timeout: 60 * time.Millisecond} //nolint:exhaustruct // only timeout.

	start := time.Now()
	_, err := c.get(context.Background(), "k", func(context.Context) (int, error) {
		<-stuck // blocks WITHOUT observing the context; only the caller timer can end this.

		return 0, nil
	})
	if err == nil {
		t.Fatal("expected the timer backstop to bound the context-ignoring fetch, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("caller took %v; the timer backstop did not bound the context-ignoring fetch", elapsed)
	}
}

// TestSyncCache_TighterCallerDeadlineWins pins that a caller whose own deadline is
// tighter than the cache timeout returns on its own deadline (the cache timeout is
// a ceiling, not a floor). This is what keeps the 5s registration probe bounded.
func TestSyncCache_TighterCallerDeadlineWins(t *testing.T) {
	t.Parallel()

	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	c := &syncCache[int]{timeout: time.Hour} //nolint:exhaustruct // only timeout.

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.get(ctx, "k", func(context.Context) (int, error) {
		<-stuck

		return 0, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded from the caller deadline, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("caller took %v; its own (tighter) deadline should have bounded it", elapsed)
	}
}

// TestSyncCache_ReturnsFetchError pins that a fetch error propagates and is NOT
// cached (a later call retries).
func TestSyncCache_ReturnsFetchError(t *testing.T) {
	t.Parallel()

	c := &syncCache[int]{} //nolint:exhaustruct // zero value uses the default timeout.

	sentinel := errors.New("boom")
	var calls int
	fetch := func(context.Context) (int, error) {
		calls++

		return 0, sentinel
	}

	if _, err := c.get(context.Background(), "k", fetch); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel error, got %v", err)
	}
	if _, err := c.get(context.Background(), "k", fetch); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel error on retry, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("fetch called %d times; errors must not be cached (want 2)", calls)
	}
}

// TestSyncCache_AlreadyCancelledCallerSkipsFetch pins that an already-cancelled
// caller returns without launching the detached background fetch (an interrupted
// request or probe must not start a cluster resolve / ClusterRole fetch).
func TestSyncCache_AlreadyCancelledCallerSkipsFetch(t *testing.T) {
	t.Parallel()

	c := &syncCache[int]{timeout: time.Hour} //nolint:exhaustruct // only timeout.

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var started atomic.Bool
	_, err := c.get(ctx, "k", func(context.Context) (int, error) {
		started.Store(true)

		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if started.Load() {
		t.Fatal("fetch must not start for an already-cancelled caller")
	}
}

// TestSyncCache_ForgetsTimedOutFetch pins that after a context-ignoring fetch
// blocks past the cache timeout, a later lookup for the same key starts a FRESH
// fetch instead of coalescing onto the stuck one, so one stalled fetch cannot
// poison the connector for the rest of the process.
func TestSyncCache_ForgetsTimedOutFetch(t *testing.T) {
	t.Parallel()

	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	c := &syncCache[int]{timeout: 60 * time.Millisecond} //nolint:exhaustruct // only timeout.

	var starts atomic.Int32
	fetch := func(context.Context) (int, error) {
		starts.Add(1)
		<-stuck // ignores context and blocks past the timeout.

		return 0, nil
	}

	if _, err := c.get(context.Background(), "k", fetch); err == nil {
		t.Fatal("first call should time out")
	}
	if _, err := c.get(context.Background(), "k", fetch); err == nil {
		t.Fatal("second call should time out")
	}

	if got := starts.Load(); got != 2 {
		t.Fatalf("fetch started %d times; a timed-out fetch must be forgotten so the retry starts fresh (want 2)", got)
	}
}

// TestSyncCache_CallerGivingUpDoesNotFailPeer pins the coalescing isolation: when
// two callers miss the same key, one giving up on a tight deadline must not make
// the other (with a longer budget) fail. The shared fetch is detached from any
// single caller.
func TestSyncCache_CallerGivingUpDoesNotFailPeer(t *testing.T) {
	t.Parallel()

	c := &syncCache[int]{timeout: time.Hour} //nolint:exhaustruct // only timeout.

	leaderStarted := make(chan struct{})
	release := make(chan struct{})
	//nolint:unparam // the error result is fixed by syncCache.get's fetch signature; this stub always succeeds.
	fetch := func(context.Context) (int, error) {
		close(leaderStarted)
		<-release

		return 42, nil
	}

	// The leader (long budget) starts the shared fetch and blocks on release.
	leaderResult := make(chan int, 1)
	go func() {
		v, _ := c.get(context.Background(), "k", fetch)
		leaderResult <- v
	}()
	<-leaderStarted

	// A peer with a tight deadline coalesces onto the in-flight fetch and gives up.
	peerCtx, peerCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer peerCancel()
	if _, err := c.get(peerCtx, "k", fetch); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("peer should have timed out with DeadlineExceeded, got %v", err)
	}

	// The peer gave up; the leader must still receive the successful result.
	close(release)
	if v := <-leaderResult; v != 42 {
		t.Fatalf("leader got %d, want 42 (a peer giving up must not fail the leader)", v)
	}
}
