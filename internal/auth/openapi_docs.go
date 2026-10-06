package auth

import (
	"context"
	"sync"

	"github.com/cynative/cynative/internal/auth/openapidoc"
	"github.com/cynative/cynative/internal/cache"
)

// hintLatch remembers that the denial path failed to load docs. Hint records
// the epoch before loading; a failure latches only if no successful load
// (Reference) reset the latch since then.
type hintLatch struct {
	mu     sync.Mutex
	epoch  uint64
	failed bool
}

// begin returns the current epoch and whether the latch is set.
func (l *hintLatch) begin() (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.epoch, l.failed
}

// fail sets the latch only if no reset happened since begin returned epoch.
func (l *hintLatch) fail(epoch uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.epoch == epoch {
		l.failed = true
	}
}

// reset clears the latch and invalidates every earlier epoch.
func (l *hintLatch) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.epoch++
	l.failed = false
}

// openAPIDocs serves one connector's cached OpenAPI operation docs to its
// Reference and Hint. It never touches credentials, probes or the gate's table.
type openAPIDocs struct {
	// cache is nil when no docs are wired (bare providers in tests).
	cache *cache.TTLCache[openapidoc.OperationDocs]
	// hintMu serializes the Hint path's latch check, docs load and latch set, so
	// concurrent denials queue behind the first load instead of each retrying it.
	hintMu sync.Mutex
	// hintFailed latches once a Hint-path docs load fails with a live context,
	// so the error path does not re-download the document on every denied
	// request. A successful Reference load resets it; the epoch orders that
	// reset against a Hint failure that was already in flight.
	hintFailed hintLatch
}

// forReference loads the docs for an api_reference lookup. A successful load
// re-enables the Hint path.
func (o *openAPIDocs) forReference(ctx context.Context) *openapidoc.OperationDocs {
	d := o.load(ctx)
	if d != nil {
		o.hintFailed.reset()
	}

	return d
}

// forHint loads the docs for an unmatched-request hint, or returns nil without
// loading once a Hint-path load has failed.
func (o *openAPIDocs) forHint(ctx context.Context) *openapidoc.OperationDocs {
	o.hintMu.Lock()
	defer o.hintMu.Unlock()
	epoch, failed := o.hintFailed.begin()
	if failed {
		return nil
	}
	d := o.load(ctx)
	// A cancelled denial says nothing about the docs, so it must not disable
	// hints for the process.
	if d == nil && ctx.Err() == nil {
		o.hintFailed.fail(epoch)
	}

	return d
}

// load returns the docs, or nil when none are wired or loadable.
func (o *openAPIDocs) load(ctx context.Context) *openapidoc.OperationDocs {
	if o.cache == nil {
		return nil
	}

	return o.cache.Get(ctx)
}
