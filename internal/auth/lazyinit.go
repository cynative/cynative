package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// hardeningBootstrapTimeout is the dedicated budget for a cloud provider's
// one-time hardening bootstrap (identity → role union → permission catalog).
// The bootstrap is decoupled from the per-request context (see
// lazyInit.bootstrapContext): it is a session-level setup step, so a short
// model-chosen request timeout — or the GCP permission-catalog enumeration,
// which pages through every testable IAM permission on the project — must not be
// able to abort it and cache a not_ready failure for the whole session.
const hardeningBootstrapTimeout = 90 * time.Second

// lazyInit is the shared deferred-initialization scaffold embedded by the
// cloud providers (aws/gcp/azure). doLazyResolve runs at most once via once;
// both success and failure are cached for the process lifetime. prefix is the
// per-provider error namespace (e.g. "aws_hardening"). bootstrapTimeout is the
// dedicated budget for that one-time resolve, decoupled from the caller's
// per-request deadline (zero leaves the caller context unchanged).
type lazyInit struct {
	prefix           string
	bootstrapTimeout time.Duration
	once             sync.Once
	err              error
	doLazyResolve    func(ctx context.Context) error
}

// ensureReady runs the one-time deferred initialization captured in
// doLazyResolve, caching its outcome. It returns an error if the provider was
// constructed without a doLazyResolve closure. The resolve runs under a
// dedicated bootstrap context (see bootstrapContext) so it is not aborted by a
// short per-request timeout.
func (l *lazyInit) ensureReady(ctx context.Context) error {
	if l.doLazyResolve == nil {
		return fmt.Errorf("%s: provider not wired (no doLazyResolve)", l.prefix)
	}

	l.once.Do(func() {
		bootstrapCtx, cancel := l.bootstrapContext(ctx)
		defer cancel()
		if err := l.doLazyResolve(bootstrapCtx); err != nil {
			l.err = fmt.Errorf("%s: not_ready: %w", l.prefix, err)
		}
	})

	return l.err
}

// bootstrapContext derives the context for the one-time resolve. With a positive
// bootstrapTimeout it detaches from the caller's deadline/cancellation
// (context.WithoutCancel) and applies the dedicated budget, so a short
// model-chosen request timeout cannot abort — and then permanently cache the
// failure of — the hardening bootstrap. A non-positive budget leaves the
// caller context unchanged (used by test-only lazyInit constructions).
func (l *lazyInit) bootstrapContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if l.bootstrapTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), l.bootstrapTimeout)
}
