// Package metrics accumulates session-cumulative operational telemetry (token
// usage, round-trips, tool calls, sub-agents, verifiers, active compute time)
// for the research loop. It is a pure leaf over internal/schema: the model
// feeds it token usage through a sink and the agent loop feeds it counters; the
// CLI snapshots it after each turn to render the footer. Counters and usage
// accumulate for the whole session (they are never reset); StartTurn/EndTurn
// bracket each turn's active compute window so the rendered elapsed is the sum
// of those windows, excluding idle time between interactive follow-ups.
package metrics

import (
	"fmt"
	"sync"
	"time"

	"github.com/cynative/cynative/internal/schema"
)

// Clock returns the current time. It is injected so tests are deterministic;
// production uses [time.Now].
type Clock func() time.Time

// Stats is an immutable snapshot of the session's cumulative metrics.
type Stats struct {
	Elapsed    time.Duration
	RoundTrips int
	Responses  int
	ToolCalls  int
	Subagents  int
	Verifiers  int
	Usage      schema.Usage
	Provider   string
	Model      string
}

// Accumulator collects the session's cumulative metrics. All methods are
// nil-receiver-safe so an Agent built without a Metrics accumulator (e.g. in
// unit tests) is a no-op. A mutex guards every field so the accumulator stays
// safe under concurrent callers (e.g. AddUsage may arrive from a model layer
// while the loop records counters).
type Accumulator struct {
	mu        sync.Mutex
	clock     Clock
	provider  string
	model     string
	maxTokens int // Per-session token ceiling; 0 = unbounded.

	// Cumulative session totals — never reset. The footer renders these.
	roundTrips int
	responses  int
	toolCalls  int
	subagents  int
	verifiers  int
	usage      schema.Usage  // Cumulative reported usage breakdown.
	active     time.Duration // Σ active compute across turns; excludes idle.

	// billedTokens is the budget's token basis: Σ usageTokens(per-call). It MUST
	// be summed per call (each call uses TotalTokens, or the prompt+completion
	// fallback when TotalTokens is 0) because that sum cannot be reconstructed
	// from a summed Usage — so it is a genuinely distinct quantity from usage,
	// not a redundant copy.
	billedTokens int

	turnStart time.Time // Start of the in-progress turn; zero when none is open.

	// turnBaseline is a Snapshot captured at StartTurn (before turnStart is set),
	// persisting across EndTurn until the next StartTurn — the footer renders after
	// EndTurn. TurnSnapshot returns the cumulative snapshot minus this baseline.
	turnBaseline Stats
}

// Option configures an Accumulator at construction time.
type Option func(*Accumulator)

// WithClock injects a deterministic clock (test seam). A nil clock is ignored so
// the default [time.Now] is preserved.
func WithClock(c Clock) Option {
	return func(a *Accumulator) {
		if c != nil {
			a.clock = c
		}
	}
}

// WithBudget sets the per-session token ceiling. A zero limit is unbounded, so an
// accumulator built without this option stays unbounded (today's behavior).
func WithBudget(maxTokens int) Option {
	return func(a *Accumulator) {
		a.maxTokens = maxTokens
	}
}

// NewAccumulator builds an accumulator for the given provider/model. The clock
// defaults to [time.Now].
func NewAccumulator(provider, model string, opts ...Option) *Accumulator {
	a := &Accumulator{ //nolint:exhaustruct // mu/start/stats zero-init; clock defaulted below.
		clock:    time.Now,
		provider: provider,
		model:    model,
	}
	for _, o := range opts {
		o(a)
	}

	return a
}

// StartTurn opens a turn's active-compute window by recording the start time and
// captures the per-turn baseline (the cumulative snapshot so far). Counters and
// usage are session-cumulative and are not reset.
func (a *Accumulator) StartTurn() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	a.turnBaseline = a.snapshotLocked() // No open turn yet → no clock read here.
	a.turnStart = a.clock()
}

// EndTurn closes the open turn's active-compute window, folding its duration
// into the cumulative active time. It is a no-op when no turn is open (nil
// receiver, never started, or already ended) and does not read the clock then.
func (a *Accumulator) EndTurn() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.turnStart.IsZero() {
		return
	}
	a.active += a.clock().Sub(a.turnStart)
	a.turnStart = time.Time{}
}

// usageTokens returns the token count to bill against the budget: the reported
// total, or prompt+completion when a provider leaves TotalTokens unset.
func usageTokens(u schema.Usage) int {
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}

	return u.PromptTokens + u.CompletionTokens
}

// AddUsage folds a model call's token counts into the cumulative usage (a session
// issues many model calls). It also adds the call's usageTokens to billedTokens,
// the budget's per-call token basis.
func (a *Accumulator) AddUsage(u schema.Usage) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	a.usage.PromptTokens += u.PromptTokens
	a.usage.CompletionTokens += u.CompletionTokens
	a.usage.TotalTokens += u.TotalTokens
	a.usage.CachedReadTokens += u.CachedReadTokens
	a.usage.CachedWriteTokens += u.CachedWriteTokens

	// Per-call token basis for the budget (TotalTokens, or prompt+completion).
	a.billedTokens += usageTokens(u)
}

// AddRoundTrip records one model.Generate call.
func (a *Accumulator) AddRoundTrip() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roundTrips++
}

// AddResponse records one model.Generate call that returned a usable message (not
// an error or cancellation). Unlike AddRoundTrip — which counts every attempt —
// this only increments when Generate actually produced a response.
func (a *Accumulator) AddResponse() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.responses++
}

// AddToolCall records one dispatched tool call.
func (a *Accumulator) AddToolCall() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.toolCalls++
}

// AddSubagent records one sub-agent spawn.
func (a *Accumulator) AddSubagent() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subagents++
}

// AddVerifier records one verification pass's model call. It is called once per
// pass (two per verification).
func (a *Accumulator) AddVerifier() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verifiers++
}

// Snapshot returns the session's cumulative stats. Elapsed is the sum of
// completed turns' active windows plus the open turn's elapsed (if a turn is in
// progress). On a nil receiver it returns the zero Stats. Before any StartTurn
// (no turn open, zero active) it reports zero Elapsed without reading the clock.
func (a *Accumulator) Snapshot() Stats {
	if a == nil {
		return Stats{} //nolint:exhaustruct // zero snapshot for a nil accumulator.
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.snapshotLocked()
}

// snapshotLocked builds the cumulative Stats. The caller must hold a.mu.
func (a *Accumulator) snapshotLocked() Stats {
	out := Stats{
		Elapsed:    a.active,
		RoundTrips: a.roundTrips,
		Responses:  a.responses,
		ToolCalls:  a.toolCalls,
		Subagents:  a.subagents,
		Verifiers:  a.verifiers,
		Usage:      a.usage,
		Provider:   a.provider,
		Model:      a.model,
	}
	if !a.turnStart.IsZero() { // Include the in-progress turn's elapsed.
		out.Elapsed += a.clock().Sub(a.turnStart)
	}

	return out
}

// TurnSnapshot returns the metrics for the current (or just-completed) turn: the
// cumulative snapshot minus the baseline captured at StartTurn. On a nil receiver
// it returns the zero Stats. Before any StartTurn the baseline is the zero Stats,
// so it equals Snapshot.
func (a *Accumulator) TurnSnapshot() Stats {
	if a == nil {
		return Stats{} //nolint:exhaustruct // zero snapshot for a nil accumulator.
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	return diffStats(a.snapshotLocked(), a.turnBaseline)
}

// diffStats returns cur − base field-by-field. Provider/Model are taken from cur
// (session constants, not deltas).
func diffStats(cur, base Stats) Stats {
	return Stats{
		Elapsed:    cur.Elapsed - base.Elapsed,
		RoundTrips: cur.RoundTrips - base.RoundTrips,
		Responses:  cur.Responses - base.Responses,
		ToolCalls:  cur.ToolCalls - base.ToolCalls,
		Subagents:  cur.Subagents - base.Subagents,
		Verifiers:  cur.Verifiers - base.Verifiers,
		Usage: schema.Usage{
			PromptTokens:      cur.Usage.PromptTokens - base.Usage.PromptTokens,
			CompletionTokens:  cur.Usage.CompletionTokens - base.Usage.CompletionTokens,
			TotalTokens:       cur.Usage.TotalTokens - base.Usage.TotalTokens,
			CachedReadTokens:  cur.Usage.CachedReadTokens - base.Usage.CachedReadTokens,
			CachedWriteTokens: cur.Usage.CachedWriteTokens - base.Usage.CachedWriteTokens,
		},
		Provider: cur.Provider,
		Model:    cur.Model,
	}
}

// BudgetExceeded reports whether cumulative session tokens have reached the
// configured budget. Nil receiver or unset budget → false (unbounded). Safe for
// hot-loop polling and under concurrent AddUsage from verifier workers.
func (a *Accumulator) BudgetExceeded() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.maxTokens > 0 && a.billedTokens >= a.maxTokens
}

// HasBudget reports whether a non-zero token ceiling is configured. Nil receiver
// or unset budget → false. Callers use it to tighten behavior only when a budget
// is actually in effect.
func (a *Accumulator) HasBudget() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.maxTokens > 0
}

// BudgetReason returns a one-line factual reason the budget is exhausted, or ""
// when within budget or on a nil receiver. The agent builds it once when it halts
// a turn.
func (a *Accumulator) BudgetReason() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.maxTokens > 0 && a.billedTokens >= a.maxTokens {
		return fmt.Sprintf("token budget reached: %d / %d tokens", a.billedTokens, a.maxTokens)
	}

	return ""
}
