package metrics_test

import (
	"testing"
	"time"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// fixedClock returns a clock that advances by step on each call, starting at base.
func fixedClock(base time.Time, step time.Duration) metrics.Clock {
	cur := base
	return func() time.Time {
		t := cur
		cur = cur.Add(step)
		return t
	}
}

// scriptedClock returns the given times in order and PANICS on any read past the
// last one. The panic makes each test's exact clock-read count load-bearing: an
// unexpected extra read (e.g. a future change that reads the clock in a
// closed-turn Snapshot) fails the test instead of silently reusing a value.
func scriptedClock(times ...time.Time) metrics.Clock {
	i := 0
	return func() time.Time {
		if i >= len(times) {
			panic("scriptedClock: unexpected clock read beyond the scripted times")
		}
		t := times[i]
		i++
		return t
	}
}

func TestAccumulator_CountersAndElapsed(t *testing.T) {
	t.Parallel()

	base := time.Unix(1000, 0)
	// StartTurn reads the clock once (t=base); Snapshot reads it once (t=base+1s).
	acc := metrics.NewAccumulator("openai", "gpt-4o", metrics.WithClock(fixedClock(base, time.Second)))

	acc.StartTurn()
	acc.AddRoundTrip()
	acc.AddRoundTrip()
	acc.AddToolCall()
	acc.AddSubagent()
	acc.AddUsage(schema.Usage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12})
	acc.AddUsage(schema.Usage{PromptTokens: 5, CompletionTokens: 1, TotalTokens: 6})

	s := acc.Snapshot()
	if s.RoundTrips != 2 || s.ToolCalls != 1 || s.Subagents != 1 {
		t.Errorf("counters = %+v, want rt=2 tc=1 sub=1", s)
	}
	if s.Usage.PromptTokens != 15 || s.Usage.CompletionTokens != 3 || s.Usage.TotalTokens != 18 {
		t.Errorf("usage = %+v, want summed 15/3/18", s.Usage)
	}
	if s.Provider != "openai" || s.Model != "gpt-4o" {
		t.Errorf("provider/model = %q/%q", s.Provider, s.Model)
	}
	if s.Elapsed != time.Second {
		t.Errorf("elapsed = %v, want 1s", s.Elapsed)
	}
}

func TestAddVerifier(t *testing.T) {
	t.Parallel()

	a := metrics.NewAccumulator("p", "m")
	a.StartTurn()
	a.AddVerifier()
	a.AddVerifier()

	if got := a.Snapshot().Verifiers; got != 2 {
		t.Errorf("Verifiers = %d, want 2", got)
	}
}

func TestAddVerifier_NilReceiver(t *testing.T) {
	t.Parallel()

	var a *metrics.Accumulator
	a.AddVerifier() // Must not panic.
}

func TestAddResponse(t *testing.T) {
	t.Parallel()

	a := metrics.NewAccumulator("p", "m")
	a.StartTurn()
	a.AddResponse()
	a.AddResponse()

	if got := a.Snapshot().Responses; got != 2 {
		t.Errorf("Responses = %d, want 2", got)
	}
}

func TestAddResponse_NilReceiver(t *testing.T) {
	t.Parallel()

	var a *metrics.Accumulator
	a.AddResponse() // Must not panic.
}

func TestAccumulator_NilReceiverSafe(t *testing.T) {
	t.Parallel()

	var acc *metrics.Accumulator // nil — mirrors an Agent built without Metrics.

	// None of these must panic.
	acc.StartTurn()
	acc.EndTurn()
	acc.AddRoundTrip()
	acc.AddResponse()
	acc.AddToolCall()
	acc.AddSubagent()
	acc.AddUsage(schema.Usage{TotalTokens: 1})

	if s := acc.Snapshot(); s != (metrics.Stats{}) {
		t.Errorf("nil Snapshot = %+v, want zero Stats", s)
	}
}

func TestNewAccumulator_DefaultClock(t *testing.T) {
	t.Parallel()

	// No WithClock: the default time.Now is used. StartTurn then Snapshot must
	// yield a non-negative elapsed without panicking.
	acc := metrics.NewAccumulator("p", "m")
	acc.StartTurn()
	if s := acc.Snapshot(); s.Elapsed < 0 {
		t.Errorf("elapsed = %v, want >= 0", s.Elapsed)
	}
}

func TestWithClock_NilIgnored(t *testing.T) {
	t.Parallel()

	// A nil clock must be ignored (default time.Now preserved), not stored — so
	// StartTurn/Snapshot do not panic on a nil function call.
	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(nil))
	acc.StartTurn()
	if s := acc.Snapshot(); s.Elapsed < 0 {
		t.Errorf("elapsed = %v, want >= 0", s.Elapsed)
	}
}

func TestAccumulator_SnapshotBeforeStartTurn(t *testing.T) {
	t.Parallel()

	// Snapshot without a prior StartTurn must report zero Elapsed (not a duration
	// measured from the zero time), and must not call the clock.
	clockCalls := 0
	clock := func() time.Time { clockCalls++; return time.Unix(0, 0) }

	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(clock))
	s := acc.Snapshot()
	if s.Elapsed != 0 {
		t.Errorf("elapsed = %v, want 0 before StartTurn", s.Elapsed)
	}
	if clockCalls != 0 {
		t.Errorf("clock called %d times, want 0 before StartTurn", clockCalls)
	}
}

func TestAccumulator_BudgetUnsetIsUnbounded(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m") // no WithBudget.
	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 1_000_000})

	if acc.BudgetExceeded() {
		t.Error("unset budget must never be exceeded")
	}
	if r := acc.BudgetReason(); r != "" {
		t.Errorf("reason = %q, want empty when within budget", r)
	}
}

func TestAccumulator_TokenBudgetExceeded(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 6})
	if acc.BudgetExceeded() {
		t.Error("6/10 must be within budget")
	}
	acc.AddUsage(schema.Usage{TotalTokens: 4}) // now 10 → reached (>=).
	if !acc.BudgetExceeded() {
		t.Error("10/10 must be exceeded")
	}
	if got, want := acc.BudgetReason(), "token budget reached: 10 / 10 tokens"; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
}

func TestAccumulator_TokenBudgetUsesPromptPlusCompletionFallback(t *testing.T) {
	t.Parallel()

	// A provider that reports components but leaves TotalTokens at 0 must still bill.
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10))
	acc.StartTurn()
	acc.AddUsage(schema.Usage{PromptTokens: 7, CompletionTokens: 5}) // 12, TotalTokens=0.
	if !acc.BudgetExceeded() {
		t.Error("prompt+completion (12) must trip a 10-token budget when TotalTokens is 0")
	}
}

func TestAccumulator_BudgetAccumulatesAcrossTurns(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10),
		metrics.WithClock(fixedClock(time.Unix(0, 0), time.Second)))

	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 8})
	acc.EndTurn()

	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 3}) // session 8+3 = 11 ≥ 10.
	acc.EndTurn()

	if !acc.BudgetExceeded() {
		t.Error("budget must accumulate across turns (8+3 ≥ 10)")
	}
	if s := acc.Snapshot(); s.Usage.TotalTokens != 11 {
		t.Errorf("cumulative usage = %d, want 11 (survives across turns)", s.Usage.TotalTokens)
	}
}

func TestAccumulator_BudgetNilReceiverSafe(t *testing.T) {
	t.Parallel()

	var acc *metrics.Accumulator
	if acc.BudgetExceeded() {
		t.Error("nil accumulator must be unbounded")
	}
	if acc.BudgetReason() != "" {
		t.Error("nil accumulator reason must be empty")
	}
	if acc.HasBudget() {
		t.Error("nil accumulator must report no budget")
	}
}

func TestAccumulator_HasBudget(t *testing.T) {
	t.Parallel()

	if metrics.NewAccumulator("p", "m").HasBudget() {
		t.Error("unset budget must report HasBudget=false")
	}
	if !metrics.NewAccumulator("p", "m", metrics.WithBudget(100)).HasBudget() {
		t.Error("token budget must report HasBudget=true")
	}
}

func TestAccumulator_CountersAreCumulative(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(fixedClock(time.Unix(0, 0), time.Second)))

	acc.StartTurn()
	acc.AddRoundTrip()
	acc.AddToolCall()
	acc.AddSubagent()
	acc.AddVerifier()
	acc.AddUsage(schema.Usage{TotalTokens: 5})
	acc.EndTurn()

	acc.StartTurn()
	acc.AddRoundTrip()
	acc.AddUsage(schema.Usage{TotalTokens: 7})
	acc.EndTurn()

	s := acc.Snapshot()
	if s.RoundTrips != 2 || s.ToolCalls != 1 || s.Subagents != 1 || s.Verifiers != 1 {
		t.Errorf("counters = %+v, want rt2 tc1 sub1 ver1 (cumulative across turns)", s)
	}
	if s.Usage.TotalTokens != 12 {
		t.Errorf("usage = %d, want 12 (cumulative)", s.Usage.TotalTokens)
	}
}

func TestAccumulator_ActiveTimeExcludesIdle(t *testing.T) {
	t.Parallel()

	base := time.Unix(0, 0)
	// Clock reads, in order: StartTurn(t0), EndTurn(t1), StartTurn(t2), EndTurn(t3).
	// Snapshot does not read the clock because the turn is closed.
	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(scriptedClock(
		base,                      // turn 1 start
		base.Add(5*time.Second),   // turn 1 end  → window 5s
		base.Add(100*time.Second), // turn 2 start (95s idle, excluded)
		base.Add(108*time.Second), // turn 2 end  → window 8s
	)))

	acc.StartTurn()
	acc.EndTurn()
	acc.StartTurn()
	acc.EndTurn()

	if got := acc.Snapshot().Elapsed; got != 13*time.Second {
		t.Errorf("active elapsed = %v, want 13s (idle between turns excluded)", got)
	}
}

func TestAccumulator_SnapshotIncludesOpenTurn(t *testing.T) {
	t.Parallel()

	base := time.Unix(0, 0)
	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(scriptedClock(
		base,                    // StartTurn
		base.Add(3*time.Second), // Snapshot reads the clock for the still-open window
	)))

	acc.StartTurn()
	if got := acc.Snapshot().Elapsed; got != 3*time.Second {
		t.Errorf("mid-turn elapsed = %v, want 3s (open window included)", got)
	}
}

func TestAccumulator_EndTurnNilReceiver(t *testing.T) {
	t.Parallel()

	var a *metrics.Accumulator
	a.EndTurn() // must not panic.
}

func TestAccumulator_EndTurnWithoutStartIsNoOp(t *testing.T) {
	t.Parallel()

	clockCalls := 0
	clock := func() time.Time { clockCalls++; return time.Unix(0, 0) }

	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(clock))
	acc.EndTurn() // no open turn → no-op, must not read the clock.

	if clockCalls != 0 {
		t.Errorf("EndTurn without StartTurn read the clock %d times, want 0", clockCalls)
	}
	if got := acc.Snapshot().Elapsed; got != 0 {
		t.Errorf("elapsed = %v, want 0", got)
	}
}

func TestAccumulator_DoubleEndTurnIsNoOp(t *testing.T) {
	t.Parallel()

	base := time.Unix(0, 0)
	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(scriptedClock(
		base, base.Add(2*time.Second), // StartTurn, EndTurn → 2s
	)))

	acc.StartTurn()
	acc.EndTurn()
	acc.EndTurn() // turn already closed → no-op, does not read the clock again.

	if got := acc.Snapshot().Elapsed; got != 2*time.Second {
		t.Errorf("elapsed = %v, want 2s (second EndTurn ignored)", got)
	}
}

func TestAccumulator_TokenBudgetReadsCumulativeUsage(t *testing.T) {
	t.Parallel()

	// The token budget reads the cumulative billed-token sum across turns.
	acc := metrics.NewAccumulator("p", "m", metrics.WithBudget(10),
		metrics.WithClock(fixedClock(time.Unix(0, 0), 0)))

	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 6})
	acc.EndTurn()
	acc.StartTurn()
	acc.AddUsage(schema.Usage{TotalTokens: 5}) // 6 + 5 = 11 ≥ 10.
	acc.EndTurn()

	if !acc.BudgetExceeded() {
		t.Error("token budget must read cumulative billed tokens (6+5 ≥ 10)")
	}
}

func TestTurnSnapshot_FirstTurnEqualsSession(t *testing.T) {
	t.Parallel()

	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(fixedClock(time.Unix(0, 0), time.Second)))
	acc.StartTurn()
	acc.AddRoundTrip()
	acc.AddUsage(schema.Usage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12, CachedReadTokens: 4})
	acc.EndTurn()

	turn, sess := acc.TurnSnapshot(), acc.Snapshot()
	if turn.RoundTrips != sess.RoundTrips || turn.Elapsed != sess.Elapsed {
		t.Errorf("turn rt/el = %d/%v, session = %d/%v",
			turn.RoundTrips, turn.Elapsed, sess.RoundTrips, sess.Elapsed)
	}
	if turn.Usage.PromptTokens != 10 || turn.Usage.CachedReadTokens != 4 || sess.Usage.PromptTokens != 10 {
		t.Errorf("turn/session usage mismatch: %+v / %+v", turn.Usage, sess.Usage)
	}
	if turn.Provider != "p" || turn.Model != "m" {
		t.Errorf("turn provider/model = %q/%q, want p/m", turn.Provider, turn.Model)
	}
}

func TestTurnSnapshot_DeltaAcrossTurns(t *testing.T) {
	t.Parallel()

	base := time.Unix(2000, 0)
	// Reads: StartTurn1=base, EndTurn1=base+1s, StartTurn2=base+2s, EndTurn2=base+3s.
	// Snapshot/TurnSnapshot after EndTurn must NOT read the clock (scriptedClock panics if they do).
	acc := metrics.NewAccumulator("p", "m", metrics.WithClock(scriptedClock(
		base, base.Add(time.Second), base.Add(2*time.Second), base.Add(3*time.Second))))

	acc.StartTurn() // turn 1.
	acc.AddRoundTrip()
	acc.AddToolCall()
	acc.AddSubagent()
	acc.AddVerifier()
	acc.AddUsage(schema.Usage{ //nolint:exhaustruct // cache write omitted.
		PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12, CachedReadTokens: 4,
	})
	acc.EndTurn()

	acc.StartTurn() // turn 2; baseline captured here.
	acc.AddRoundTrip()
	acc.AddRoundTrip()
	acc.AddToolCall()
	acc.AddToolCall()
	acc.AddToolCall()
	acc.AddSubagent()
	acc.AddVerifier()
	acc.AddVerifier()
	acc.AddVerifier()
	acc.AddVerifier()
	acc.AddUsage(schema.Usage{
		PromptTokens: 30, CompletionTokens: 5, TotalTokens: 35, CachedReadTokens: 20, CachedWriteTokens: 7,
	})
	acc.EndTurn()

	turn, sess := acc.TurnSnapshot(), acc.Snapshot()
	// Turn 2 deltas only (each counter field distinct to pin the diffStats mapping).
	if turn.RoundTrips != 2 || turn.ToolCalls != 3 || turn.Subagents != 1 || turn.Verifiers != 4 {
		t.Errorf("turn counters = %+v, want rt2/tc3/sub1/ver4", turn)
	}
	if turn.Elapsed != time.Second {
		t.Errorf("turn elapsed = %v, want 1s", turn.Elapsed)
	}
	if turn.Usage.PromptTokens != 30 || turn.Usage.CompletionTokens != 5 ||
		turn.Usage.TotalTokens != 35 || turn.Usage.CachedReadTokens != 20 || turn.Usage.CachedWriteTokens != 7 {
		t.Errorf("turn usage = %+v, want delta 30/5/35/20/7", turn.Usage)
	}
	// Session cumulative.
	if sess.RoundTrips != 3 || sess.ToolCalls != 4 || sess.Subagents != 2 || sess.Verifiers != 5 {
		t.Errorf("session counters = %+v, want rt3/tc4/sub2/ver5", sess)
	}
	if sess.Elapsed != 2*time.Second {
		t.Errorf("session elapsed = %v, want 2s", sess.Elapsed)
	}
	if sess.Usage.PromptTokens != 40 || sess.Usage.TotalTokens != 47 || sess.Usage.CachedReadTokens != 24 {
		t.Errorf("session usage = %+v, want cumulative 40/.../47/24", sess.Usage)
	}
}

func TestTurnSnapshot_NilReceiver(t *testing.T) {
	t.Parallel()

	var acc *metrics.Accumulator
	if s := acc.TurnSnapshot(); s != (metrics.Stats{}) {
		t.Errorf("nil TurnSnapshot = %+v, want zero Stats", s)
	}
}
