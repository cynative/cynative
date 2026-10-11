package audit

import (
	"testing"
	"time"
)

// TestPendingAfter_FollowsAHoldTakenAfterTheCountReachedZero pins that the wait reads the holds open now, not the
// channel it saw first: when the count reaches zero and a new hold is taken before the waiter wakes, the waiter
// keeps waiting for the new one. The state change is made under the lock, so the order is fixed.
func TestPendingAfter_FollowsAHoldTakenAfterTheCountReachedZero(t *testing.T) {
	t.Parallel()

	waiting := make(chan struct{})
	l := New(nil, WithDrain(time.Minute), WithDrainNotice(func(time.Duration) { close(waiting) }))
	l.Hold()
	got := make(chan int, 1)
	go func() { got <- l.pendingAfter() }()
	// The notice comes after the waiter read the first channel and before it waits on it.
	<-waiting
	l.holdMu.Lock()
	close(l.drained)
	l.drained = make(chan struct{})
	l.holdMu.Unlock()
	select {
	case n := <-got:
		t.Fatalf("pendingAfter returned %d while a hold taken after the count reached zero was open", n)
	case <-time.After(100 * time.Millisecond):
	}
	l.holdMu.Lock()
	l.holds = 0
	close(l.drained)
	l.holdMu.Unlock()
	select {
	case n := <-got:
		if n != 0 {
			t.Errorf("pendingAfter = %d after every hold was released, want 0", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pendingAfter never returned")
	}
}
