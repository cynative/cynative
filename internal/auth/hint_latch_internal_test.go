package auth

import "testing"

func TestHintLatch_BeginFailLatches(t *testing.T) {
	t.Parallel()
	var l hintLatch
	e, failed := l.begin()
	if failed {
		t.Fatal("new latch is set")
	}
	l.fail(e)
	if _, failed = l.begin(); !failed {
		t.Error("fail with the current epoch must latch")
	}
}

func TestHintLatch_ResetClearsLatched(t *testing.T) {
	t.Parallel()
	var l hintLatch
	e, _ := l.begin()
	l.fail(e)
	l.reset()
	if _, failed := l.begin(); failed {
		t.Error("reset must clear the latch")
	}
}

func TestHintLatch_StaleEpochFailDoesNotLatch(t *testing.T) {
	t.Parallel()
	var l hintLatch
	stale, _ := l.begin()
	l.reset()
	l.fail(stale)
	if _, failed := l.begin(); failed {
		t.Error("a failure begun before a reset must not latch")
	}
}
