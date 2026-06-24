package interrupt

import "testing"

func TestState_Trip(t *testing.T) {
	t.Parallel()

	t.Run("idle press hard-kills", func(t *testing.T) {
		t.Parallel()
		s := &State{}
		if !s.Trip() {
			t.Errorf("press while not in a turn must request kill")
		}
	})

	t.Run("first in-turn press is graceful", func(t *testing.T) {
		t.Parallel()
		s := &State{}
		s.BeginTurn()
		if s.Trip() {
			t.Errorf("first in-turn press must be graceful (no kill)")
		}
		if !s.Interrupted() {
			t.Errorf("first in-turn press must set Interrupted")
		}
	})

	t.Run("second in-turn press hard-kills", func(t *testing.T) {
		t.Parallel()
		s := &State{}
		s.BeginTurn()
		_ = s.Trip()
		if !s.Trip() {
			t.Errorf("second in-turn press must request kill")
		}
	})

	t.Run("BeginTurn clears a stale trip", func(t *testing.T) {
		t.Parallel()
		s := &State{}
		s.BeginTurn()
		_ = s.Trip()
		s.EndTurn()
		s.BeginTurn()
		if s.Interrupted() {
			t.Errorf("BeginTurn must reset the tripped flag")
		}
	})
}
