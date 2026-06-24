// Package interrupt provides the mutex-guarded two-stage interrupt state machine
// shared by the signal handler (L1) and the cbreak terminal controller (L3).
package interrupt

import "sync"

// State is a mutex-guarded two-stage interrupt machine. A single mutex makes
// BeginTurn/EndTurn/Trip transitions indivisible, so a press between two stores
// can never observe a half-updated state. The zero value is ready to use.
type State struct {
	mu      sync.Mutex
	inTurn  bool
	tripped bool
}

// Interrupted reports whether a graceful stop was requested this turn.
func (s *State) Interrupted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tripped
}

// BeginTurn arms interrupt handling and clears any stale trip from a prior turn.
func (s *State) BeginTurn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tripped = false
	s.inTurn = true
}

// EndTurn disarms interrupt handling.
func (s *State) EndTurn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inTurn = false
}

// Trip records an interrupt press and reports whether the process should hard-kill:
// idle (not in a turn) → kill; first in-turn press → graceful (sets Interrupted);
// second in-turn press → kill.
func (s *State) Trip() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inTurn {
		return true
	}
	if s.tripped {
		return true
	}
	s.tripped = true

	return false
}
