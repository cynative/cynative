package agent

// Interrupter lets the host request a graceful stop and brackets each turn.
// All three methods are called from Agent.Run; the concrete implementation is the
// cli's signal-backed handler (L1) or the cbreak terminal controller (L3). A nil
// Interrupter is a no-op (never interrupts), so an Agent built without one — e.g.
// in tests — is unaffected.
type Interrupter interface {
	// Interrupted reports whether a graceful stop was requested this turn.
	Interrupted() bool
	// BeginTurn arms interrupt handling for a turn (and, in L3, enters cbreak).
	BeginTurn()
	// EndTurn disarms it (and, in L3, restores the terminal).
	EndTurn()
}
