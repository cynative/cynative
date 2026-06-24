package ui

import "testing"

// TestTerminalController_RestoreNilSafe verifies that calling Restore on a nil
// *TerminalController does not panic. The method is in a coverage-exempt shell
// file, but the nil-safety contract is load-bearing so we pin it here.
func TestTerminalController_RestoreNilSafe(t *testing.T) {
	t.Parallel()

	var c *TerminalController
	c.Restore() // must not panic.
}
