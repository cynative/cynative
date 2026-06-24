package schema

import "testing"

// Test that directly calls the isBlock methods to satisfy coverage.
func TestIsBlockMethods(t *testing.T) {
	t.Parallel()

	// Call the methods directly since they're unexported and have empty bodies.
	TextBlock{}.isBlock()
	ToolCallBlock{}.isBlock()
	ToolResultBlock{}.isBlock()
}
