//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package ui

import (
	"github.com/cynative/cynative/internal/interrupt"
	"github.com/cynative/cynative/internal/tools"
)

// TerminalController is the non-unix stub. The cli only constructs one when an
// editor-capable TTY exists, which is unix-only, so these methods are never reached
// in practice; they exist so *TerminalController satisfies agent.Interrupter and
// ui.Controller on every GOOS.
type TerminalController struct{}

// NewTerminalController returns nil on non-unix platforms. The cli caller guards
// construction behind editor != nil, which can only be true on unix.
func NewTerminalController(int, *interrupt.State) (*TerminalController, error) {
	return nil, nil
}

// Restore is a no-op on non-unix platforms.
func (c *TerminalController) Restore() {}

// Interrupted always reports false on non-unix platforms.
func (c *TerminalController) Interrupted() bool { return false }

// BeginTurn is a no-op on non-unix platforms.
func (c *TerminalController) BeginTurn() {}

// EndTurn is a no-op on non-unix platforms.
func (c *TerminalController) EndTurn() {}

// BeginApproval returns nil channels and a no-op cleanup on non-unix platforms.
func (c *TerminalController) BeginApproval() (<-chan tools.Decision, <-chan struct{}, func()) {
	return nil, nil, func() {}
}
