//go:build !unix

package ui

import "io"

// WithTerminalEditor on non-unix platforms has no raw-mode editor; it degrades to
// the cooked scanner over rw and pins the prompt writer to rw. It exists only so
// the symbol resolves for the untagged cli composition root; resolveInteraction
// returns no editor target off unix, so this is never invoked in practice.
func WithTerminalEditor(rw io.ReadWriter, _ int) Option {
	return func(u *UI) {
		u.in = newScannerLineReader(u, rw)
		u.promptW = rw
	}
}
