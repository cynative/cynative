package ui

import (
	"os"

	"charm.land/glamour/v2"
	"charm.land/lipgloss/v2"
	"golang.org/x/term"
)

// defaultTermWidth returns the current terminal width, or 0 if not a TTY.
func defaultTermWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}

	return 0
}

// stdoutIsTTY reports whether stdout is an interactive terminal.
func stdoutIsTTY() bool {
	// Mirrors defaultTermWidth's cast rationale: Fd() returns a uintptr that is
	// always a valid small int on all supported platforms.
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// detectDarkBackground reports whether the terminal background is dark. It
// queries the terminal via lipgloss (OSC 11 + DA1) and returns true (dark) on
// any error, non-TTY, or no response — the safe default that matches the prior
// behavior. An [os.File] such as [os.Stdin] satisfies lipgloss's term.File parameter.
func detectDarkBackground() bool {
	return lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
}

// renderResolved renders markdown with the already-resolved style. The adaptive
// style is built from adaptiveStyleConfig(isDark); every other style is a
// glamour built-in path. Word wrap is applied to the terminal width.
func renderResolved(in, resolved string, isDark bool) (string, error) {
	opts := []glamour.TermRendererOption{glamour.WithWordWrap(defaultTermWidth())}
	if resolved == adaptiveStyle {
		opts = append(opts, glamour.WithStyles(adaptiveStyleConfig(isDark)))
	} else {
		opts = append(opts, glamour.WithStylePath(resolved))
	}

	r, err := glamour.NewTermRenderer(opts...)
	if err != nil {
		return "", err
	}

	return r.Render(in)
}

// renderAdaptive is the production render seam: it resolves the style, detects
// the background once via the u.detectDark seam (only when adaptive is actually
// in effect, so non-TTY / NO_COLOR runs never query the terminal), and renders.
func (u *UI) renderAdaptive(text, style string) (string, error) {
	resolved := resolveStyle(style, stdoutIsTTY(), os.Getenv("NO_COLOR"))
	if resolved == adaptiveStyle {
		u.detectOnce.Do(func() { u.isDark = u.detectDark() })
	}

	return renderResolved(text, resolved, u.isDark)
}

// PrimeBackground performs the one-time terminal background detection up front,
// before any keystroke watcher or raw-mode line editor reads the terminal, so the
// OSC 11/DA1 probe reply cannot be stolen by a concurrent reader and misread as Esc.
// It extends renderAdaptive's gate (adaptive style) with a
// controller-present check, so it is a no-op under notty/NO_COLOR or when there is
// no controller (no watcher to protect).
func (u *UI) PrimeBackground(style string) {
	u.primeIfAdaptive(resolveStyle(style, stdoutIsTTY(), os.Getenv("NO_COLOR")))
}

// New constructs a production UI wired to real terminal I/O.
// The glamour renderer, stdin scanner, and [os.Stderr] writer are
// integration-only and live here so the coverage gate excludes them.
func New(opts ...Option) *UI {
	base := &UI{ //nolint:exhaustruct // render/in set below; isDark/detectOnce zero-valued.
		in:         nil,
		promptW:    os.Stderr,
		errW:       os.Stderr,
		detectDark: detectDarkBackground,
	}
	base.render = base.renderAdaptive
	base.in = newScannerLineReader(base, os.Stdin)

	return assemble(base, opts...)
}
