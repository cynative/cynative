//go:build unix && !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package ui

import "golang.org/x/term"

// makeRawKeepSignals falls back to full raw mode on Unix targets without the per-GOOS
// cbreak termios constants (e.g. solaris/illumos/aix). Idle Ctrl-C there still reports
// [io.EOF] (a silent exit 0) — out of reach without per-GOOS termios for these platforms.
func makeRawKeepSignals(fd int) (*term.State, error) {
	return term.MakeRaw(fd)
}
