//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import (
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// makeRawKeepSignals puts fd into raw mode but leaves ISIG enabled, so a typed Ctrl-C
// at the idle prompt generates SIGINT (handled by the process signal handler → exit
// 130) instead of being delivered to x/term as a byte it reports as [io.EOF] — which is
// indistinguishable from Ctrl-D and exits 0 silently. It returns the pre-raw state for
// restoration, exactly like term.MakeRaw. Shell: termios ioctls are untestable I/O.
func makeRawKeepSignals(fd int) (*term.State, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}

	t, err := unix.IoctlGetTermios(fd, cbreakGetReq)
	if err != nil {
		_ = term.Restore(fd, state)

		return nil, err
	}
	t.Lflag |= unix.ISIG
	// Keep ONLY Ctrl-C (VINTR) signalling; disable Ctrl-\ (VQUIT) and Ctrl-Z (VSUSP) so
	// SIGQUIT/SIGTSTP cannot fire from the idle prompt and leave the tty raw — the signal
	// handler restores only on SIGINT/SIGTERM. Those keys become inert (x/term ignores them).
	t.Cc[unix.VQUIT] = posixVDisable
	t.Cc[unix.VSUSP] = posixVDisable
	if err = unix.IoctlSetTermios(fd, cbreakSetReq, t); err != nil {
		_ = term.Restore(fd, state)

		return nil, err
	}

	return state, nil
}
