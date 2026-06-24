//go:build linux

package ui

import "golang.org/x/sys/unix"

// cbreakGetReq/cbreakSetReq are the Linux termios ioctl requests. They differ per
// GOOS (TCGETS/TCSETS on Linux, TIOCGETA/TIOCSETA on the BSDs/darwin), so they live
// in per-GOOS shell files; unix.TCGETS is undefined on darwin.
const (
	cbreakGetReq = unix.TCGETS
	cbreakSetReq = unix.TCSETS
)

// posixVDisable is the Cc value that disables a control character on Linux.
const posixVDisable = 0
