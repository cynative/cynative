//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import "golang.org/x/sys/unix"

// cbreakGetReq/cbreakSetReq are the BSD/darwin termios ioctl requests. The Linux
// spellings (TCGETS/TCSETS) are undefined on these platforms, so the per-GOOS pair
// lives in separate build-tagged shell files.
const (
	cbreakGetReq = unix.TIOCGETA
	cbreakSetReq = unix.TIOCSETA
)

// posixVDisable is the Cc value that disables a control character on BSD/darwin
// (_POSIX_VDISABLE is 0xff there, unlike Linux's 0).
const posixVDisable = 0xff
