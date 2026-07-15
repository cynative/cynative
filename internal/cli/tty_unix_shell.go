//go:build unix

package cli

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// resolveInteraction returns the scanner-path reader/writer, whether a usable
// controlling terminal exists, and an editor target when that terminal supports
// raw-mode line editing. It opens /dev/tty O_RDWR and accepts it only when it is
// a terminal in this process's foreground group, so a backgrounded run fails
// closed (--auto-approve required). With no usable terminal, prompts fall back to
// stderr (reached only under --auto-approve, where no input is read).
func resolveInteraction() (io.Reader, io.Writer, bool, *editorTarget) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return strings.NewReader(""), os.Stderr, false, nil
	}

	fd := int(tty.Fd())
	if !term.IsTerminal(fd) || !foreground(fd) {
		_ = tty.Close()

		return strings.NewReader(""), os.Stderr, false, nil
	}

	return tty, tty, true, &editorTarget{rw: tty, fd: fd}
}

// foreground reports whether this process is in fd's foreground process group.
func foreground(fd int) bool {
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return false
	}

	return pgrp == unix.Getpgrp()
}
