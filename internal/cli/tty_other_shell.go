//go:build !unix

package cli

import (
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// resolveInteraction has no /dev/tty on non-unix platforms and no raw-mode editor
// (editor is always nil). It uses stdio when stdin is a real terminal (approvals
// read from stdin, prompts go to stderr) and otherwise reports no usable terminal.
func resolveInteraction() (io.Reader, io.Writer, bool, *editorTarget) {
	//nolint:gosec // Fd() returns a uintptr that is always a valid small int.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, os.Stderr, true, nil
	}

	return strings.NewReader(""), os.Stderr, false, nil
}
