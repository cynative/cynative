//go:build unix

package ui

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"golang.org/x/term"
)

// termLineReader is the raw-mode line editor backing the interactive prompt on
// unix. It builds a fresh term.Terminal per read (pristine line/cursor state, so
// a prior Ctrl-C leaves no stale buffer) and shares one history across reads. It
// lives in the shell because it drives real terminal I/O.
type termLineReader struct {
	rw      io.ReadWriter
	fd      int
	history history
	cooked  *bufio.Reader
}

func (r *termLineReader) ReadLine(prompt string, withHistory bool) (string, bool) {
	t := term.NewTerminal(r.rw, prompt)
	t.History = historyFor(withHistory, r.history)
	applySize(t, r.fd)

	state, err := makeRawKeepSignals(r.fd)
	if err != nil {
		return r.cookedRead(prompt)
	}
	defer func() { _ = term.Restore(r.fd, state) }()

	line, rerr := t.ReadLine()
	if errors.Is(rerr, term.ErrPasteIndicator) {
		rerr = errPaste
	}

	return mapReadResult(line, rerr)
}

// applySize syncs the terminal's width from the raw fd; a query error or a zero
// width skips the update (term.SetSize would clamp 0→1 and corrupt wrapping).
func applySize(t *term.Terminal, fd int) {
	if w, h, err := term.GetSize(fd); err == nil && w > 0 {
		_ = t.SetSize(w, h)
	}
}

// cookedRead is the degraded fallback when MakeRaw fails: it prints the inline
// prompt and reads one cooked line (no editing), mirroring mapReadResult's EOF
// behavior. The fallback reader persists so buffered bytes are not dropped.
func (r *termLineReader) cookedRead(prompt string) (string, bool) {
	if r.cooked == nil {
		r.cooked = bufio.NewReader(r.rw)
	}
	_, _ = io.WriteString(r.rw, prompt)
	line, err := r.cooked.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}

	return strings.TrimRight(line, "\r\n"), true
}

// WithTerminalEditor installs the raw-mode editor over the controlling terminal
// rw (fd is the descriptor to raw) and routes the prompt writer to rw so
// tool-call previews and prompt spacing reach the terminal.
func WithTerminalEditor(rw io.ReadWriter, fd int) Option {
	return func(u *UI) {
		u.in = &termLineReader{rw: rw, fd: fd, history: newBoundedHistory(), cooked: nil}
		u.promptW = rw
	}
}
