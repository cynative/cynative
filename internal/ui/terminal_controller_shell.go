//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/cynative/cynative/internal/interrupt"
	"github.com/cynative/cynative/internal/tools"
)

// interruptExitCode is the conventional exit code for a process killed by SIGINT
// (128+2). The ui cannot import internal/cli (cycle), so this duplicates cli's
// exitInterrupted by design — both are SIGINT's 130.
const interruptExitCode = 130

// readErrBackoff paces the watcher after a persistent tty read error (a revoked or
// disconnected terminal returns the error immediately) so it cannot spin and peg a CPU
// core until EndTurn; a transient EINTR is retried without backing off.
const readErrBackoff = 50 * time.Millisecond

// Compile-time check: *TerminalController satisfies the UI's approval Controller.
var _ Controller = (*TerminalController)(nil)

// TerminalController owns the interaction tty fd, the original cooked state, and
// (during a turn) cbreak mode plus the single keystroke-watcher goroutine. It is
// the agent's Interrupter (BeginTurn/EndTurn/Interrupted) and the UI's approval
// source (BeginApproval). The watcher is the sole reader of the fd while a turn is
// in flight; the cli restores cooked between turns so the line editor owns it.
type TerminalController struct {
	fd       int
	original *term.State      // cooked state captured at construction; restored on any exit path.
	state    *interrupt.State // shared two-stage interrupt machine (also driven by the signal handler).

	stop     atomic.Bool   // requests the watcher to exit; read with -race-safe loads.
	done     chan struct{} // closed when the watcher goroutine returns.
	watching bool          // a watcher is running this turn; touched only by the agent-loop goroutine.

	mu     sync.Mutex          // guards dec, decCh, intrCh (watcher + main goroutine both touch them).
	dec    keyDecoder          // pure byte->event state machine.
	decCh  chan tools.Decision // active approval's decision sink; nil when no approval is open.
	intrCh chan struct{}       // active approval's interrupt signal; nil when no approval is open.
}

// NewTerminalController captures fd's current (cooked) state and binds the shared
// interrupt state. fd must be an editor-capable tty (the caller guarantees this).
func NewTerminalController(fd int, state *interrupt.State) (*TerminalController, error) {
	original, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}

	return &TerminalController{ //nolint:exhaustruct // stop/done/mu/dec/chans start at their zero/per-turn state.
		fd:       fd,
		original: original,
		state:    state,
	}, nil
}

// Restore returns the terminal to its original cooked state. Safe from any current
// mode (raw or cbreak) and idempotent enough for a signal handler.
func (c *TerminalController) Restore() {
	if c == nil || c.original == nil {
		return
	}

	_ = term.Restore(c.fd, c.original)
}

// Interrupted reports whether a graceful stop was requested this turn.
func (c *TerminalController) Interrupted() bool { return c.state.Interrupted() }

// BeginTurn arms the interrupt machine, enters cbreak, and starts the watcher.
// If cbreak entry fails the fd stays canonical (a degraded turn with no watcher);
// SIGINT still works via the signal handler because cooked-mode ISIG is on.
func (c *TerminalController) BeginTurn() {
	c.state.BeginTurn()
	if err := c.enterCbreak(); err != nil {
		c.watching = false

		return
	}
	c.watching = true
	c.stop.Store(false)
	c.done = make(chan struct{})
	c.mu.Lock()
	c.dec = keyDecoder{} // clear any stale modeEsc/approvalActive carried from a prior turn before the watcher reads.
	c.mu.Unlock()
	go c.watch()
}

// EndTurn stops the watcher and JOINS it before restoring cooked, so the next
// line-editor read cannot race the watcher on the same fd, then disarms the machine.
// A degraded turn (cbreak entry failed, no watcher) skips the join.
func (c *TerminalController) EndTurn() {
	if c.watching {
		c.stop.Store(true)
		<-c.done
		c.Restore()
		c.watching = false
	}
	c.state.EndTurn()
}

// BeginApproval arms a single-key approval window and returns the channels the UI
// selects on plus an idempotent cleanup. The watcher delivers the decoded y/a/n
// decision on decCh and signals intrCh on an Esc/Ctrl-C during the window. On a
// degraded (cbreak-failed) turn there is no watcher to feed decisions, so it fails
// closed — a pre-closed interrupt channel makes the UI's select deny immediately,
// rather than block forever on a channel nothing will ever write. A rare fallback.
func (c *TerminalController) BeginApproval() (<-chan tools.Decision, <-chan struct{}, func()) {
	if !c.watching {
		return nil, closedChan(), func() {}
	}
	c.mu.Lock()
	if c.state.Interrupted() { // tripped between the caller's pre-check and here: deny now (intrCh was nil, so the trip closed nothing).
		c.mu.Unlock()

		return nil, closedChan(), func() {}
	}
	c.dec.approvalActive = true
	c.decCh = make(chan tools.Decision, 1)
	c.intrCh = make(chan struct{})
	dec, intr := c.decCh, c.intrCh
	c.mu.Unlock()

	var once sync.Once
	cleanup := func() { once.Do(c.disarmApproval) }

	return dec, intr, cleanup
}

// disarmApproval clears the active approval window under the lock.
func (c *TerminalController) disarmApproval() {
	c.mu.Lock()
	c.dec.approvalActive = false
	c.decCh = nil
	c.intrCh = nil
	c.mu.Unlock()
}

// watch is the single keystroke reader for the turn. It reads one byte at a time
// (cbreak's VMIN=0/VTIME=1 yields n==0 on a ~100ms timeout), decodes it, and acts
// on the event — all decode+handle work under the lock; the blocking read is not.
func (c *TerminalController) watch() {
	defer close(c.done)

	var buf [1]byte
	for {
		if c.stop.Load() {
			return
		}
		n, err := c.readKey(buf[:])
		c.step(n, err, buf[0])
		if err != nil {
			time.Sleep(readErrBackoff) // a persistent read error returns instantly; pace to avoid a spin.
		}
	}
}

// readKey reads one byte, transparently retrying a signal-interrupted (EINTR) read so a
// stray signal is not mistaken for a tty failure. Returns the VTIME timeout (n==0) or a
// real read error to the caller.
func (c *TerminalController) readKey(buf []byte) (int, error) {
	for {
		n, err := unix.Read(c.fd, buf)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}

// step decodes one read result and handles it under the lock. A read error or a
// zero-byte VTIME timeout both feed the decoder's timeout tick (never an approval
// decision), so a failed read cannot replay the stale buffer byte.
func (c *TerminalController) step(n int, err error, b byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.handleEvent(c.dec.decode(n, err, b))
	// Fail an open approval closed when either (a) a SIGINT was delivered out-of-band (the
	// os/signal handler — kill -INT or an IDE — not a typed key, which trips the shared
	// state without a keystroke), or (b) the tty read errored (revoked/disconnected
	// terminal): the watcher can no longer deliver a decision, so deny rather than let the
	// approval select block forever.
	if c.state.Interrupted() || err != nil {
		c.closeApprovalWindow()
	}
}

// closeApprovalWindow denies any active single-key approval by closing its interrupt
// channel and clearing the window. A no-op when no approval is open. Called with c.mu held.
func (c *TerminalController) closeApprovalWindow() {
	if c.intrCh != nil {
		close(c.intrCh)
		c.intrCh = nil
	}
}

// handleEvent dispatches a decoded event. It is called with c.mu held. An interrupt
// either hard-kills (Trip says kill) or gracefully signals a pending approval to
// deny; a decision is delivered non-blocking so an abandoned approval never hangs.
func (c *TerminalController) handleEvent(ev keyEvent) {
	switch ev.kind {
	case evInterrupt:
		c.handleInterrupt()
	case evDecision:
		if c.decCh != nil {
			select {
			case c.decCh <- ev.decision:
			default:
			}
		}
	case evIgnore:
	}
}

// handleInterrupt trips the two-stage machine: a kill decision restores the tty and
// exits; otherwise it signals any pending approval to deny (once). Called with c.mu held.
func (c *TerminalController) handleInterrupt() {
	if c.state.Trip() {
		c.Restore()
		os.Exit(interruptExitCode)
	}
	c.closeApprovalWindow()
}

// enterCbreak puts the fd into cbreak: no canonical/echo/signal/extended-input
// processing, no flow control, and a VMIN=0/VTIME=1 polling read. Output processing
// (OPOST/ONLCR) is left untouched so rendered text still wraps newlines correctly.
func (c *TerminalController) enterCbreak() error {
	t, err := unix.IoctlGetTermios(c.fd, cbreakGetReq)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ICANON | unix.ECHO | unix.ISIG | unix.IEXTEN
	t.Iflag &^= unix.IXON
	t.Cc[unix.VMIN] = 0
	t.Cc[unix.VTIME] = 1

	return unix.IoctlSetTermios(c.fd, cbreakSetReq, t)
}
