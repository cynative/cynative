//go:build linux

package ui

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cynative/cynative/internal/interrupt"
)

// openPTY opens a Linux pty pair and returns (master, slaveFd). The pair is closed
// via t.Cleanup. The test skips (not fails) if pty allocation is unavailable.
func openPTY(t *testing.T) (*os.File, int) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("cannot open /dev/ptmx: %v", err)
	}
	mfd := int(ptmx.Fd())
	if unlockErr := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); unlockErr != nil {
		t.Skipf("unlockpt: %v", unlockErr)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		t.Skipf("ptsname: %v", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open slave: %v", err)
	}
	t.Cleanup(func() { _ = pts.Close(); _ = ptmx.Close() })

	return ptmx, int(pts.Fd())
}

// newPTYController builds a TerminalController over a fresh pty slave and begins a
// turn (cbreak + watcher). EndTurn is registered via t.Cleanup. Skips if cbreak entry
// leaves no watcher (degraded), which would make the assertions vacuous.
func newPTYController(t *testing.T) (*os.File, *TerminalController) {
	t.Helper()
	master, slaveFd := openPTY(t)
	ctrl, err := NewTerminalController(slaveFd, &interrupt.State{}) //nolint:exhaustruct // zero start.
	if err != nil {
		t.Skipf("NewTerminalController on pty: %v", err)
	}
	ctrl.BeginTurn()
	if !ctrl.watching {
		t.Skip("cbreak entry produced no watcher on this pty; skipping")
	}
	t.Cleanup(ctrl.EndTurn)

	return master, ctrl
}

// TestTerminalController_NoTripOnOSCReply feeds the leading bytes of an OSC 11 reply
// (no ST, so a regression would produce exactly one graceful interrupt — never the
// second, [os.Exit]-causing one) and asserts the watcher does NOT trip. This is the
// #285 regression guard.
func TestTerminalController_NoTripOnOSCReply(t *testing.T) {
	t.Parallel()

	master, ctrl := newPTYController(t)

	if _, err := master.WriteString("\x1b]11;rgb:1c1c/1c1c"); err != nil {
		t.Fatalf("write OSC reply: %v", err)
	}

	// Give the watcher ample time to read and (correctly) ignore the reply. This is the
	// end-to-end smoke; the deterministic keyDecoder unit tests are the authoritative
	// guard. A positive feed-Esc synchronization is deliberately avoided: a second
	// in-turn interrupt would [os.Exit] the test process.
	time.Sleep(400 * time.Millisecond)

	if ctrl.Interrupted() {
		t.Fatalf("watcher tripped on a terminal OSC 11 reply (issue #285 regression)")
	}
}

// TestTerminalController_TripsOnRealEsc proves a genuine lone Esc still interrupts:
// one ESC byte then a VTIME timeout resolves to a single graceful interrupt (no
// [os.Exit], which only fires on a second in-turn interrupt).
func TestTerminalController_TripsOnRealEsc(t *testing.T) {
	t.Parallel()

	master, ctrl := newPTYController(t)

	if _, err := master.Write([]byte{0x1b}); err != nil {
		t.Fatalf("write esc: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !ctrl.Interrupted() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ctrl.Interrupted() {
		t.Fatalf("watcher did not trip on a real lone Esc")
	}
}
