package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cynative/cynative/internal/interrupt"
)

// handleSig dispatches one received signal: restores the terminal when required and
// exits with the appropriate code. Shell: [os.Exit] is untestable I/O.
func handleSig(sig os.Signal, s *interrupt.State, restore func()) {
	doRestore, exit, code := signalAction(sig == syscall.SIGTERM, s.Trip())
	if doRestore && restore != nil {
		restore()
	}

	if exit {
		os.Exit(code)
	}
}

// installSignalHandler delivers SIGINT (two-stage) and SIGTERM to s, restoring the
// terminal (restore, nil on non-editor runs) before any hard exit so a kill during a
// raw/cbreak window never leaves the tty broken. Shell: os/signal and [os.Exit] are I/O.
func installSignalHandler(s *interrupt.State, restore func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		for sig := range ch {
			handleSig(sig, s, restore)
		}
	}()
}
