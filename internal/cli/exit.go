package cli

import (
	"errors"

	"github.com/cynative/cynative/internal/agent"
)

// ExitCodeFor maps a top-level command error to a process exit code: a graceful
// operator interrupt maps to the conventional 130 (128+SIGINT), any other error
// maps to 1, and nil maps to 0.
func ExitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, agent.ErrInterrupted):
		return exitInterrupted
	default:
		return 1
	}
}
