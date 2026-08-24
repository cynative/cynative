package cli

import (
	"errors"

	"github.com/cynative/cynative/internal/agent"
)

// exitNoAnswer is the exit code for a run that completed without producing an
// answer (agent.ErrNoAnswer). It is distinct from the generic 1 so a scripted
// `cynative -p` caller can tell "the model gave up" from an execution failure
// without parsing stdout; the rendered notice names the specific reason.
const exitNoAnswer = 2

// ExitCodeFor maps a top-level command error to a process exit code: a graceful
// operator interrupt maps to the conventional 130 (128+SIGINT), a run that
// produced no answer maps to 2, any other error maps to 1, and nil maps to 0.
func ExitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, agent.ErrInterrupted):
		return exitInterrupted
	case errors.Is(err, agent.ErrNoAnswer):
		return exitNoAnswer
	default:
		return 1
	}
}
