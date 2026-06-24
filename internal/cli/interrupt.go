package cli

// exitInterrupted is the conventional exit code for a process killed by SIGINT (128+2).
const exitInterrupted = 130

// exitTerminated is the conventional exit code for a process killed by SIGTERM (128+15).
const exitTerminated = 143

// signalAction decides what a received signal does, given whether it is SIGTERM and
// whether the two-stage machine asked to kill: SIGTERM always restores the terminal
// and exits; a SIGINT restores+exits only on a kill decision; a graceful SIGINT does
// neither (the loop handles the flag). Pure so the handler's branches are covered.
func signalAction(isTerm, kill bool) (bool, bool, int) {
	if isTerm {
		return true, true, exitTerminated
	}

	if kill {
		return true, true, exitInterrupted
	}

	return false, false, 0
}
