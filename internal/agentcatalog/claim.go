package agentcatalog

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// ClaimsSource reports whether a directory entry with this mode claims an agents
// source.
//
// A symlink claims regardless of its target: whether it resolves or escapes the
// directory is decided later by the confined open, and treating an unresolvable
// one as "absent" would silently hand the name to a lower tier. Anything else
// that is not a directory is a stray file, not a claim.
func ClaimsSource(mode fs.FileMode) bool {
	return mode.IsDir() || mode&fs.ModeSymlink != 0
}

// ValidateHome rejects a home directory that is not usable as a source root.
//
// It must be absolute and already cleaned. A RELATIVE home is the dangerous
// case, not merely untidy: [os.UserHomeDir] returns $HOME verbatim, so `HOME=.`
// makes every lookup resolve against the working directory and a checkout's
// .cynative/agents becomes the user tier. That is exactly the
// working-directory-is-never-a-source invariant, defeated by an environment
// variable, so it is rejected rather than silently reinterpreted.
func ValidateHome(home string) error {
	if home == "" {
		return fmt.Errorf("%w: home directory is empty", ErrAgentInvalid)
	}
	if !filepath.IsAbs(home) {
		return fmt.Errorf("%w: home directory %q is not absolute", ErrAgentInvalid, home)
	}
	if filepath.Clean(home) != home {
		return fmt.Errorf("%w: home directory %q is not cleaned", ErrAgentInvalid, home)
	}

	return nil
}
