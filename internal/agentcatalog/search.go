package agentcatalog

import (
	"fmt"
	"path/filepath"
)

// ProjectSearchPath returns the ordered directories to look for a
// .cynative/agents in: cwd, then each parent, stopping at and including the
// nearest one holding a .git marker.
//
// The walk stops before home and never returns it, so a dotfiles repository
// with .git in $HOME cannot make ~/.cynative the project tier and collapse the
// user tier into it. When cwd is home there are no project candidates at all,
// and when no marker is found within the boundary the result is cwd alone.
//
// Both inputs must already be cleaned, absolute, and canonicalized the same
// way by the caller. Cleaned-and-absolute alone is not enough: [os.Getwd] and
// [os.UserHomeDir] can spell the same physical directory differently through
// symlinks, which would reopen exactly the boundary hole above. The shell
// resolves both through [filepath.EvalSymlinks] before calling in.
//
// hasGit returns (bool, error) rather than a bare bool so a permission or I/O
// failure is not silently indistinguishable from "no marker here".
func ProjectSearchPath(cwd, home string, hasGit func(dir string) (bool, error)) ([]string, error) {
	if err := checkCanonical("cwd", cwd); err != nil {
		return nil, err
	}
	if err := checkCanonical("home", home); err != nil {
		return nil, err
	}

	if cwd == home {
		return nil, nil
	}

	var out []string

	for dir := cwd; dir != home; {
		out = append(out, dir)

		found, err := hasGit(dir)
		if err != nil {
			return nil, fmt.Errorf("probe for .git in %s: %w", dir, err)
		}
		if found {
			return out, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
	}

	// No marker inside the boundary: only cwd itself is a project candidate.
	return out[:1], nil
}

// checkCanonical rejects a path that is not absolute and already cleaned.
func checkCanonical(label, path string) error {
	if path == "" {
		return fmt.Errorf("%s is empty", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s %q is not absolute", label, path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s %q is not cleaned", label, path)
	}

	return nil
}
