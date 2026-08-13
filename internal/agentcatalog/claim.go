package agentcatalog

import "io/fs"

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
