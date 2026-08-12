// Package agentcatalog resolves named markdown agent files from an ordered set
// of sources and composes them into the prompt for a run. The core takes
// [io/fs.FS] values and never touches the operating system; sources_shell.go
// opens the real directories.
package agentcatalog

import "errors"

var (
	// ErrAgentName reports an agent name that is not a valid name at all, so no
	// source is consulted. Returned before any filesystem access.
	ErrAgentName = errors.New("invalid agent name")
	// ErrAgentNotFound reports that no source holds an agent with that name.
	ErrAgentNotFound = errors.New("agent not found")
	// ErrAgentInvalid reports a candidate that was claimed but cannot be used:
	// a symlink, a non-regular file, an unreadable or oversized file, or
	// malformed content. It never falls through to a lower-precedence source.
	ErrAgentInvalid = errors.New("agent file unusable")
)
