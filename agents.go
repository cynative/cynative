package cynative

import (
	"embed"
	"io/fs"
)

// builtinAgents embeds the built-in agent files. The all: prefix is
// load-bearing: it includes dot-prefixed files, and the directory currently
// holds only .keep. Without it the build fails with "pattern agents: cannot
// embed directory agents: contains no embeddable files", because an empty
// directory cannot be committed to git either.
//
// This lives at the module root for the same reason about.go does: go:embed
// cannot reference a parent directory, so no package under internal/ can embed
// a top-level directory.
//
//go:embed all:agents
var builtinAgents embed.FS

// BuiltinAgents returns the embedded built-in agent tree, rooted at the module,
// so the agent files are at "agents/<name>.md". Callers narrow it with [fs.Sub].
//
// It returns the tree rather than the already-narrowed subtree deliberately:
// [fs.Sub] returns an error that cannot occur for this fixed, valid path, and a
// defensive branch around it here could never be covered by a test, which the
// coverage gate would reject. The shell handles that error where it is exempt.
func BuiltinAgents() fs.FS {
	return builtinAgents
}
