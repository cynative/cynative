package agentcatalog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// agentsRelPath is the agents directory relative to a project or home
// directory. It is opened as ONE multi-component name through an already-open
// root, never as a nested root per component: see openAgentsRoot.
const agentsRelPath = ".cynative/agents"

// builtinSubdir is the embedded directory holding the built-in agents.
const builtinSubdir = "agents"

// builtinDisplayPath labels the embedded tier in listings and provenance.
const builtinDisplayPath = "built-in"

// OpenSources builds the production catalog: the nearest project agents
// directory bounded by the git root, the user directory, and the embedded
// built-ins.
//
// cwd and home must already be canonicalized by the caller through
// [filepath.EvalSymlinks], and canonicalized the same way, or the home boundary
// in [ProjectSearchPath] cannot be enforced.
//
// On failure it closes anything it already opened and returns a nil cleanup. On
// success the returned func closes the retained roots in reverse order.
func OpenSources(cwd, home string, builtin fs.FS) (*Catalog, func(), error) {
	var opened openedRoots

	projectDir, err := findProjectDir(cwd, home)
	if err != nil {
		return nil, nil, err
	}

	if err = opened.add(SourceProject, projectDir); err != nil {
		opened.closeAll()

		return nil, nil, err
	}

	if err = opened.add(SourceUser, home); err != nil {
		opened.closeAll()

		return nil, nil, err
	}

	builtinFS, err := fs.Sub(builtin, builtinSubdir)
	if err != nil {
		opened.closeAll()

		return nil, nil, fmt.Errorf("open embedded agents: %w", err)
	}

	opened.roots = append(opened.roots, Root{Source: SourceBuiltin, FS: builtinFS, DisplayPath: builtinDisplayPath})

	return New(opened.roots...), opened.closeAll, nil
}

// openedRoots accumulates the OS handles OpenSources takes ownership of,
// alongside the catalog roots they back. Keeping the bookkeeping on a type is
// what holds every shell function inside the complexity budget: OpenSources
// itself becomes a straight line of guarded steps.
type openedRoots struct {
	roots   []Root
	handles []*os.Root
}

// add opens dir's agents directory and appends it as a root. An empty dir or an
// absent directory is skipped silently; every other failure is returned.
func (o *openedRoots) add(source Source, dir string) error {
	if dir == "" {
		return nil
	}

	root, ok, err := openAgentsRoot(dir)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	o.handles = append(o.handles, root)
	o.roots = append(o.roots, Root{
		Source:      source,
		FS:          root.FS(),
		DisplayPath: filepath.Join(dir, agentsRelPath),
	})

	return nil
}

// closeAll closes the retained handles in reverse order of opening.
func (o *openedRoots) closeAll() {
	for _, h := range slices.Backward(o.handles) {
		_ = h.Close()
	}
}

// findProjectDir returns the nearest directory holding a .cynative/agents,
// searched from cwd up to the git root, or "" when there is none.
func findProjectDir(cwd, home string) (string, error) {
	candidates, err := ProjectSearchPath(cwd, home, hasGitMarker)
	if err != nil {
		return "", err
	}

	for _, dir := range candidates {
		ok, serr := hasAgentsDir(dir)
		if serr != nil {
			return "", serr
		}
		if ok {
			return dir, nil
		}
	}

	return "", nil
}

// hasAgentsDir reports whether dir holds a .cynative/agents directory. A
// non-directory at that path is treated as absent, not as an error: it is a
// stray file, not a claimed source.
func hasAgentsDir(dir string) (bool, error) {
	info, err := os.Stat(filepath.Join(dir, agentsRelPath))
	if err == nil {
		return info.IsDir(), nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, fmt.Errorf("stat agents dir under %s: %w", dir, err)
}

// hasGitMarker reports whether dir holds a .git file or directory. A worktree
// or submodule uses a .git FILE, so this deliberately does not require a
// directory.
func hasGitMarker(dir string) (bool, error) {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, fmt.Errorf("lstat: %w", err)
}

// openAgentsRoot opens parent's agents directory confined to parent.
//
// ok is false ONLY when the directory genuinely is not there. Every other
// failure is propagated, and that distinction is the fail-closed contract:
// an escaping symlink, a permission failure, an ENOTDIR, or a symlink loop all
// mean a project tier was CLAIMED but could not be opened. Skipping those would
// silently run a lower-precedence user or built-in agent under a name the
// project meant to define, which is exactly the substitution the precedence
// rules exist to prevent.
//
// The whole relative path is opened through ONE root. Nesting a second root at
// .cynative would be weaker: if .cynative were a contained symlink, re-rooting
// at it would confine "agents" to the symlink's target instead of to parent.
func openAgentsRoot(parent string) (*os.Root, bool, error) {
	boundary, err := os.OpenRoot(parent)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("open %s: %w", parent, err)
	}
	defer func() { _ = boundary.Close() }()

	root, err := boundary.OpenRoot(agentsRelPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("open %s in %s: %w", agentsRelPath, parent, err)
	}

	return root, true, nil
}
