package agentcatalog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// agentsRelPath is the agents directory relative to the home directory. It is
// opened as ONE multi-component name through an already-open root, never as a
// nested root per component: see openAgentsRoot.
const agentsRelPath = agentsParentDir + "/" + agentsChildDir

// The two components of agentsRelPath, checked separately: an intermediate
// dangling symlink hides everything beneath it from Lstat, so the parent has to
// be probed on its own.
const (
	agentsParentDir = ".cynative"
	agentsChildDir  = "agents"
)

// builtinSubdir is the embedded directory holding the built-in agents.
const builtinSubdir = "agents"

// builtinDisplayPath labels the embedded tier in listings and provenance.
const builtinDisplayPath = "built-in"

// OpenSources builds the production catalog: the operator's own
// ~/.cynative/agents, then the embedded built-ins.
//
// There is deliberately no project tier. Agents are operator-authored
// configuration, so they are never read from the working directory: a checkout
// must not be able to supply the prompt for a run.
//
// home must be absolute and already canonicalized by the caller through
// [filepath.EvalSymlinks]; it is validated here rather than trusted, because a
// relative home would resolve every lookup against the working directory and
// hand the checkout the user tier.
//
// On failure it closes anything it already opened and returns a nil cleanup. On
// success the returned func closes the retained roots in reverse order.
func OpenSources(home string, builtin fs.FS) (*Catalog, func(), error) {
	if err := ValidateHome(home); err != nil {
		return nil, nil, err
	}

	var opened openedRoots

	userDir, err := claimedUserDir(home)
	if err != nil {
		return nil, nil, err
	}

	if err = opened.add(SourceUser, userDir); err != nil {
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
// what holds every shell function inside the complexity budget.
type openedRoots struct {
	roots   []Root
	handles []*os.Root
}

// add opens dir's agents directory and appends it as a root. An empty dir is a
// source that is simply not present on this machine.
//
// A non-empty dir is one claimedUserDir already established is CLAIMED, so "not
// there" is a contradiction rather than a skip: the .cynative/agents entry
// exists, and a subsequent not-found means it is there but unusable — a dangling
// symlink, most likely. Skipping it would hide the broken source and silently
// resolve a same-named built-in instead.
func (o *openedRoots) add(source Source, dir string) error {
	if dir == "" {
		return nil
	}

	root, ok, err := openAgentsRoot(dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s/%s was claimed but could not be opened", dir, agentsRelPath)
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

// claimedUserDir returns home when it CLAIMS an agents source, or "" when that
// tier is genuinely absent.
func claimedUserDir(home string) (string, error) {
	claimed, err := hasAgentsDir(home)
	if err != nil {
		return "", err
	}

	if !claimed {
		return "", nil
	}

	return home, nil
}

// hasAgentsDir reports whether dir CLAIMS a .cynative/agents source.
//
// The two path components are probed separately because an intermediate
// dangling symlink hides everything beneath it: a stat of the full path would
// report ErrNotExist and the broken source would be silently skipped, after
// which a same-named built-in would resolve in its place.
func hasAgentsDir(dir string) (bool, error) {
	parent := filepath.Join(dir, agentsParentDir)

	ok, err := parentUsable(parent)
	if err != nil || !ok {
		return false, err
	}

	return childClaims(filepath.Join(parent, agentsChildDir))
}

// parentUsable reports whether the .cynative entry exists, resolves, AND is a
// directory. A present-but-dangling one is an error, not an absence.
//
// The directory check matters for availability: a stray regular file named
// .cynative cannot contain an agents entry, so it is an absent source. Without
// the check, the child lookup fails with ENOTDIR, which aborts opening the
// catalog and takes the built-in tier down with it.
func parentUsable(parent string) (bool, error) {
	present, err := entryExists(parent)
	if err != nil || !present {
		return false, err
	}

	info, serr := os.Stat(parent)
	if serr != nil {
		if errors.Is(serr, fs.ErrNotExist) {
			return false, fmt.Errorf("%s is a broken symlink", parent)
		}

		return false, fmt.Errorf("stat %s: %w", parent, serr)
	}

	return info.IsDir(), nil
}

// childClaims reports whether the agents entry claims a source. Lstat, not
// Stat: a symlink claims whatever its target turns out to be.
func childClaims(agents string) (bool, error) {
	info, err := os.Lstat(agents)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("stat %s: %w", agents, err)
	}

	return ClaimsSource(info.Mode()), nil
}

// entryExists reports whether p exists as a directory entry, without following
// it if it is a symlink.
func entryExists(p string) (bool, error) {
	if _, err := os.Lstat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("lstat %s: %w", p, err)
	}

	return true, nil
}

// openAgentsRoot opens parent's agents directory confined to parent.
//
// ok is false ONLY when the directory genuinely is not there. Every other
// failure is propagated: an escaping symlink, a permission failure, an ENOTDIR
// or a symlink loop all mean the source was CLAIMED but could not be opened,
// and skipping those would resolve a same-named built-in in its place.
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
