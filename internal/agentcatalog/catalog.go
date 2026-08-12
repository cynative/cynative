package agentcatalog

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
)

// mdExt is the only extension an agent file may have.
const mdExt = ".md"

// Root is one source the catalog searches, in precedence order. FS is rooted at
// the agents directory itself, so an agent is the single entry "<name>.md".
type Root struct {
	Source      Source
	FS          fs.FS
	DisplayPath string
}

// Entry is one candidate as `agents list` sees it. Err is set when a candidate
// was claimed but cannot be used at all: an escaping symlink, a symlinked or
// non-regular file, an unreadable or oversized file, or malformed content.
// Description is then empty.
type Entry struct {
	Name        string
	Description string
	Source      Source
	Path        string
	// Shadowed is true when a higher-precedence source CLAIMED this name, not
	// "won" it. A blocking invalid claimant shadows lower copies while producing
	// no active winner at all, so "claimed" is the load-bearing word.
	Shadowed bool
	Err      error
}

// Catalog resolves agent names across an ordered set of roots, first match
// wins. It is pure and owns no operating-system handles; OpenSources builds the
// production roots and owns their cleanup.
type Catalog struct {
	roots []Root
}

// New returns a Catalog over roots, searched in the order given.
func New(roots ...Root) *Catalog {
	return &Catalog{roots: roots}
}

// Resolve returns the agent named name from the highest-precedence source that
// holds it.
//
// It fails closed: only a missing directory or a missing entry falls through to
// a lower source. A claimed-but-unusable candidate is an error, so a typo in a
// project agent surfaces instead of silently running a different one.
func (c *Catalog) Resolve(name string) (Definition, error) {
	if err := ValidName(name); err != nil {
		return Definition{}, err
	}

	for _, r := range c.roots {
		def, found, err := readFrom(r, name)
		if err != nil {
			return Definition{}, err
		}
		if found {
			return def, nil
		}
	}

	return Definition{}, fmt.Errorf("%w: %q", ErrAgentNotFound, name)
}

// List returns every candidate in every source, sorted by name then precedence,
// with each entry marked shadowed when a higher-precedence source already
// claimed its name and carrying Err when it is unusable.
//
// A per-file problem is reported in the entry; only a source that cannot be
// enumerated at all is returned as an error, because that makes the precedence
// view itself untrustworthy.
func (c *Catalog) List() ([]Entry, error) {
	claimed := make(map[string]bool)

	var out []Entry

	for _, r := range c.roots {
		names, err := candidateNames(r)
		if err != nil {
			return nil, err
		}

		for _, n := range names {
			out = append(out, entryFor(r, n, claimed[n]))
			claimed[n] = true
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}

		return out[i].Source < out[j].Source
	})

	return out, nil
}

// Names returns the deduplicated agent names across all sources, sorted. It
// never parses a body, so it is cheap enough for shell completion.
//
// A name whose highest-precedence claimant is invalid is still returned:
// completion must not hide the name an operator has to fix, and hiding it would
// misrepresent precedence by silently promoting a shadowed copy.
func (c *Catalog) Names() ([]string, error) {
	seen := make(map[string]bool)

	var out []string

	for _, r := range c.roots {
		names, err := candidateNames(r)
		if err != nil {
			return nil, err
		}

		for _, n := range names {
			if !seen[n] {
				seen[n] = true

				out = append(out, n)
			}
		}
	}

	sort.Strings(out)

	return out, nil
}

// entryFor builds the listing row for one candidate.
func entryFor(r Root, name string, shadowed bool) Entry {
	e := Entry{ //nolint:exhaustruct // Description and Err are set below.
		Name:     name,
		Source:   r.Source,
		Path:     filepath.Join(r.DisplayPath, name+mdExt),
		Shadowed: shadowed,
	}

	def, found, err := readFrom(r, name)

	switch {
	case err != nil:
		e.Err = err
	case !found:
		// Enumerated a moment ago and gone now: report it rather than dropping
		// the row, so a vanishing file is visible instead of silently absent.
		e.Err = fmt.Errorf("%w: %q disappeared during listing", ErrAgentInvalid, name)
	default:
		e.Description = def.Description
	}

	return e
}

// candidateNames returns the valid agent-name stems of the "<name>.md" entries
// directly in r. A missing directory is not an error: that source simply does
// not exist on this machine.
func candidateNames(r Root) ([]string, error) {
	entries, err := fs.ReadDir(r.FS, ".")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("read agents directory %s: %w", r.DisplayPath, err)
	}

	var out []string

	for _, e := range entries {
		name, ok := agentStem(e.Name())
		if !ok {
			continue
		}

		out = append(out, name)
	}

	return out, nil
}

// agentStem returns the agent name for a directory entry, and whether the entry
// is a candidate at all. Everything that is not a "<valid-name>.md" file is
// ignored, which is what keeps .keep, README.md and stray files out.
func agentStem(filename string) (string, bool) {
	if len(filename) <= len(mdExt) || filename[len(filename)-len(mdExt):] != mdExt {
		return "", false
	}

	stem := filename[:len(filename)-len(mdExt)]
	if ValidName(stem) != nil {
		return "", false
	}

	return stem, true
}

// readFrom loads one agent from one root. It distinguishes three outcomes:
// absent (fall through to the next source), present and usable, and present but
// unusable (fail closed).
func readFrom(r Root, name string) (Definition, bool, error) {
	filename := name + mdExt

	entries, err := fs.ReadDir(r.FS, ".")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Definition{}, false, nil
		}

		return Definition{}, false, fmt.Errorf("read agents directory %s: %w", r.DisplayPath, err)
	}

	if !hasEntry(entries, filename) {
		return Definition{}, false, nil
	}

	raw, err := readCandidate(r, filename)
	if err != nil {
		return Definition{}, false, err
	}

	def, err := Parse(name, raw)
	if err != nil {
		return Definition{}, false, fmt.Errorf("%s: %w", filepath.Join(r.DisplayPath, filename), err)
	}

	def.Source = r.Source
	def.Path = filepath.Join(r.DisplayPath, filename)

	return def, true, nil
}

// hasEntry reports whether filename is present as an exact directory entry.
// Matching the listing rather than opening the name is what stops a
// case-insensitive filesystem serving Foo.md for --agent foo.
func hasEntry(entries []fs.DirEntry, filename string) bool {
	for _, e := range entries {
		if e.Name() == filename {
			return true
		}
	}

	return false
}

// readCandidate reads a claimed candidate, rejecting anything that is not a
// plain regular file. The Lstat check is what refuses a symlink: the file's
// bytes go straight into the prompt, so file-level indirection is refused even
// when [os.Root] would have allowed it as contained.
//
// Every failure here wraps ErrAgentInvalid as well as the underlying cause: the
// candidate was claimed, so callers testing [errors.Is](err, ErrAgentInvalid)
// must see it whether the file was malformed or merely unreadable. A whole
// SOURCE that cannot be enumerated is different and stays an enumeration error,
// because it says nothing about any particular candidate.
func readCandidate(r Root, filename string) ([]byte, error) {
	display := filepath.Join(r.DisplayPath, filename)

	info, err := fs.Lstat(r.FS, filename)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %w", ErrAgentInvalid, display, err)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s is a symbolic link", ErrAgentInvalid, display)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrAgentInvalid, display)
	}

	f, err := r.FS.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrAgentInvalid, display, err)
	}
	// A close error cannot affect the bytes already read from a read-only file.
	defer func() { _ = f.Close() }()

	// limit+1 so Parse can reject an oversized file rather than silently
	// truncating it into a half-parsed prompt.
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrAgentInvalid, display, err)
	}

	return raw, nil
}
