package azure

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

const (
	kindStable  = "stable"
	kindPreview = "preview"

	specsRoot         = "specification"
	resourceManager   = "resource-manager"
	commonTypesDir    = "common-types"
	serviceCommonDir  = "common"
	examplesDir       = "examples"
	jsonSuffix        = ".json"
	adminSuffix       = ".Admin"
	newLayoutSegs     = 8
	classicLayoutSegs = 7
	// refMinSegs is specification/<svc>/<file> at the shortest.
	refMinSegs = 3
	// groupIDMaxParts is "<svc>/<Service>".
	groupIDMaxParts = 2
)

var (
	namespacePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)+$`)
	versionPattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(-[a-z][a-z0-9.]*)?$`)
	groupPartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	fileNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$`)
	// operationPattern admits every stable operationId of 2026-10-12 (117,672, the longest 96 bytes).
	operationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$`)
	// refSegmentPattern admits every segment an operation file's path can hold, so BuildIndex never drops an
	// operation file as a ref target. The longest file name is 180 bytes, bounded by the selector check. The
	// namespace is not part of the selector; parseOpPath bounds it with this same pattern.
	refSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,204}$`)
	shaPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Index maps the specs tree at one commit: namespace, then group, then version dir, then operation files, plus
// every file a $ref may resolve to.
type Index struct {
	SHA        string                     `json:"sha"`
	Namespaces map[string]*IndexNamespace `json:"namespaces"`
	Refs       map[string]string          `json:"refs"`
}

// IndexNamespace is one resource-provider namespace, keyed by its lower-cased name.
type IndexNamespace struct {
	Name   string                 `json:"name"`
	Groups map[string]*IndexGroup `json:"groups"`
}

// IndexGroup is one spec group: a service dir, and in the new layout its service name.
type IndexGroup struct {
	Dirs []IndexDir `json:"dirs"`
}

// IndexDir is one version dir, stable or preview.
type IndexDir struct {
	Kind  string      `json:"kind"`
	Name  string      `json:"name"`
	Files []IndexFile `json:"files"`
}

// IndexFile is one operation file with its blob id.
type IndexFile struct {
	Path string `json:"path"`
	Blob string `json:"blob"`
}

// opFile is where an operation file sits in one of the two layouts.
type opFile struct {
	namespace, group, kind, dir, file string
}

// BuildIndex indexes a listing. It refuses a listing with a bad commit or blob id, and one that holds no operation
// file, and what it returns has passed admitIndex.
func BuildIndex(l *Listing) (*Index, error) {
	if !validSHA(l.SHA) {
		return nil, fmt.Errorf("%w: commit id %q", ErrSpecsRejected, l.SHA)
	}
	ix := &Index{SHA: l.SHA, Namespaces: map[string]*IndexNamespace{}, Refs: map[string]string{}}
	for _, e := range l.Entries {
		if !validSHA(e.Blob) {
			return nil, fmt.Errorf("%w: blob id of %q", ErrSpecsRejected, e.Path)
		}
		if !refTarget(e.Path) {
			continue
		}
		ix.Refs[e.Path] = e.Blob
		if of, ok := parseOpPath(e.Path); ok {
			ix.add(of, IndexFile(e))
		}
	}
	ix.sort()
	if err := admitIndex(ix); err != nil {
		return nil, err
	}

	return ix, nil
}

// Serialize encodes the index for the cache.
func (ix *Index) Serialize() []byte {
	// An Index holds only strings, slices and string-keyed maps, so Marshal cannot fail.
	b, _ := json.Marshal(ix)

	return b
}

func (ix *Index) add(of opFile, f IndexFile) {
	key := strings.ToLower(of.namespace)
	ns := ix.Namespaces[key]
	if ns == nil {
		ns = &IndexNamespace{Name: of.namespace, Groups: map[string]*IndexGroup{}}
		ix.Namespaces[key] = ns
	}
	ns.Name = min(ns.Name, of.namespace)
	g := ns.Groups[of.group]
	if g == nil {
		g = &IndexGroup{}
		ns.Groups[of.group] = g
	}
	i := slices.IndexFunc(g.Dirs, func(d IndexDir) bool { return d.Kind == of.kind && d.Name == of.dir })
	if i < 0 {
		g.Dirs = append(g.Dirs, IndexDir{Kind: of.kind, Name: of.dir})
		i = len(g.Dirs) - 1
	}
	g.Dirs[i].Files = append(g.Dirs[i].Files, f)
}

func (ix *Index) sort() {
	for _, ns := range ix.Namespaces {
		for _, g := range ns.Groups {
			slices.SortFunc(g.Dirs, compareDirs)
			for i := range g.Dirs {
				slices.SortFunc(g.Dirs[i].Files, func(a, b IndexFile) int { return cmp.Compare(a.Path, b.Path) })
			}
		}
	}
}

// compareDirs orders dirs newest first by name, then stable before preview.
func compareDirs(a, b IndexDir) int {
	return cmp.Or(cmp.Compare(b.Name, a.Name), cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)))
}

func kindRank(kind string) int {
	if kind == kindStable {
		return 0
	}

	return 1
}

// unmarshalIndex decodes a cached index; admitIndex then checks it.
func unmarshalIndex(b []byte) (*Index, error) {
	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, fmt.Errorf("%w: decode index: %w", ErrSpecsRejected, err)
	}

	return &ix, nil
}

// admitIndex checks every part of an index a lookup trusts, so an index read back from disk can never widen what
// a lookup fetches: the commit and blob ids, every path against its grammar, and every file where its path puts it.
func admitIndex(ix *Index) error {
	if !validSHA(ix.SHA) || len(ix.Namespaces) == 0 {
		return fmt.Errorf("%w: index has no valid commit or no namespace", ErrSpecsRejected)
	}
	for p, blob := range ix.Refs {
		if !refTarget(p) || !validSHA(blob) {
			return fmt.Errorf("%w: ref target %q", ErrSpecsRejected, p)
		}
	}
	for key, ns := range ix.Namespaces {
		if err := admitNamespace(ix, key, ns); err != nil {
			return err
		}
	}

	return nil
}

func admitNamespace(ix *Index, key string, ns *IndexNamespace) error {
	if ns == nil || key != strings.ToLower(ns.Name) || !validNamespace(ns.Name) || len(ns.Groups) == 0 {
		return fmt.Errorf("%w: namespace %q", ErrSpecsRejected, key)
	}
	for gid, g := range ns.Groups {
		if g == nil || len(g.Dirs) == 0 {
			return fmt.Errorf("%w: group %q of %s has no dirs", ErrSpecsRejected, gid, ns.Name)
		}
		// Dirs must be strictly ordered: no equal neighbors.
		for i := 1; i < len(g.Dirs); i++ {
			if compareDirs(g.Dirs[i-1], g.Dirs[i]) >= 0 {
				return fmt.Errorf("%w: group %q dirs not strictly ordered", ErrSpecsRejected, gid)
			}
		}
		for _, d := range g.Dirs {
			if err := admitDir(ix, key, gid, d); err != nil {
				return err
			}
		}
	}

	return nil
}

func admitDir(ix *Index, key, gid string, d IndexDir) error {
	if len(d.Files) == 0 {
		return fmt.Errorf("%w: dir %s/%s of %s holds no file", ErrSpecsRejected, d.Kind, d.Name, gid)
	}
	// Files must be strictly ordered by path: no equal neighbors.
	for i := 1; i < len(d.Files); i++ {
		if cmp.Compare(d.Files[i-1].Path, d.Files[i].Path) >= 0 {
			return fmt.Errorf("%w: dir %s/%s files not strictly ordered", ErrSpecsRejected, d.Kind, d.Name)
		}
	}
	for _, f := range d.Files {
		if !validSHA(f.Blob) {
			return fmt.Errorf("%w: file %q blob", ErrSpecsRejected, f.Path)
		}
		b, ok := ix.Refs[f.Path]
		if !ok || b != f.Blob {
			return fmt.Errorf("%w: file %q ref mismatch", ErrSpecsRejected, f.Path)
		}
		of, opOK := parseOpPath(f.Path)
		if !opOK || strings.ToLower(of.namespace) != key || of.group != gid || of.kind != d.Kind || of.dir != d.Name {
			return fmt.Errorf("%w: file %q is not where the index puts it", ErrSpecsRejected, f.Path)
		}
	}

	return nil
}

// parseOpPath classifies a repository path as an operation file of either layout.
func parseOpPath(p string) (opFile, bool) {
	segs := strings.Split(p, "/")
	if len(segs) < classicLayoutSegs || segs[0] != specsRoot || segs[2] != resourceManager {
		return opFile{}, false
	}
	var of opFile
	switch len(segs) {
	case newLayoutSegs:
		of = opFile{namespace: segs[3], group: segs[1] + "/" + segs[4], kind: segs[5], dir: segs[6], file: segs[7]}
	case classicLayoutSegs:
		of = opFile{namespace: segs[3], group: segs[1], kind: segs[4], dir: segs[5], file: segs[6]}
	default:
		return opFile{}, false
	}
	ok := !slices.Contains(segs, examplesDir) && validNamespace(of.namespace) &&
		!strings.HasSuffix(of.namespace, adminSuffix) && refSegmentPattern.MatchString(of.namespace) &&
		validGroupID(of.group) && (of.kind == kindStable || of.kind == kindPreview) && validVersion(of.dir) &&
		validFileName(of.file) && len(of.selector()) <= apiref.MaxChoice

	return of, ok
}

// selector is the longest name a lookup can give this file in an ambiguous answer, <group>@<kind>/<dir>/<file>.
// A file whose selector would not fit one choice (apiref.MaxChoice) is not indexed, since a cut selector names
// nothing; the longest on 2026-10-12 was 131 bytes, so no real file is affected. Every part is ASCII, so bytes
// are runes.
func (of opFile) selector() string {
	return of.group + "@" + of.kind + "/" + of.dir + "/" + of.file
}

// refTarget reports whether a $ref may resolve to p: a JSON file outside examples, under a service's
// resource-manager tree, under a service's common tree (Synapse's resource-manager files ref
// specification/synapse/common/v1/types.json) or under common-types, with every segment in the ref-segment grammar.
func refTarget(p string) bool {
	segs := strings.Split(p, "/")
	if len(segs) < refMinSegs || segs[0] != specsRoot || !strings.HasSuffix(p, jsonSuffix) ||
		slices.Contains(segs, examplesDir) {
		return false
	}
	if segs[1] != commonTypesDir && segs[2] != resourceManager && segs[2] != serviceCommonDir {
		return false
	}
	for _, s := range segs {
		if !refSegmentPattern.MatchString(s) {
			return false
		}
	}

	return true
}

func validNamespace(s string) bool { return namespacePattern.MatchString(s) }

func validVersion(s string) bool { return versionPattern.MatchString(s) }

func validGroupPart(s string) bool { return groupPartPattern.MatchString(s) }

func validFileName(s string) bool { return fileNamePattern.MatchString(s) }

func validOperation(s string) bool { return operationPattern.MatchString(s) }

func validSHA(s string) bool { return shaPattern.MatchString(s) }

// validGroupID reports whether g is "<svc>" or "<svc>/<Service>" with each part in the group-part grammar.
func validGroupID(g string) bool {
	parts := strings.Split(g, "/")
	if len(parts) > groupIDMaxParts {
		return false
	}
	for _, part := range parts {
		if !validGroupPart(part) {
			return false
		}
	}

	return true
}
