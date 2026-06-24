package aws

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cynative/cynative/internal/cache"
)

// archiveEntry is one modeled service: its directory and latest API version.
type archiveEntry struct {
	Dir     string `json:"dir"`
	Version string `json:"version"`
}

// archiveIndex maps each host endpoint prefix to the modeled services that
// answer on it (more than one ⇒ a prefix collision). SHA256 is the tarball the
// index was built from, used to detect a stale persisted index.
type archiveIndex struct {
	Prefixes map[string][]archiveEntry `json:"prefixes"`
	SHA256   string                    `json:"sha256"`
}

// ErrUnsupportedService indicates the requested service has no directory in the
// AWS model repository, so cynative cannot model it. Distinct from a transient
// fetch failure; callers fail closed (deny).
var ErrUnsupportedService = errors.New("aws_hardening: service not modeled by cynative")

// parseModelPath matches "models/{dir}/service/{version}/{file}.json" and
// returns the directory and version. ok is false for any other path shape.
func parseModelPath(path string) (string, string, bool) {
	if !strings.HasSuffix(path, ".json") {
		return "", "", false
	}
	const wantParts = 5
	parts := strings.Split(path, "/")
	if len(parts) != wantParts || parts[0] != "models" || parts[2] != "service" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

// parseArchivePath strips the tarball's top-level directory and delegates to
// parseModelPath (e.g. "api-models-aws-main/models/s3/service/V/s3-V.json").
func parseArchivePath(name string) (string, string, bool) {
	i := strings.Index(name, "models/")
	if i < 0 {
		return "", "", false
	}
	return parseModelPath(name[i:])
}

// endpointPrefixOf parses a Smithy model and returns its endpoint prefix from
// the service shape's traits. Lighter than ParseModel (no operation parse).
func endpointPrefixOf(raw []byte) string {
	var doc smithyDoc
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	for _, rawShape := range doc.Shapes {
		var sh smithyShape
		if json.Unmarshal(rawShape, &sh) != nil {
			continue
		}
		if sh.Type == serviceShapeType {
			return extractEndpointPrefix(sh.Traits)
		}
	}
	return ""
}

// buildIndex streams a gzipped tarball of aws/api-models-aws and returns the
// endpointPrefix → entries index, keeping the lexically-max version per dir.
func buildIndex(targz []byte, sha string) (*archiveIndex, error) {
	gzr, gzErr := gzip.NewReader(bytes.NewReader(targz))
	if gzErr != nil {
		return nil, fmt.Errorf("%w: gzip: %w", ErrSmithyUnavailable, gzErr)
	}
	defer func() { _ = gzr.Close() }()
	tr := tar.NewReader(gzr)

	type winner struct{ version, prefix string }
	latest := map[string]winner{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %w", ErrSmithyUnavailable, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dir, version, ok := parseArchivePath(hdr.Name)
		if !ok {
			continue
		}
		if cur, seen := latest[dir]; seen && version <= cur.version {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("%w: read %s: %w", ErrSmithyUnavailable, hdr.Name, err)
		}
		latest[dir] = winner{version: version, prefix: endpointPrefixOf(raw)}
	}
	if len(latest) == 0 {
		return nil, fmt.Errorf("%w: no models in archive", ErrSmithyUnavailable)
	}
	idx := &archiveIndex{Prefixes: map[string][]archiveEntry{}, SHA256: sha}
	for dir, w := range latest {
		if w.prefix == "" {
			continue
		}
		idx.Prefixes[w.prefix] = append(idx.Prefixes[w.prefix], archiveEntry{Dir: dir, Version: w.version})
	}
	return idx, nil
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ModelArchiveConfig wires the archive's external dependencies via injection.
type ModelArchiveConfig struct {
	cache.Config

	Fetcher func(ctx context.Context) ([]byte, error) // fetches the .tar.gz.
}

// ModelArchive caches the aws/api-models-aws repository tarball and serves the
// endpointPrefix→model resolution from it. In-memory → on-disk (per TTL) →
// fetcher, with stale-disk fallback on fetch failure. Replaces TreeIndex and
// the per-model HTTPS fetcher.
type ModelArchive struct {
	cfg       ModelArchiveConfig
	byteCache *cache.TTLCache[[]byte] // the .tar.gz tier (shared TTL disk cache).
	mu        sync.Mutex
	index     *archiveIndex
	raw       []byte   // cached .tar.gz bytes, for model extraction. Read-only after set.
	memo      sync.Map // dir -> *ServiceModel
}

// NewModelArchive constructs an archive. Caller must set all cfg fields.
func NewModelArchive(cfg ModelArchiveConfig) *ModelArchive {
	dir := filepath.Join(cfg.Dir, "archive")
	return &ModelArchive{ //nolint:exhaustruct // mu/index/raw/memo zero-valued by design.
		cfg: cfg,
		byteCache: &cache.TTLCache[[]byte]{
			DataPath: filepath.Join(dir, "repo.tar.gz"),
			MetaPath: filepath.Join(dir, "repo.meta"),
			TTL:      cfg.TTL,
			Clock:    cfg.Clock,
			Fetch:    cfg.Fetcher,
			Parse:    func(raw []byte) (*[]byte, error) { return &raw, nil }, // identity.
		},
	}
}

func (a *ModelArchive) indexPath() string {
	return filepath.Join(a.cfg.Dir, "archive", "index.json")
}

// load resolves the index, fetching/caching the tarball as needed.
func (a *ModelArchive) load(ctx context.Context) (*archiveIndex, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.index != nil {
		return a.index, nil
	}
	raw := a.byteCache.Get(ctx)
	if raw == nil {
		// Fetch failed and no stale tarball on disk. The cache reports a miss as
		// nil; the underlying fetch error detail is not surfaced (accepted).
		return nil, fmt.Errorf("%w: fetch archive failed", ErrSmithyUnavailable)
	}
	return a.useArchive(*raw)
}

// useArchive sets the raw bytes and builds-or-loads the index for them.
func (a *ModelArchive) useArchive(raw []byte) (*archiveIndex, error) {
	sha := sha256Hex(raw)
	if idx, ok := a.tryLoadIndex(sha); ok {
		a.raw, a.index = raw, idx
		return idx, nil
	}
	idx, err := buildIndex(raw, sha)
	if err != nil {
		return nil, err
	}
	_ = a.persistIndex(idx)
	a.raw, a.index = raw, idx
	return idx, nil
}

func (a *ModelArchive) tryLoadIndex(sha string) (*archiveIndex, bool) {
	raw, err := os.ReadFile(a.indexPath())
	if err != nil {
		return nil, false
	}
	var idx archiveIndex
	if json.Unmarshal(raw, &idx) != nil || idx.SHA256 != sha || len(idx.Prefixes) == 0 {
		return nil, false
	}
	return &idx, true
}

func (a *ModelArchive) persistIndex(idx *archiveIndex) error {
	dir := filepath.Join(a.cfg.Dir, "archive")
	if err := os.MkdirAll(dir, cache.DirPerm); err != nil {
		return fmt.Errorf("mkdir cache: %w", err)
	}
	b, _ := json.MarshalIndent(idx, "", "  ") //nolint:errchkjson // archiveIndex is JSON-safe.
	return os.WriteFile(a.indexPath(), b, cache.FilePerm)
}

// Resolve returns every modeled service answering on the host endpoint prefix
// (more than one ⇒ a collision the caller disambiguates by operation).
// Returns ErrUnsupportedService when no service is indexed for the prefix.
func (a *ModelArchive) Resolve(ctx context.Context, prefix string) ([]*ServiceModel, error) {
	idx, err := a.load(ctx)
	if err != nil {
		return nil, err
	}
	entries := idx.Prefixes[prefix]
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedService, prefix)
	}
	out := make([]*ServiceModel, 0, len(entries))
	for _, e := range entries {
		m, modelErr := a.modelFor(idx, e.Dir, e.Version)
		if modelErr != nil {
			return nil, modelErr
		}
		out = append(out, m)
	}
	return out, nil
}

func (a *ModelArchive) modelFor(idx *archiveIndex, dir, version string) (*ServiceModel, error) {
	if v, ok := a.memo.Load(dir); ok {
		return v.(*ServiceModel), nil //nolint:forcetypeassert,errcheck // memo only stores *ServiceModel.
	}
	raw, err := extractModel(a.raw, dir, version)
	if err != nil {
		return nil, err
	}
	m, err := ParseModel(raw)
	if err != nil {
		return nil, err
	}
	m.Dir = dir
	// Computed before memoization so the shared *ServiceModel is never mutated
	// after publication (race-free under -race).
	m.NamespaceShadowed = namespaceShadowed(idx, m)
	actual, _ := a.memo.LoadOrStore(dir, m)
	return actual.(*ServiceModel), nil //nolint:forcetypeassert,errcheck // memo only stores *ServiceModel.
}

// namespaceShadowed reports whether a different-dir model owns m's ARN namespace
// as an endpoint prefix (so m's IAM namespace belongs to a foreign primary
// service and must not be used to resolve m's operations).
func namespaceShadowed(idx *archiveIndex, m *ServiceModel) bool {
	if m.ARNNamespace == "" {
		return false
	}
	for _, e := range idx.Prefixes[m.ARNNamespace] {
		if e.Dir != m.Dir {
			return true
		}
	}
	return false
}

// extractModel streams the cached tarball and returns the bytes of the model at
// models/{dir}/service/{version}/…json.
func extractModel(targz []byte, dir, version string) ([]byte, error) {
	gzr, gzErr := gzip.NewReader(bytes.NewReader(targz))
	if gzErr != nil {
		return nil, fmt.Errorf("%w: gzip: %w", ErrSmithyUnavailable, gzErr)
	}
	defer func() { _ = gzr.Close() }()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %w", ErrSmithyUnavailable, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if d, v, ok := parseArchivePath(hdr.Name); ok && d == dir && v == version {
			b, readErr := io.ReadAll(tr)
			if readErr != nil {
				return nil, fmt.Errorf("%w: read model: %w", ErrSmithyUnavailable, readErr)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: model %s/%s not in archive", ErrSmithyUnavailable, dir, version)
}
