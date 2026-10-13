package azure

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/cynative/cynative/internal/cache"
)

const (
	// maxIndexBytes bounds the cached index read from disk.
	maxIndexBytes = 64 << 20
	// maxFileBytes bounds one spec file after decompression (largest measured 2.04 MB on 2026-10-12).
	maxFileBytes = 16 << 20
	// maxFileCacheBytes is the size the store evicts the on-disk file and summary cache down to, least recently used
	// first. It is a target the store works toward on its own writes, not a hard limit (see noteWrite and evict).
	maxFileCacheBytes = 512 << 20
	// rescanEvery is how many cache writes a store makes between two scans of the files dir. A scan is what sees
	// the writes of other processes sharing the dir.
	rescanEvery    = 256
	indexCacheName = "index"
	filesDirName   = "files"
	blobSuffix     = ".json"
	summarySuffix  = ".ops.json"
	tempPrefix     = "."
)

// FileSummary is what a lookup needs from one spec file to search it: its declared version and its operations.
type FileSummary struct {
	Version string      `json:"version"`
	Ops     []OpSummary `json:"ops"`
}

// OpSummary is one operation of a spec file.
type OpSummary struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	XMs    bool   `json:"x_ms,omitempty"`
}

// SpecStoreConfig configures a SpecStore.
type SpecStoreConfig struct {
	// Cache is the store's directory (<cache.dir>/azure/specs), TTL and clock.
	Cache cache.Config
	// Client is anonymous and refuses redirects.
	Client  *http.Client
	RepoURL string
	RawBase string
	// Scrub removes proxy credentials from an error; nil leaves errors unchanged.
	Scrub func(error) error
	// Listing lists the repository; nil means FetchListing.
	Listing func(ctx context.Context, client *http.Client, repoURL string) (*Listing, error)
	// Summarize reads a spec file's summary. Required.
	Summarize func(body []byte) (*FileSummary, error)
}

// SpecStore serves the specs index and the spec files a lookup needs, verified by blob id and cached on disk by it.
// It never sends a credential.
type SpecStore struct {
	client    *http.Client
	rawBase   string
	scrub     func(error) error
	summarize func([]byte) (*FileSummary, error)
	clock     func() time.Time
	filesDir  string
	index     *cache.TTLCache[Index]
	failure   *cache.LoadFailure
	maxFile   int64
	maxCache  int64
	// writeFile writes a temp file; tests replace it to fail after some bytes are written.
	writeFile func(name string, data []byte, perm os.FileMode) error
	// readDir lists the files dir for eviction; tests count its calls.
	readDir func(name string) ([]os.DirEntry, error)
	// remove deletes an evicted file; tests make it fail.
	remove func(name string) error
	// joined runs when a caller joins a download already in flight, and leading when a caller starts one; tests
	// use them to order goroutines and to fill the cache in between.
	joined, leading func()
	seq             atomic.Uint64

	mu      sync.Mutex
	flights map[string]*flight

	// loadMu guards loading, the index load in flight, or nil when none is.
	loadMu  sync.Mutex
	loading *indexLoad

	// sizeMu guards cacheSize, the bytes the files dir held at the last scan plus every write since, or -1 before
	// the first scan; writes, the store's cache writes so far; and rescan, how many writes apart scans are.
	sizeMu    sync.Mutex
	cacheSize int64
	writes    int
	rescan    int
}

// flight is one blob download that later callers for the same blob wait on.
type flight struct {
	done chan struct{}
	body []byte
	err  error
	// abandoned is set when the download failed after the leader's own context ended, the one outcome a joiner
	// still live does not share.
	abandoned bool
}

// indexLoad is one index load that every concurrent Index caller waits on. The loader writes ix before it closes
// done, and callers read ix only after done is closed.
type indexLoad struct {
	done chan struct{}
	ix   *Index
}

// NewSpecStore builds the store. Nothing is read until the first Index, File or Summary call.
func NewSpecStore(cfg SpecStoreConfig) *SpecStore {
	listing := cfg.Listing
	if listing == nil {
		listing = FetchListing
	}
	scrub := cfg.Scrub
	if scrub == nil {
		scrub = func(err error) error { return err }
	}
	fetch := func(ctx context.Context) ([]byte, error) {
		l, err := listing(ctx, cfg.Client, cfg.RepoURL)
		if err != nil {
			return nil, err
		}
		ix, err := BuildIndex(l)
		if err != nil {
			return nil, err
		}

		return ix.Serialize(), nil
	}
	tc := cache.NewNamedCache(cfg.Cache, indexCacheName, fetch, unmarshalIndex, (*Index).Serialize,
		unmarshalIndex, admitIndex)
	tc.MaxDiskBytes = maxIndexBytes

	return &SpecStore{
		client:    cfg.Client,
		rawBase:   strings.TrimSuffix(cfg.RawBase, "/"),
		scrub:     scrub,
		summarize: cfg.Summarize,
		clock:     cfg.Cache.Clock,
		filesDir:  filepath.Join(cfg.Cache.Dir, filesDirName),
		index:     tc,
		failure:   cache.RecordLoadFailure(tc),
		maxFile:   maxFileBytes,
		maxCache:  maxFileCacheBytes,
		writeFile: os.WriteFile,
		readDir:   os.ReadDir,
		remove:    os.Remove,
		cacheSize: -1,
		rescan:    rescanEvery,
		joined:    func() {},
		leading:   func() {},
		flights:   map[string]*flight{},
	}
}

// Index returns the specs index, from memory, the disk cache or a fresh listing. When there is no index, the error
// wraps ErrSpecsUnavailable and either this caller's context error, when its context ended first, or the last listing
// failure, scrubbed.
//
// A loaded index is returned without waiting. Otherwise the caller starts the store's one load, or joins the one in
// flight, and waits for it or for its own context. The load runs in its own goroutine under the context of the caller
// that started it with the cancellation removed, so no caller's interrupt or deadline stops a load the others share;
// the listing's own deadline (listingTimeout) bounds it.
func (s *SpecStore) Index(ctx context.Context) (*Index, error) {
	if ix := s.index.TryPeek(); ix != nil {
		return ix, nil
	}
	l, err := s.joinIndexLoad(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSpecsUnavailable, err)
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrSpecsUnavailable, ctx.Err())
	case <-l.done:
	}
	if l.ix != nil {
		return l.ix, nil
	}

	return nil, s.scrub(fmt.Errorf("%w: %w", ErrSpecsUnavailable, s.failure.Err()))
}

// joinIndexLoad returns the index load in flight, starting one when none is. The loader clears loading before it
// closes done, so a caller that finds none after that point starts a new load, which a failed load needs for a retry.
// A caller whose context has ended joins a load in flight but never starts one; with none in flight it gets its
// context's error.
func (s *SpecStore) joinIndexLoad(ctx context.Context) (*indexLoad, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if s.loading != nil {
		return s.loading, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l := &indexLoad{done: make(chan struct{})}
	s.loading = l
	loadCtx := context.WithoutCancel(ctx)
	go func() {
		l.ix = s.index.Get(loadCtx)
		s.loadMu.Lock()
		s.loading = nil
		s.loadMu.Unlock()
		close(l.done)
	}()

	return l, nil
}

// File returns the body of f at commit sha, verified against f's blob id: from the disk cache when a cached copy
// still matches, else downloaded once for every concurrent caller.
func (s *SpecStore) File(ctx context.Context, sha string, f IndexFile) ([]byte, error) {
	// A warm cache answers from disk, which never looks at the context, so a done lookup is stopped here.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validSHA(sha) || !validSHA(f.Blob) {
		return nil, fmt.Errorf("%w: commit or blob id of %q", ErrSpecsRejected, f.Path)
	}
	if body, ok := s.readCached(f.Blob); ok {
		return body, nil
	}
	body, err := s.download(ctx, sha, f)
	if err != nil {
		return nil, s.scrub(err)
	}

	return body, nil
}

// Summary returns f's summary: a cached one costs nothing; a fresh one charges the file's bytes to b before it is
// parsed, and is cached for the next lookup.
func (s *SpecStore) Summary(ctx context.Context, sha string, f IndexFile, b *Budget) (*FileSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validSHA(f.Blob) {
		return nil, fmt.Errorf("%w: blob id of %q", ErrSpecsRejected, f.Path)
	}
	if sum, ok := s.readSummary(f.Blob); ok {
		return sum, nil
	}
	body, err := s.File(ctx, sha, f)
	if err != nil {
		return nil, err
	}
	if err = b.Charge(int64(len(body))); err != nil {
		return nil, err
	}
	sum, err := s.summarize(body)
	if err != nil {
		return nil, fmt.Errorf("%w: summarize %q: %w", ErrSpecsRejected, f.Path, err)
	}
	// A record of strings and slices always encodes.
	rec, _ := json.Marshal(summaryRecord{
		Format: summaryFormat, Blob: f.Blob, Summary: sum, Check: summaryCheck(summaryFormat, f.Blob, sum),
	})
	if s.writeAtomic(f.Blob+summarySuffix, rec) == nil {
		s.noteWrite(int64(len(rec)))
	}

	return sum, nil
}

// summaryFormat versions the cached summary record; a record of another format is rebuilt.
const summaryFormat = 1

// summaryRecord is a cached summary with the blob it was built from and a check over both. The check refuses a
// truncated, bit-flipped or hand-edited record, one that keeps its blob field but drops or renames operations
// included. It cannot stop a process running as the same user, which could rewrite the check too and could as well
// edit the gate's own caches; against that, the lookup re-reads every operation it renders from the verified file
// and refuses one whose id the summary got wrong (swaggerDoc.operation).
type summaryRecord struct {
	Format  int          `json:"format"`
	Blob    string       `json:"blob"`
	Summary *FileSummary `json:"summary"`
	Check   string       `json:"check"`
}

// summaryCheck is the SHA-256 of a record's format, blob and summary as encoded.
func summaryCheck(format int, blob string, sum *FileSummary) string {
	// A struct of an int, a string and a summary of strings and slices always encodes.
	b, _ := json.Marshal(struct {
		Format  int          `json:"format"`
		Blob    string       `json:"blob"`
		Summary *FileSummary `json:"summary"`
	}{format, blob, sum})
	h := sha256.Sum256(b)

	return hex.EncodeToString(h[:])
}

func (s *SpecStore) readSummary(blob string) (*FileSummary, bool) {
	path := filepath.Join(s.filesDir, blob+summarySuffix)
	b, err := readFileCapped(path, s.maxFile)
	var rec summaryRecord
	if err != nil || json.Unmarshal(b, &rec) != nil || rec.Format != summaryFormat || rec.Blob != blob ||
		rec.Summary == nil || rec.Check != summaryCheck(rec.Format, rec.Blob, rec.Summary) {
		return nil, false
	}
	s.touch(path)

	return rec.Summary, true
}

// readCached returns a cached file whose content still matches its blob id, deleting one that does not.
func (s *SpecStore) readCached(blob string) ([]byte, bool) {
	path := filepath.Join(s.filesDir, blob+blobSuffix)
	b, err := readFileCapped(path, s.maxFile)
	if err != nil {
		return nil, false
	}
	if gitBlobID(b) != blob {
		_ = os.Remove(path)

		return nil, false
	}
	s.touch(path)

	return b, true
}

// Download coordination. The flights map belongs to the store, so these hold across every lookup that shares one
// store; a process that builds one store gets them process-wide:
//
//  1. At most one download per blob is in flight. A caller registers a flight under mu only when none exists for
//     the blob, and the leader deletes it under mu before it closes done, so a caller that finds no flight after
//     that point starts a new one and never joins a finished flight.
//  2. The leader's lookup owns the download's context. The request runs under the leader's ctx and nothing else
//     can cancel it, so a joiner that gives up returns its own ctx.Err() and leaves the download running.
//  3. The leader writes body and err before it closes done, and joiners read them only after done is closed, so
//     the close orders those reads after the writes. The body is shared by every caller and none may modify it.
//  4. A joiner still live when the download failed because the leader's own context ended (abandoned) loops and
//     downloads or joins again under its own context. Any other outcome is shared and final, a client timeout
//     included, though its error also matches [context.DeadlineExceeded].
//  5. The leader rechecks the disk after it wins the flight, because another flight may have written the blob
//     between this caller's cache miss and its registration; the blob check runs on that read as on any other.
//
// download fetches one blob for every concurrent caller under the rules above.
func (s *SpecStore) download(ctx context.Context, sha string, f IndexFile) ([]byte, error) {
	for {
		s.mu.Lock()
		fl, joined := s.flights[f.Blob]
		if !joined {
			fl = &flight{done: make(chan struct{})}
			s.flights[f.Blob] = fl
		}
		s.mu.Unlock()
		if !joined {
			s.leading()
			// Another lookup may have finished this blob between the caller's cache miss and this leadership.
			if body, ok := s.readCached(f.Blob); ok {
				fl.body = body
			} else {
				fl.body, fl.err = s.fetchVerified(ctx, sha, f)
			}
			fl.abandoned = fl.err != nil && ctx.Err() != nil
			s.mu.Lock()
			delete(s.flights, f.Blob)
			s.mu.Unlock()
			close(fl.done)

			return fl.body, fl.err
		}
		s.joined()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-fl.done:
		}
		if !fl.abandoned || ctx.Err() != nil {
			return fl.body, fl.err
		}
	}
}

// fetchVerified downloads one file from the raw host at sha and keeps it only when it matches its blob id.
func (s *SpecStore) fetchVerified(ctx context.Context, sha string, f IndexFile) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.rawURL(sha, f.Path), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request for %q: %w", ErrSpecsRejected, f.Path, err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %q: status %d", ErrSpecsRejected, f.Path, resp.StatusCode)
	}
	body, err := readAllCapped(resp.Body, s.maxFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read %q: %w", ErrSpecsRejected, f.Path, err)
	}
	if gitBlobID(body) != f.Blob {
		return nil, fmt.Errorf("%w: %q does not match blob %s", ErrSpecsRejected, f.Path, f.Blob)
	}
	if s.writeAtomic(f.Blob+blobSuffix, body) == nil {
		s.noteWrite(int64(len(body)))
	}

	return body, nil
}

// rawURL is the raw host's URL of path at sha, each path segment escaped.
func (s *SpecStore) rawURL(sha, path string) string {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}

	return s.rawBase + "/" + sha + "/" + strings.Join(segs, "/")
}

// writeAtomic writes name in the files dir through a temp file beside it and a rename, so a reader never sees
// half a file. A failed write or rename removes the temp file, which evict never counts or removes.
func (s *SpecStore) writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(s.filesDir, cache.DirPerm); err != nil {
		return err
	}
	final := filepath.Join(s.filesDir, name)
	tmp := filepath.Join(filepath.Dir(final),
		fmt.Sprintf("%s%s.%d.%d.tmp", tempPrefix, filepath.Base(name), os.Getpid(), s.seq.Add(1)))
	if err := s.writeFile(tmp, data, cache.FilePerm); err != nil {
		_ = os.Remove(tmp)

		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)

		return err
	}

	return nil
}

// noteWrite adds a write of n bytes to the running total and scans the files dir on the store's first write, on
// every rescan-th write and whenever the total passes maxCache. Between scans the total misses other processes'
// writes and overcounts a rewritten or deleted file, so the dir can exceed maxCache by what other processes wrote
// since this store's last scan. Only a write can scan, so the dir can stay over maxCache until a store sharing it
// makes a write that scans.
func (s *SpecStore) noteWrite(n int64) {
	s.sizeMu.Lock()
	defer s.sizeMu.Unlock()
	s.writes++
	if s.cacheSize >= 0 && s.writes%s.rescan != 0 {
		s.cacheSize += n
		if s.cacheSize <= s.maxCache {
			return
		}
	}
	s.cacheSize = s.evict()
}

// evict removes the least recently used cache files it lists, oldest first, until the ones left fit within maxCache,
// and returns the bytes it counts as left. A file it fails to remove still counts, so the result can stay over
// maxCache. It counts only the regular files it can list and stat; temp files are skipped, since they belong to
// writes in flight, possibly in another process, so the dir can hold more than it counts.
func (s *SpecStore) evict() int64 {
	type cached struct {
		path string
		size int64
		mod  time.Time
	}
	// ReadDir of a missing dir returns no entries, which evicts nothing.
	entries, _ := s.readDir(s.filesDir)
	var files []cached
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && !strings.HasPrefix(e.Name(), tempPrefix) {
			files = append(
				files,
				cached{path: filepath.Join(s.filesDir, e.Name()), size: info.Size(), mod: info.ModTime()},
			)
			total += info.Size()
		}
	}
	slices.SortFunc(
		files,
		func(a, b cached) int { return cmp.Or(a.mod.Compare(b.mod), cmp.Compare(a.path, b.path)) },
	)
	for _, f := range files {
		if total <= s.maxCache {
			break
		}
		if s.remove(f.path) == nil {
			total -= f.size
		}
	}

	return total
}

// touch marks a cache file as just used.
func (s *SpecStore) touch(path string) {
	now := s.clock()
	_ = os.Chtimes(path, now, now)
}

// readFileCapped reads path, refusing more than limit bytes.
func readFileCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return readAllCapped(f, limit)
}

// readAllCapped reads r to the end, refusing more than limit bytes.
func readAllCapped(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrSpecsRejected, limit)
	}

	return b, nil
}

// gitBlobID is git's blob id of body: the SHA-1 of "blob <len>\0" followed by body.
func gitBlobID(body []byte) string {
	return plumbing.ComputeHash(plumbing.BlobObject, body).String()
}

// Budget is one lookup's allowance of parsed spec bytes. It is safe for concurrent use.
type Budget struct {
	mu        sync.Mutex
	remaining int64
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit int64) *Budget {
	return &Budget{remaining: limit}
}

// Charge takes n bytes from the budget and fails once less than nothing is left.
func (b *Budget) Charge(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remaining -= n
	if b.remaining < 0 {
		return ErrBudgetExceeded
	}

	return nil
}
