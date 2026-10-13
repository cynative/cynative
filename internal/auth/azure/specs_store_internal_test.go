package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

const testRawBase = "https://raw.example/Azure/azure-rest-api-specs"

// rawServer serves raw files: every path's body is the path itself, so fakeBlob verifies it, unless overridden.
type rawServer struct {
	mu       sync.Mutex
	bodies   map[string][]byte
	statuses map[string]int
	hits     map[string]int
	gate     chan struct{} // when set, every request waits on it
	started  chan struct{} // when set, signalled once per request before waiting
	err      error
	urls     []string
}

func newRawServer() *rawServer {
	return &rawServer{bodies: map[string][]byte{}, statuses: map[string]int{}, hits: map[string]int{}}
}

func (s *rawServer) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/Azure/azure-rest-api-specs/"+testSHA+"/")
	s.hits[path]++
	s.urls = append(s.urls, r.URL.String())
	body, ok := s.bodies[path]
	if !ok {
		body = []byte(path)
	}
	status, ok := s.statuses[path]
	if !ok {
		status = http.StatusOK
	}
	gate, started, err := s.gate, s.started, s.err
	s.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	if err != nil {
		return nil, err
	}

	return fakeResponse(r, status, body), nil
}

func (s *rawServer) hitsFor(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.hits[path]
}

// summaries counts summarize calls; a body "bad" fails.
type summaries struct{ calls atomic.Int32 }

func (c *summaries) summarize(body []byte) (*FileSummary, error) {
	c.calls.Add(1)
	if string(body) == "bad" {
		return nil, errors.New("not swagger")
	}

	return &FileSummary{Version: "v1", Ops: []OpSummary{{ID: "Op_" + string(body[:3]), Method: "GET", Path: "/x"}}}, nil
}

func newTestStore(
	t *testing.T,
	rt http.RoundTripper,
	listing func(context.Context, *http.Client, string) (*Listing, error),
) (*SpecStore, *summaries) {
	t.Helper()
	sums := &summaries{}
	s := NewSpecStore(SpecStoreConfig{
		Cache:     cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Client:    &http.Client{Transport: rt},
		RepoURL:   testRepoURL,
		RawBase:   testRawBase,
		Listing:   listing,
		Summarize: sums.summarize,
	})

	return s, sums
}

func staticListing(l *Listing) func(context.Context, *http.Client, string) (*Listing, error) {
	return func(context.Context, *http.Client, string) (*Listing, error) { return l, nil }
}

func fileOf(path string) IndexFile { return IndexFile{Path: path, Blob: fakeBlob(path).String()} }

// TestSpecStore_IndexLoadsOnceAndMemoizes pins the index load: one listing, then memory.
func TestSpecStore_IndexLoadsOnceAndMemoizes(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	s, _ := newTestStore(t, newRawServer(), func(context.Context, *http.Client, string) (*Listing, error) {
		calls.Add(1)

		return listingOf(computeNew), nil
	})
	for range 2 {
		ix, err := s.Index(t.Context())
		if err != nil || ix.SHA != testSHA {
			t.Fatalf("Index = %+v, %v", ix, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("listing ran %d times, want 1", calls.Load())
	}
}

// TestSpecStore_IndexFailureIsRecordedAndScrubbed pins the unavailable error: it wraps ErrSpecsUnavailable and the
// cause, and passes through the scrubber.
func TestSpecStore_IndexFailureIsRecordedAndScrubbed(t *testing.T) {
	t.Parallel()
	cases := map[string]func(context.Context, *http.Client, string) (*Listing, error){
		"listing error": func(context.Context, *http.Client, string) (*Listing, error) {
			return nil, fmt.Errorf("dial proxy user:hunter2@proxy: %w", errTransport)
		},
		"index refused": staticListing(&Listing{SHA: "bad"}),
	}
	for name, listing := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sums := &summaries{}
			s := NewSpecStore(SpecStoreConfig{
				Cache:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
				Client: &http.Client{Transport: newRawServer()}, RepoURL: testRepoURL, RawBase: testRawBase,
				Listing: listing, Summarize: sums.summarize,
				Scrub: func(err error) error {
					return &scrubbedTestError{text: strings.ReplaceAll(err.Error(), "hunter2", "***"), err: err}
				},
			})
			_, err := s.Index(t.Context())
			if !errors.Is(err, ErrSpecsUnavailable) || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

type scrubbedTestError struct {
	text string
	err  error
}

func (e *scrubbedTestError) Error() string { return e.text }
func (e *scrubbedTestError) Unwrap() error { return e.err }

// TestSpecStore_IndexRefusesAnOversizeCache pins MaxDiskBytes on the index cache: an index file over the bound is
// not served even as a stale fallback.
func TestSpecStore_IndexRefusesAnOversizeCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := func(listing func(context.Context, *http.Client, string) (*Listing, error)) SpecStoreConfig {
		sums := &summaries{}

		return SpecStoreConfig{
			Cache:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
			Client: &http.Client{Transport: newRawServer()}, RepoURL: testRepoURL, RawBase: testRawBase,
			Listing: listing, Summarize: sums.summarize,
		}
	}
	seed := NewSpecStore(cfg(staticListing(listingOf(computeNew))))
	if seed.index.MaxDiskBytes != 64<<20 {
		t.Fatalf("index MaxDiskBytes = %d, want 64 MiB", seed.index.MaxDiskBytes)
	}
	if _, err := seed.Index(t.Context()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, indexCacheName+".json"))
	if err != nil {
		t.Fatal(err)
	}
	failing := func(context.Context, *http.Client, string) (*Listing, error) { return nil, errTransport }
	// The same cached file at exactly the bound is served, and one byte over it is refused.
	atBound := NewSpecStore(cfg(failing))
	atBound.index.MaxDiskBytes = info.Size()
	if ix, ixErr := atBound.Index(t.Context()); ixErr != nil || ix.SHA != testSHA {
		t.Fatalf("at the bound: Index = %+v, %v", ix, ixErr)
	}
	over := NewSpecStore(cfg(failing))
	over.index.MaxDiskBytes = info.Size() - 1
	if _, err = over.Index(t.Context()); !errors.Is(err, ErrSpecsUnavailable) || !errors.Is(err, errTransport) {
		t.Fatalf("over the bound: err = %v, want ErrSpecsUnavailable wrapping the listing failure", err)
	}
}

// TestSpecStore_IndexAdmitsTheCachedIndex pins admission on the cache read: a cached index that is fresh and
// decodes but holds an invalid blob id is refused and the index is listed again, never served.
func TestSpecStore_IndexAdmitsTheCachedIndex(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tampered, err := BuildIndex(listingOf(computeNew))
	if err != nil {
		t.Fatal(err)
	}
	forEachIndexFile(tampered, func(f *IndexFile) { f.Blob = "../../not-a-blob" })
	meta, _ := json.Marshal(map[string]time.Time{"fetched_at": time.Now()})
	for name, data := range map[string][]byte{".json": tampered.Serialize(), ".meta": meta} {
		if err = os.WriteFile(filepath.Join(dir, indexCacheName+name), data, cache.FilePerm); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	sums := &summaries{}
	s := NewSpecStore(SpecStoreConfig{
		Cache:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
		Client: &http.Client{Transport: newRawServer()}, RepoURL: testRepoURL, RawBase: testRawBase,
		Listing: func(context.Context, *http.Client, string) (*Listing, error) {
			calls.Add(1)

			return listingOf(computeNew), nil
		}, Summarize: sums.summarize,
	})
	ix, err := s.Index(t.Context())
	if err != nil || calls.Load() != 1 {
		t.Fatalf("Index = %v after %d listings, want a fresh listing", err, calls.Load())
	}
	forEachIndexFile(ix, func(f *IndexFile) {
		if !validSHA(f.Blob) {
			t.Errorf("served a tampered blob id %q", f.Blob)
		}
	})
}

// forEachIndexFile calls fn on every file of ix in place.
func forEachIndexFile(ix *Index, fn func(*IndexFile)) {
	for _, ns := range ix.Namespaces {
		for _, g := range ns.Groups {
			for i := range g.Dirs {
				for j := range g.Dirs[i].Files {
					fn(&g.Dirs[i].Files[j])
				}
			}
		}
	}
}

// TestSpecStore_IndexDefaultsToTheGitListing pins that a nil Listing uses FetchListing over the client.
func TestSpecStore_IndexDefaultsToTheGitListing(t *testing.T) {
	t.Parallel()
	r := newTestRepo(t)
	commit := r.commit(r.files(computeNew))
	pack := r.pack(0, false)
	srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
	s, _ := newTestStore(t, srv, nil)
	ix, err := s.Index(t.Context())
	if err != nil || ix.SHA != commit.String() || ix.Namespaces["microsoft.compute"] == nil {
		t.Fatalf("Index = %+v, %v", ix, err)
	}
}

// TestSpecStore_FileDownloadsVerifiesAndCaches pins the raw URL, the blob check and that a second read comes from
// disk with no request.
func TestSpecStore_FileDownloadsVerifiesAndCaches(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	s, _ := newTestStore(t, srv, nil)
	for range 2 {
		body, err := s.File(t.Context(), testSHA, fileOf(computeNew))
		if err != nil || string(body) != computeNew {
			t.Fatalf("File = %q, %v", body, err)
		}
	}
	if n := srv.hitsFor(computeNew); n != 1 {
		t.Errorf("downloads = %d, want 1", n)
	}
	if want := testRawBase + "/" + testSHA + "/" + computeNew; srv.urls[0] != want {
		t.Errorf("url = %s, want %s", srv.urls[0], want)
	}
	if _, err := os.Stat(filepath.Join(s.filesDir, fakeBlob(computeNew).String()+blobSuffix)); err != nil {
		t.Errorf("cached file: %v", err)
	}
}

// TestSpecStore_FileRefusals pins every refusal of File; none caches anything.
func TestSpecStore_FileRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup func(s *SpecStore, srv *rawServer)
		sha   string
		file  IndexFile
		want  error
	}{
		"bad commit id": {nil, "nope", fileOf(computeNew), ErrSpecsRejected},
		"bad blob id":   {nil, testSHA, IndexFile{Path: computeNew, Blob: "../x"}, ErrSpecsRejected},
		"blob mismatch": {
			func(_ *SpecStore, srv *rawServer) { srv.bodies[computeNew] = []byte("tampered") }, testSHA,
			fileOf(computeNew), ErrSpecsRejected,
		},
		"status": {
			func(_ *SpecStore, srv *rawServer) { srv.statuses[computeNew] = http.StatusMovedPermanently },
			testSHA, fileOf(computeNew), ErrSpecsRejected,
		},
		"too large": {
			func(s *SpecStore, _ *rawServer) { s.maxFile = 4 }, testSHA, fileOf(computeNew),
			ErrSpecsRejected,
		},
		"transport": {
			func(_ *SpecStore, srv *rawServer) { srv.err = errTransport }, testSHA, fileOf(computeNew),
			errTransport,
		},
		"bad raw base": {
			func(s *SpecStore, _ *rawServer) { s.rawBase = "http://bad host" }, testSHA,
			fileOf(computeNew), ErrSpecsRejected,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := newRawServer()
			s, _ := newTestStore(t, srv, nil)
			if tc.setup != nil {
				tc.setup(s, srv)
			}
			if _, err := s.File(t.Context(), tc.sha, tc.file); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if entries, _ := os.ReadDir(s.filesDir); len(entries) != 0 {
				t.Errorf("cached %d files after a refusal", len(entries))
			}
		})
	}
}

// TestSpecStore_FileSizeBound pins the 16 MiB per-file bound at its edge: a body of exactly the bound is served,
// one byte more is refused.
func TestSpecStore_FileSizeBound(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		size int
		ok   bool
	}{"at the bound": {16 << 20, true}, "one byte over": {16<<20 + 1, false}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := bytes.Repeat([]byte("x"), tc.size)
			srv := newRawServer()
			srv.bodies[computeNew] = body
			s, _ := newTestStore(t, srv, nil)
			got, err := s.File(t.Context(), testSHA, IndexFile{Path: computeNew, Blob: gitBlobID(body)})
			if tc.ok && (err != nil || len(got) != tc.size) {
				t.Fatalf("File = %d bytes, %v", len(got), err)
			}
			if !tc.ok && !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("err = %v, want ErrSpecsRejected", err)
			}
		})
	}
}

// TestSpecStore_FileCacheBound pins the on-disk file cache cap at 512 MiB; TestSpecStore_EvictsLeastRecentlyUsed
// pins the eviction at a cap's edge.
func TestSpecStore_FileCacheBound(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t, newRawServer(), nil)
	if s.maxCache != 512<<20 || s.maxFile != 16<<20 {
		t.Fatalf("maxCache = %d, maxFile = %d", s.maxCache, s.maxFile)
	}
}

// TestSpecStore_FileBodyReadError pins a body that fails mid-read.
func TestSpecStore_FileBodyReadError(t *testing.T) {
	t.Parallel()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: io.NopCloser(io.MultiReader(strings.NewReader("abc"), errReader{})),
		}, nil
	})
	s, _ := newTestStore(t, rt, nil)
	if _, err := s.File(t.Context(), testSHA, fileOf(computeNew)); !errors.Is(err, errTransport) {
		t.Fatalf("err = %v, want errTransport", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errTransport }

// TestSpecStore_CorruptCacheIsRefetched pins the integrity check on a cache read: a cached file whose content no
// longer matches its blob id is deleted and fetched again, and a directory planted at that name is skipped.
func TestSpecStore_CorruptCacheIsRefetched(t *testing.T) {
	t.Parallel()
	for name, plant := range map[string]func(path string) error{
		"edited":    func(path string) error { return os.WriteFile(path, []byte("edited"), cache.FilePerm) },
		"directory": func(path string) error { _ = os.Remove(path); return os.Mkdir(path, cache.DirPerm) },
		"too large": func(path string) error {
			return os.WriteFile(path, bytes.Repeat([]byte("x"), len(computeNew)+1), cache.FilePerm)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := newRawServer()
			s, _ := newTestStore(t, srv, nil)
			s.maxFile = int64(len(computeNew))
			if _, err := s.File(t.Context(), testSHA, fileOf(computeNew)); err != nil {
				t.Fatalf("seed: %v", err)
			}
			path := filepath.Join(s.filesDir, fakeBlob(computeNew).String()+blobSuffix)
			if err := plant(path); err != nil {
				t.Fatalf("plant: %v", err)
			}
			body, err := s.File(t.Context(), testSHA, fileOf(computeNew))
			if err != nil || string(body) != computeNew || srv.hitsFor(computeNew) != 2 {
				t.Fatalf("File = %q, %v after %d downloads", body, err, srv.hitsFor(computeNew))
			}
		})
	}
}

// TestSpecStore_JoinsOneDownloadPerBlob pins that concurrent readers of one blob share one download.
func TestSpecStore_JoinsOneDownloadPerBlob(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.gate = make(chan struct{})
	srv.started = make(chan struct{}, 1)
	s, _ := newTestStore(t, srv, nil)
	joined := signalJoins(s)
	results := make(chan error, 2)
	read := func() {
		body, err := s.File(t.Context(), testSHA, fileOf(computeNew))
		if err == nil && string(body) != computeNew {
			err = fmt.Errorf("body %q", body)
		}
		results <- err
	}
	go read()
	<-srv.started
	go read()
	<-joined
	close(srv.gate)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("File: %v", err)
		}
	}
	if n := srv.hitsFor(computeNew); n != 1 {
		t.Errorf("downloads = %d, want 1", n)
	}
}

// signalJoins chains a signal onto the store's joined hook, keeping the default it wraps.
func signalJoins(s *SpecStore) <-chan struct{} {
	joined := make(chan struct{}, 1)
	prev := s.joined
	s.joined = func() {
		prev()
		joined <- struct{}{}
	}

	return joined
}

// TestSpecStore_AJoinerGivesUpAlone pins that a joiner whose context ends returns at once while the download it
// joined carries on for the lookup that started it.
func TestSpecStore_AJoinerGivesUpAlone(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.gate = make(chan struct{})
	srv.started = make(chan struct{}, 1)
	s, _ := newTestStore(t, srv, nil)
	joined := signalJoins(s)
	leader := make(chan error, 1)
	go func() {
		_, err := s.File(t.Context(), testSHA, fileOf(computeNew))
		leader <- err
	}()
	<-srv.started
	ctx, cancel := context.WithCancel(t.Context())
	joinerDone := make(chan error, 1)
	go func() {
		_, err := s.File(ctx, testSHA, fileOf(computeNew))
		joinerDone <- err
	}()
	<-joined
	cancel()
	if err := <-joinerDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("joiner err = %v, want context.Canceled", err)
	}
	close(srv.gate)
	if err := <-leader; err != nil {
		t.Fatalf("leader err = %v", err)
	}
}

// TestSpecStore_AJoinerRetriesWhenTheLeaderIsCancelled pins that a joiner still live when the leader's lookup ends
// downloads the blob itself.
func TestSpecStore_AJoinerRetriesWhenTheLeaderIsCancelled(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.gate = make(chan struct{})
	srv.started = make(chan struct{}, 2)
	s, _ := newTestStore(t, srv, nil)
	joined := signalJoins(s)
	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	leader := make(chan error, 1)
	go func() {
		_, err := s.File(leaderCtx, testSHA, fileOf(computeNew))
		leader <- err
	}()
	<-srv.started
	joiner := make(chan error, 1)
	go func() {
		_, err := s.File(t.Context(), testSHA, fileOf(computeNew))
		joiner <- err
	}()
	<-joined
	cancelLeader()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v, want context.Canceled", err)
	}
	<-srv.started
	close(srv.gate)
	if err := <-joiner; err != nil {
		t.Fatalf("joiner err = %v", err)
	}
	if n := srv.hitsFor(computeNew); n != 2 {
		t.Errorf("downloads = %d, want 2", n)
	}
}

// TestSpecStore_AJoinerSharesALeadersTimeout pins that a download that fails with a deadline error while the
// leader's own context is live, as a client timeout does, is shared with its joiner and not downloaded again.
func TestSpecStore_AJoinerSharesALeadersTimeout(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.gate = make(chan struct{})
	srv.started = make(chan struct{}, 2)
	srv.err = context.DeadlineExceeded
	s, _ := newTestStore(t, srv, nil)
	joined := signalJoins(s)
	results := make(chan error, 2)
	read := func() {
		_, err := s.File(t.Context(), testSHA, fileOf(computeNew))
		results <- err
	}
	go read()
	<-srv.started
	go read()
	<-joined
	close(srv.gate)
	for range 2 {
		if err := <-results; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the shared deadline error", err)
		}
	}
	if n := srv.hitsFor(computeNew); n != 1 {
		t.Errorf("downloads = %d, want 1", n)
	}
}

// TestSpecStore_SummaryChargesOnlyWhatItParses pins the summary cache: a fresh summary charges the file's bytes,
// a cached one charges nothing and runs no parse, and a corrupt cached record is rebuilt.
func TestSpecStore_SummaryChargesOnlyWhatItParses(t *testing.T) {
	t.Parallel()
	s, sums := newTestStore(t, newRawServer(), nil)
	b := NewBudget(int64(len(computeNew)))
	sum, err := s.Summary(t.Context(), testSHA, fileOf(computeNew), b)
	if err != nil || sum.Version != "v1" || sum.Ops[0].ID != "Op_spe" {
		t.Fatalf("Summary = %+v, %v", sum, err)
	}
	if err = b.Charge(0); err != nil {
		t.Fatalf("budget after one fresh summary: %v", err)
	}
	if _, err = s.Summary(t.Context(), testSHA, fileOf(computeNew), b); err != nil || sums.calls.Load() != 1 {
		t.Fatalf("cached Summary: %v after %d parses", err, sums.calls.Load())
	}
	if err = b.Charge(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("a cached summary charged the budget: %v", err)
	}
	rec := filepath.Join(s.filesDir, fakeBlob(computeNew).String()+summarySuffix)
	blob := fakeBlob(computeNew).String()
	// Each record keeps the right blob and is refused for another reason: the check is what catches an edit that
	// drops the operations or renames one, and the format what retires an old layout.
	edited, _ := json.Marshal(summaryRecord{
		Format: summaryFormat, Blob: blob, Summary: &FileSummary{Version: "v1"},
		Check: summaryCheck(summaryFormat, blob, sum),
	})
	renamed, _ := json.Marshal(summaryRecord{
		Format: summaryFormat, Blob: blob,
		Summary: &FileSummary{Version: "v1", Ops: []OpSummary{{ID: "Other", Method: "GET", Path: "/x"}}},
		Check:   summaryCheck(summaryFormat, blob, sum),
	})
	oldFormat, _ := json.Marshal(summaryRecord{
		Format: summaryFormat + 1, Blob: blob, Summary: sum,
		Check: summaryCheck(summaryFormat+1, blob, sum),
	})
	for i, bad := range [][]byte{[]byte(`{"blob":"other","summary":{}}`), edited, renamed, oldFormat} {
		if err = os.WriteFile(rec, bad, cache.FilePerm); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		before := sums.calls.Load()
		if _, err = s.Summary(t.Context(), testSHA, fileOf(computeNew), NewBudget(1<<20)); err != nil ||
			sums.calls.Load() != before+1 {
			t.Fatalf("record %d: rebuilt Summary: %v, parses %d -> %d", i, err, before, sums.calls.Load())
		}
	}
}

// TestSpecStore_WarmCacheHonoursTheContext pins that a done context stops File and Summary even when both could
// answer from disk without any I/O that looks at it.
func TestSpecStore_WarmCacheHonoursTheContext(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t, newRawServer(), nil)
	if _, err := s.Summary(t.Context(), testSHA, fileOf(computeNew), NewBudget(1<<20)); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.File(ctx, testSHA, fileOf(computeNew)); !errors.Is(err, context.Canceled) {
		t.Errorf("warm File: err = %v, want context.Canceled", err)
	}
	if _, err := s.Summary(ctx, testSHA, fileOf(computeNew), NewBudget(1<<20)); !errors.Is(err, context.Canceled) {
		t.Errorf("warm Summary: err = %v, want context.Canceled", err)
	}
}

// TestSpecStore_LeaderRechecksTheCache pins the recheck after a caller wins the download: when the blob landed on
// disk in between, the leader serves it and never downloads.
func TestSpecStore_LeaderRechecksTheCache(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	s, _ := newTestStore(t, srv, nil)
	s.leading = func() {
		if err := s.writeAtomic(fakeBlob(computeNew).String()+blobSuffix, []byte(computeNew)); err != nil {
			t.Errorf("fill the cache: %v", err)
		}
	}
	body, err := s.File(t.Context(), testSHA, fileOf(computeNew))
	if err != nil || string(body) != computeNew || srv.hitsFor(computeNew) != 0 {
		t.Fatalf("File = %q, %v after %d downloads; want the cached copy and none", body, err,
			srv.hitsFor(computeNew))
	}
}

// TestSpecStore_SummaryRefusals pins every Summary failure.
func TestSpecStore_SummaryRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup  func(srv *rawServer)
		file   IndexFile
		budget int64
		want   error
	}{
		"bad blob id": {nil, IndexFile{Path: computeNew, Blob: "x"}, 1 << 20, ErrSpecsRejected},
		"file error":  {func(srv *rawServer) { srv.err = errTransport }, fileOf(computeNew), 1 << 20, errTransport},
		"budget":      {nil, fileOf(computeNew), 3, ErrBudgetExceeded},
		"summarize": {
			func(srv *rawServer) { srv.bodies["bad.json"] = []byte("bad") },
			IndexFile{Path: "bad.json", Blob: fakeBlob("bad").String()},
			1 << 20, ErrSpecsRejected,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := newRawServer()
			if tc.setup != nil {
				tc.setup(srv)
			}
			s, _ := newTestStore(t, srv, nil)
			if _, err := s.Summary(t.Context(), testSHA, tc.file, NewBudget(tc.budget)); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSpecStore_WriteAtomicFailures pins the three ways a cache write fails; File and Summary treat a failed
// write as best effort.
func TestSpecStore_WriteAtomicFailures(t *testing.T) {
	t.Parallel()
	t.Run("mkdir", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t, newRawServer(), nil)
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, cache.FilePerm); err != nil {
			t.Fatal(err)
		}
		s.filesDir = filepath.Join(blocker, "files")
		if err := s.writeAtomic("x.json", []byte("x")); err == nil {
			t.Fatal("writeAtomic under a regular file succeeded")
		}
		if body, err := s.File(t.Context(), testSHA, fileOf(computeNew)); err != nil || string(body) != computeNew {
			t.Fatalf("File with an unwritable cache = %q, %v", body, err)
		}
	})
	t.Run("write", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t, newRawServer(), nil)
		if err := s.writeAtomic("missing/x.json", []byte("x")); err == nil {
			t.Fatal("writeAtomic into a missing subdirectory succeeded")
		}
	})
	t.Run("rename", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t, newRawServer(), nil)
		target := filepath.Join(s.filesDir, "x.json")
		if err := os.MkdirAll(filepath.Join(target, "inner"), cache.DirPerm); err != nil {
			t.Fatal(err)
		}
		if err := s.writeAtomic("x.json", []byte("x")); err == nil {
			t.Fatal("writeAtomic over a non-empty directory succeeded")
		}
		if entries, _ := os.ReadDir(s.filesDir); len(entries) != 1 {
			t.Errorf("temp file left behind: %d entries", len(entries))
		}
	})
}

// TestSpecStore_WriteAtomicRemovesAPartialWrite pins that a write failing after some bytes reached the temp file
// removes it, since evict never counts or removes a temp file.
func TestSpecStore_WriteAtomicRemovesAPartialWrite(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t, newRawServer(), nil)
	s.writeFile = func(name string, data []byte, perm os.FileMode) error {
		if err := os.WriteFile(name, data[:len(data)/2], perm); err != nil {
			return err
		}

		return errors.New("disk full")
	}
	if err := s.writeAtomic("x.json", []byte("0123456789")); err == nil {
		t.Fatal("writeAtomic with a failing write succeeded")
	}
	if entries, _ := os.ReadDir(s.filesDir); len(entries) != 0 {
		t.Errorf("a failed write left %d entries, want none", len(entries))
	}
}

// TestSpecStore_EvictsLeastRecentlyUsed pins the cache cap: the oldest files go first, a read refreshes a file's
// place, and in-flight temp files are never evicted.
func TestSpecStore_EvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	s, _ := newTestStore(t, srv, nil)
	paths := []string{computeNew, computeOld, diskNew}
	for _, p := range paths {
		if _, err := s.File(t.Context(), testSHA, fileOf(p)); err != nil || srv.hitsFor(p) != 1 {
			t.Fatalf("File %s: %v after %d downloads", p, err, srv.hitsFor(p))
		}
	}
	old := time.Now().Add(-time.Hour)
	for i, p := range paths {
		at := old.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filepath.Join(s.filesDir, fakeBlob(p).String()+blobSuffix), at, at); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.readCached(fakeBlob(computeNew).String()); !ok {
		t.Fatal("cached read failed")
	}
	tmp := filepath.Join(s.filesDir, ".in-flight.tmp")
	if err := os.WriteFile(tmp, bytes.Repeat([]byte("t"), 1000), cache.FilePerm); err != nil {
		t.Fatal(err)
	}
	s.maxCache = int64(len(computeNew) + len(diskNew))
	s.evict()
	for p, want := range map[string]bool{computeNew: true, computeOld: false, diskNew: true} {
		_, err := os.Stat(filepath.Join(s.filesDir, fakeBlob(p).String()+blobSuffix))
		if (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", p, err == nil, want)
		}
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("temp file evicted: %v", err)
	}
	s.filesDir = filepath.Join(t.TempDir(), "absent")
	s.evict()
}

// TestBudget_Charge pins the budget: within it nothing fails, past it every charge fails.
func TestBudget_Charge(t *testing.T) {
	t.Parallel()
	b := NewBudget(10)
	if err := b.Charge(10); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := b.Charge(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("past the limit: %v", err)
	}
	if err := b.Charge(0); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("after the limit: %v", err)
	}
}

// TestBudget_ChargeIsSafeConcurrently pins that concurrent charges, as a lookup's parallel summary loads make,
// account every byte: under -race, 8 goroutines charging 100 bytes each exhaust a 799-byte budget exactly once.
func TestBudget_ChargeIsSafeConcurrently(t *testing.T) {
	t.Parallel()
	b := NewBudget(799)
	var wg sync.WaitGroup
	var over atomic.Int32
	for range 8 {
		wg.Go(func() {
			if b.Charge(100) != nil {
				over.Add(1)
			}
		})
	}
	wg.Wait()
	if over.Load() != 1 {
		t.Fatalf("%d charges failed, want exactly 1", over.Load())
	}
}

// TestSpecStore_ScrubDefaultsToIdentity pins that a store with no scrubber returns errors unchanged.
func TestSpecStore_ScrubDefaultsToIdentity(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.err = errTransport
	s, _ := newTestStore(t, srv, nil)
	if _, err := s.File(t.Context(), testSHA, fileOf(computeNew)); !errors.Is(err, errTransport) ||
		!strings.Contains(err.Error(), errTransport.Error()) {
		t.Fatalf("err = %v", err)
	}
}

// TestSpecStore_FileScrubsDownloadErrors pins that a spec file's download error passes through the scrubber, as a
// proxy credential in a transport error would.
func TestSpecStore_FileScrubsDownloadErrors(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	srv.err = fmt.Errorf("dial proxy user:hunter2@proxy: %w", errTransport)
	s := NewSpecStore(SpecStoreConfig{
		Cache:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Client: &http.Client{Transport: srv}, RepoURL: testRepoURL, RawBase: testRawBase,
		Summarize: (&summaries{}).summarize,
		Scrub: func(err error) error {
			return &scrubbedTestError{text: strings.ReplaceAll(err.Error(), "hunter2", "***"), err: err}
		},
	})
	_, err := s.File(t.Context(), testSHA, fileOf(computeNew))
	if !errors.Is(err, errTransport) || strings.Contains(err.Error(), "hunter2") ||
		!strings.Contains(err.Error(), "***") {
		t.Fatalf("err = %v, want the transport error scrubbed", err)
	}
}

// TestSpecStore_ReadSummaryBounds pins the two checks on a cached summary record that the other refusals do not
// reach: a record over the per-file bound is not read, and a valid record copied from another blob is refused.
func TestSpecStore_ReadSummaryBounds(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t, newRawServer(), nil)
	blob := fakeBlob(computeNew).String()
	if _, err := s.Summary(t.Context(), testSHA, fileOf(computeNew), NewBudget(1<<20)); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	rec, err := os.ReadFile(filepath.Join(s.filesDir, blob+summarySuffix))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}
	s.maxFile = int64(len(rec))
	if _, ok := s.readSummary(blob); !ok {
		t.Fatalf("a record of exactly the bound was refused")
	}
	s.maxFile = int64(len(rec)) - 1
	if _, ok := s.readSummary(blob); ok {
		t.Fatalf("a record over the bound was read")
	}
	s.maxFile = maxFileBytes
	other := fakeBlob(diskNew).String()
	if err = os.WriteFile(filepath.Join(s.filesDir, other+summarySuffix), rec, cache.FilePerm); err != nil {
		t.Fatalf("copy the record: %v", err)
	}
	if _, ok := s.readSummary(other); ok {
		t.Fatalf("a record copied from blob %s was served for blob %s", blob, other)
	}
}

// TestSpecStore_ScansOnlyPastTheCap pins the running total: the first write scans the files dir to start it, a write
// that keeps the total under the cap scans nothing, and the write that passes the cap scans and evicts the least
// recently used file.
func TestSpecStore_ScansOnlyPastTheCap(t *testing.T) {
	t.Parallel()
	srv := newRawServer()
	s, _ := newTestStore(t, srv, nil)
	var scans atomic.Int32
	s.readDir = func(name string) ([]os.DirEntry, error) {
		scans.Add(1)

		return os.ReadDir(name)
	}
	s.maxCache = int64(len(computeNew) + len(computeOld) + len(diskNew) - 1)
	read := func(p string) {
		t.Helper()
		if _, err := s.File(t.Context(), testSHA, fileOf(p)); err != nil {
			t.Fatalf("File %s: %v", p, err)
		}
	}
	read(computeNew)
	if n := scans.Load(); n != 1 {
		t.Fatalf("the first write scanned %d times, want 1", n)
	}
	read(computeOld)
	if n := scans.Load(); n != 1 {
		t.Fatalf("a write under the cap scanned: %d scans, want 1", n)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(s.filesDir, fakeBlob(computeOld).String()+blobSuffix), old, old); err != nil {
		t.Fatal(err)
	}
	read(diskNew)
	if n := scans.Load(); n != 2 {
		t.Fatalf("the write past the cap scanned %d times in all, want 2", n)
	}
	for p, want := range map[string]bool{computeNew: true, computeOld: false, diskNew: true} {
		_, err := os.Stat(filepath.Join(s.filesDir, fakeBlob(p).String()+blobSuffix))
		if (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", p, err == nil, want)
		}
	}
	if s.cacheSize != int64(len(computeNew)+len(diskNew)) {
		t.Errorf("the total after eviction is %d, want %d", s.cacheSize, len(computeNew)+len(diskNew))
	}
}

// dirTotal is the bytes of the files dir that evict counts: regular files, temp files left out.
func dirTotal(t *testing.T, dir string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the files dir: %v", err)
	}
	var total int64
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil {
			t.Fatalf("stat %s: %v", e.Name(), ierr)
		}
		if info.Mode().IsRegular() && !strings.HasPrefix(e.Name(), tempPrefix) {
			total += info.Size()
		}
	}

	return total
}

// TestSpecStore_RescansASharedDir pins the periodic scan: two stores sharing one files dir, as two processes do, each
// count only their own writes between scans, so together they pass the cap with neither total past it, and the next
// store write that is a rescan-th one scans the dir and evicts it back within the cap.
func TestSpecStore_RescansASharedDir(t *testing.T) {
	t.Parallel()
	a, _ := newTestStore(t, newRawServer(), nil)
	b := NewSpecStore(SpecStoreConfig{
		Cache:  cache.Config{Dir: filepath.Dir(a.filesDir), TTL: time.Hour, Clock: time.Now},
		Client: &http.Client{Transport: newRawServer()}, RawBase: testRawBase, Summarize: (&summaries{}).summarize,
	})
	if a.rescan != rescanEvery || rescanEvery != 256 {
		t.Fatalf("rescan = %d, rescanEvery = %d; want 256", a.rescan, rescanEvery)
	}
	const size = 100
	for _, s := range []*SpecStore{a, b} {
		s.maxCache, s.rescan = 950, 6
	}
	write := func(s *SpecStore, i int) {
		t.Helper()
		name := fmt.Sprintf("f%02d%s", i, blobSuffix)
		if err := s.writeAtomic(name, bytes.Repeat([]byte("x"), size)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		s.noteWrite(size)
	}
	for i := range 10 {
		write([]*SpecStore{a, b}[i%2], i)
	}
	if got := dirTotal(t, a.filesDir); got != 10*size || a.cacheSize > a.maxCache || b.cacheSize > b.maxCache {
		t.Fatalf("before the rescan: dir %d bytes, totals %d and %d; want 1000 with both under 950", got,
			a.cacheSize, b.cacheSize)
	}
	write(a, 10)
	if got := dirTotal(t, a.filesDir); got > a.maxCache || got != a.cacheSize {
		t.Errorf("after the rescan: dir %d bytes, total %d; want them equal and at most 950", got, a.cacheSize)
	}
}

// TestSpecStore_EvictCountsAFailedRemoval pins that a file evict cannot remove still counts: evict goes on to the
// next file, and the total it returns is what the dir holds.
func TestSpecStore_EvictCountsAFailedRemoval(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t, newRawServer(), nil)
	if err := os.MkdirAll(s.filesDir, cache.DirPerm); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	var paths []string
	for i := range 3 {
		p := filepath.Join(s.filesDir, fmt.Sprintf("f%d%s", i, blobSuffix))
		at := old.Add(time.Duration(i) * time.Minute)
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 100), cache.FilePerm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	s.remove = func(name string) error {
		if name == paths[0] {
			return errors.New("busy")
		}

		return os.Remove(name)
	}
	s.maxCache = 150
	if got, held := s.evict(), dirTotal(t, s.filesDir); got != held || held > s.maxCache {
		t.Errorf("evict counts %d bytes left, the dir holds %d; want them equal and at most 150", got, held)
	}
	if _, err := os.Stat(paths[0]); err != nil {
		t.Errorf("the file that failed to go: %v", err)
	}
}
