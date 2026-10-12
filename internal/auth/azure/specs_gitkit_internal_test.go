package azure

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/storage/memory"
)

// testRepoURL is the remote the tests fetch from; the fake RoundTripper never dials it.
const testRepoURL = "https://git.example/Azure/azure-rest-api-specs"

// testRepo builds trees and commits in a go-git memory storage.
type testRepo struct {
	t  *testing.T
	st *memory.Storage
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()

	return &testRepo{t: t, st: memory.NewStorage()}
}

// fakeBlob is the blob id of a file whose content is its own path, so a raw fetch serving the path verifies.
func fakeBlob(path string) plumbing.Hash {
	return plumbing.ComputeHash(plumbing.BlobObject, []byte(path))
}

func (r *testRepo) put(
	o interface {
		Encode(plumbing.EncodedObject) error
	},
) plumbing.Hash {
	r.t.Helper()
	obj := r.st.NewEncodedObject()
	if err := o.Encode(obj); err != nil {
		r.t.Fatalf("encode: %v", err)
	}
	h, err := r.st.SetEncodedObject(obj)
	if err != nil {
		r.t.Fatalf("store: %v", err)
	}

	return h
}

// tree stores a tree of entries, sorted by name as git orders them.
func (r *testRepo) tree(entries ...object.TreeEntry) plumbing.Hash {
	r.t.Helper()
	slices.SortFunc(entries, func(a, b object.TreeEntry) int { return strings.Compare(a.Name, b.Name) })

	return r.put(&object.Tree{Entries: entries})
}

// files stores the trees holding paths as regular files, each with the blob id fakeBlob(path), and returns the root.
func (r *testRepo) files(paths ...string) plumbing.Hash {
	r.t.Helper()
	type dir struct {
		files map[string]plumbing.Hash
		dirs  map[string]*dir
	}
	newDir := func() *dir { return &dir{files: map[string]plumbing.Hash{}, dirs: map[string]*dir{}} }
	root := newDir()
	for _, p := range paths {
		segs := strings.Split(p, "/")
		d := root
		for _, s := range segs[:len(segs)-1] {
			if d.dirs[s] == nil {
				d.dirs[s] = newDir()
			}
			d = d.dirs[s]
		}
		d.files[segs[len(segs)-1]] = fakeBlob(p)
	}
	var write func(d *dir) plumbing.Hash
	write = func(d *dir) plumbing.Hash {
		var es []object.TreeEntry
		for name, h := range d.files {
			es = append(es, object.TreeEntry{Name: name, Mode: filemode.Regular, Hash: h})
		}
		for name, sub := range d.dirs {
			es = append(es, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: write(sub)})
		}

		return r.tree(es...)
	}

	return write(root)
}

func (r *testRepo) commit(tree plumbing.Hash) plumbing.Hash {
	r.t.Helper()
	sig := object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(0, 0).UTC()}

	return r.put(&object.Commit{Author: sig, Committer: sig, Message: "m\n", TreeHash: tree})
}

// pack encodes every stored object. A window above zero lets the encoder build deltas; refDeltas picks REF_DELTA
// over OFS_DELTA for them.
func (r *testRepo) pack(window uint, refDeltas bool) []byte {
	r.t.Helper()
	iter, err := r.st.IterEncodedObjects(plumbing.AnyObject)
	if err != nil {
		r.t.Fatalf("iterate: %v", err)
	}
	var hashes []plumbing.Hash
	if iterErr := iter.ForEach(func(o plumbing.EncodedObject) error {
		hashes = append(hashes, o.Hash())

		return nil
	}); iterErr != nil {
		r.t.Fatalf("collect: %v", iterErr)
	}
	var buf bytes.Buffer
	if _, encErr := packfile.NewEncoder(&buf, r.st, refDeltas).Encode(hashes, window); encErr != nil {
		r.t.Fatalf("encode pack: %v", encErr)
	}

	return buf.Bytes()
}

// fullCaps are the capabilities GitHub advertises that the fetch needs.
func fullCaps() []capability.Capability {
	return []capability.Capability{capability.Sideband64k, capability.Shallow, capability.Filter, capability.OFSDelta}
}

// advertisement is a smart-HTTP info/refs body naming main and the given capabilities.
func advertisement(t *testing.T, main plumbing.Hash, caps ...capability.Capability) []byte {
	t.Helper()
	ar := packp.NewAdvRefs()
	ar.Prefix = [][]byte{[]byte("# service=git-upload-pack"), pktline.Flush}
	for _, c := range caps {
		if err := ar.Capabilities.Set(c); err != nil {
			t.Fatalf("set %s: %v", c, err)
		}
	}
	ar.References[specsMainRef] = main
	var buf bytes.Buffer
	if err := ar.Encode(&buf); err != nil {
		t.Fatalf("encode refs: %v", err)
	}

	return buf.Bytes()
}

// uploadResponse is a git-upload-pack body for a depth-1 fetch: the shallow line, NAK, a progress frame and the
// pack on side-band 1, then a flush.
func uploadResponse(t *testing.T, commit plumbing.Hash, pack []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	su := packp.ShallowUpdate{Shallows: []plumbing.Hash{commit}}
	if err := su.Encode(&buf); err != nil {
		t.Fatalf("shallow: %v", err)
	}
	if err := pktline.NewEncoder(&buf).EncodeString("NAK\n"); err != nil {
		t.Fatalf("nak: %v", err)
	}
	m := sideband.NewMuxer(sideband.Sideband64k, &buf)
	if _, err := m.WriteChannel(sideband.ProgressMessage, []byte("Counting objects: 1\n")); err != nil {
		t.Fatalf("progress: %v", err)
	}
	if _, err := m.Write(pack); err != nil {
		t.Fatalf("pack: %v", err)
	}
	if err := pktline.NewEncoder(&buf).Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	return buf.Bytes()
}

// gitServer is a fake smart-HTTP git server behind an [http.RoundTripper]. It records the upload-pack request body.
type gitServer struct {
	adv, resp             []byte
	advStatus, respStatus int
	advErr, upErr         error
	location              string // when set, info/refs answers 302 to it
	onUpload              func() // when set, runs as the upload-pack request arrives

	mu       sync.Mutex
	gotBody  []byte
	reqCount int
}

func newGitServer(adv, resp []byte) *gitServer {
	return &gitServer{adv: adv, resp: resp, advStatus: http.StatusOK, respStatus: http.StatusOK}
}

func (g *gitServer) RoundTrip(r *http.Request) (*http.Response, error) {
	g.mu.Lock()
	g.reqCount++
	g.mu.Unlock()
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/info/refs"):
		if g.advErr != nil {
			return nil, g.advErr
		}
		if g.location != "" {
			resp := fakeResponse(r, http.StatusFound, nil)
			resp.Header.Set("Location", g.location)

			return resp, nil
		}

		return fakeResponse(r, g.advStatus, g.adv), nil
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
		body, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.gotBody = body
		g.mu.Unlock()
		if g.onUpload != nil {
			g.onUpload()
		}
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		if g.upErr != nil {
			return nil, g.upErr
		}

		return fakeResponse(r, g.respStatus, g.resp), nil
	default:
		return fakeResponse(r, http.StatusNotFound, nil), nil
	}
}

func (g *gitServer) uploadBody() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	return string(g.gotBody)
}

func (g *gitServer) requests() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.reqCount
}

func fakeResponse(r *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    r,
	}
}

// smallRepo is a repository with two files and its pack, ready to serve.
func smallRepo(t *testing.T) (plumbing.Hash, []byte) {
	t.Helper()
	r := newTestRepo(t)
	c := r.commit(r.files(
		"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/compute.json",
		"README.md",
	))

	return c, r.pack(0, false)
}
