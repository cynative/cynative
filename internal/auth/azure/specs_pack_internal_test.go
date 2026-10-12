package azure

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// testPackLimits are the production bounds; each test lowers one.
func testPackLimits() packLimits {
	return packLimits{objects: maxPackObjects, object: maxObjectBytes, total: maxPackInflated}
}

// deltaRepo builds trees similar enough that the encoder stores some of them as deltas.
func deltaRepo(t *testing.T) (*testRepo, plumbing.Hash) {
	t.Helper()
	r := newTestRepo(t)
	var dirs []object.TreeEntry
	for d := range 8 {
		var es []object.TreeEntry
		for i := range 200 {
			name := fmt.Sprintf("file-%03d.json", i)
			if i == d {
				name = fmt.Sprintf("changed-%d.json", d)
			}
			es = append(es, object.TreeEntry{Name: name, Mode: filemode.Regular, Hash: fakeBlob(name)})
		}
		dirs = append(dirs, object.TreeEntry{Name: fmt.Sprintf("d%d", d), Mode: filemode.Dir, Hash: r.tree(es...)})
	}

	return r, r.commit(r.tree(dirs...))
}

// objectTypes lists the object types a pack's headers declare, in order.
func objectTypes(t *testing.T, pack []byte) []plumbing.ObjectType {
	t.Helper()
	sc := packfile.NewScanner(bytes.NewReader(pack))
	_, n, err := sc.Header()
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	var types []plumbing.ObjectType
	for range n {
		h, herr := sc.NextObjectHeader()
		if herr != nil {
			t.Fatalf("object header: %v", herr)
		}
		types = append(types, h.Type)
	}

	return types
}

// firstOffset returns the pack offset of the first object of type typ.
func firstOffset(t *testing.T, pack []byte, typ plumbing.ObjectType) int64 {
	t.Helper()
	sc := packfile.NewScanner(bytes.NewReader(pack))
	_, n, _ := sc.Header()
	for range n {
		h, err := sc.NextObjectHeader()
		if err != nil {
			t.Fatalf("object header: %v", err)
		}
		if h.Type == typ {
			return h.Offset
		}
	}
	t.Fatalf("no %s object in the pack", typ)

	return 0
}

// TestPreflightPack_AdmitsARealShallowPack pins that a pack of one commit, trees and OFS deltas passes.
func TestPreflightPack_AdmitsARealShallowPack(t *testing.T) {
	t.Parallel()
	r, _ := deltaRepo(t)
	pack := r.pack(10, false)
	if !slices.Contains(objectTypes(t, pack), plumbing.OFSDeltaObject) {
		t.Fatal("the fixture pack has no OFS delta; make deltaRepo's trees more alike")
	}
	if err := preflightPack(t.Context(), pack); err != nil {
		t.Fatalf("preflightPack: %v", err)
	}
}

// TestPreflightPack_Refusals pins every refusal.
func TestPreflightPack_Refusals(t *testing.T) {
	t.Parallel()
	r, _ := deltaRepo(t)
	good := r.pack(10, false)
	withBlob := func(t *testing.T) []byte {
		t.Helper()
		b := newTestRepo(t)
		obj := b.st.NewEncodedObject()
		obj.SetType(plumbing.BlobObject)
		if _, err := obj.Writer(); err != nil {
			t.Fatalf("blob: %v", err)
		}
		if _, err := b.st.SetEncodedObject(obj); err != nil {
			t.Fatalf("blob: %v", err)
		}
		b.commit(b.files("a.json"))

		return b.pack(0, false)
	}
	noCommit := func(t *testing.T) []byte {
		t.Helper()
		b := newTestRepo(t)
		b.files("a.json")

		return b.pack(0, false)
	}
	twoCommits := func(t *testing.T) []byte {
		t.Helper()
		b := newTestRepo(t)
		b.commit(b.files("a.json"))
		b.commit(b.files("b.json"))

		return b.pack(0, false)
	}
	trees := firstOffset(t, good, plumbing.TreeObject)
	delta := firstOffset(t, good, plumbing.OFSDeltaObject)
	cases := map[string]struct {
		pack   func(t *testing.T) []byte
		lim    func(packLimits) packLimits
		substr string
	}{
		"empty": {func(*testing.T) []byte { return nil }, nil, "pack header"},
		"too many": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.objects = 2; return l },
			"holds",
		},
		"header cut":     {func(*testing.T) []byte { return good[:trees+1] }, nil, "object header"},
		"delta data cut": {func(*testing.T) []byte { return good[:delta+6] }, nil, "pack delta"},
		"object too big": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.object = 64; return l },
			"pack object of",
		},
		"total too big": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.total = 4096; return l },
			"inflate past",
		},
		"blob": {withBlob, nil, "not admitted"},
		"ref delta": {
			func(t *testing.T) []byte { t.Helper(); rr, _ := deltaRepo(t); return rr.pack(10, true) },
			nil,
			"not admitted",
		},
		"no commit":   {noCommit, nil, "holds 0 commits"},
		"two commits": {twoCommits, nil, "holds 2 commits"},
		"no checksum": {func(*testing.T) []byte { return good[:len(good)-20] }, nil, "checksum"},
		"wrong checksum": {
			func(*testing.T) []byte { b := slices.Clone(good); b[len(b)-1] ^= 1; return b },
			nil,
			"checksum",
		},
		"trailing bytes": {
			func(*testing.T) []byte { return append(slices.Clone(good), 'x') },
			nil,
			"follow the pack checksum",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lim := testPackLimits()
			if tc.lim != nil {
				lim = tc.lim(lim)
			}
			err := preflightWith(t.Context(), tc.pack(t), lim)
			if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("err = %v, want ErrSpecsRejected with %q", err, tc.substr)
			}
		})
	}
}

// TestDeltaVarint_StaysNonNegative pins the varint bound: a nine-byte varint decodes to a positive value, and one
// that would need a tenth byte is refused instead of wrapping into a negative size.
func TestDeltaVarint_StaysNonNegative(t *testing.T) {
	t.Parallel()
	v, rest, ok := deltaVarint(append(bytes.Repeat([]byte{0xff}, 8), 0x7f, 'x'))
	if !ok || v <= 0 || string(rest) != "x" {
		t.Fatalf("nine-byte varint = %d, %q, %v; want a positive value", v, rest, ok)
	}
	if _, _, ok2 := deltaVarint(append(bytes.Repeat([]byte{0xff}, 9), 0x01)); ok2 {
		t.Fatal("a ten-byte varint was decoded")
	}
}

// rawObject encodes one pack object by hand: git's type-and-size header, an OFS delta's base offset when neg is
// positive, then the zlib-compressed data. It lets a test build packs the go-git encoder never writes.
func rawObject(t *testing.T, typ plumbing.ObjectType, neg int64, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	size := len(data)
	c := byte(typ)<<4 | byte(size&0x0f)
	for size >>= 4; size > 0; size >>= 7 {
		b.WriteByte(c | 0x80)
		c = byte(size & 0x7f)
	}
	b.WriteByte(c)
	if neg > 0 {
		b.Write(ofsBytes(neg))
	}
	zw := zlib.NewWriter(&b)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib: %v", err)
	}

	return b.Bytes()
}

// ofsBytes is git's OFS_DELTA base offset encoding (utils/binary ReadVariableWidthInt reads it back): big-endian
// 7-bit groups, each continuation adding one.
func ofsBytes(n int64) []byte {
	out := []byte{byte(n & 0x7f)}
	for n >>= 7; n > 0; n >>= 7 {
		n--
		out = append([]byte{byte(0x80 | n&0x7f)}, out...)
	}

	return out
}

// rawPack frames encoded objects as a version 2 pack with its SHA-1 trailer.
func rawPack(objs ...[]byte) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, uint32(2))         // A bytes.Buffer write cannot fail.
	_ = binary.Write(&b, binary.BigEndian, uint32(len(objs))) // A bytes.Buffer write cannot fail.
	for _, o := range objs {
		b.Write(o)
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	return b.Bytes()
}

// TestPreflightPack_DeltaAccounting pins the two delta rules the go-git encoder never exercises: a delta whose base
// offset points inside another object is refused, and the total counts each delta's own stream as well as its
// target, so a limit that fits the targets alone but not the streams is refused for its total.
func TestPreflightPack_DeltaAccounting(t *testing.T) {
	t.Parallel()
	tree := rawObject(t, plumbing.TreeObject, 0, []byte("0123456789"))
	// The delta: source size 10, target size 4, then one insert instruction of 4 literal bytes.
	deltaData := []byte{10, 4, 4, 'a', 'b', 'c', 'd'}
	const treeOffset = 12 // after the 12-byte pack header
	deltaOffset := int64(treeOffset + len(tree))
	t.Run("base inside an object", func(t *testing.T) {
		t.Parallel()
		inside := rawObject(t, plumbing.OFSDeltaObject, deltaOffset-(treeOffset+1), deltaData)
		err := preflightWith(t.Context(), rawPack(tree, inside), testPackLimits())
		if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), "names no admitted object") {
			t.Fatalf("err = %v, want the base refusal", err)
		}
	})
	t.Run("streams count toward the total", func(t *testing.T) {
		t.Parallel()
		delta := rawObject(t, plumbing.OFSDeltaObject, deltaOffset-treeOffset, deltaData)
		lim := testPackLimits()
		lim.total = int64(len("0123456789") + 4) // the tree plus the target, without the delta stream
		err := preflightWith(t.Context(), rawPack(tree, delta), lim)
		if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), "inflate past") {
			t.Fatalf("err = %v, want the total refusal", err)
		}
		lim.total += int64(len(deltaData))
		err = preflightWith(t.Context(), rawPack(tree, delta), lim)
		if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), "commits") {
			t.Fatalf("err = %v, want the walk to reach the commit count once the streams fit", err)
		}
	})
}

// TestPreflightPack_HonoursTheContext pins that a done context stops the preflight with its own error.
func TestPreflightPack_HonoursTheContext(t *testing.T) {
	t.Parallel()
	r, _ := deltaRepo(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := preflightPack(ctx, r.pack(10, false)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestCtxObserver pins each observer hook: the two per-object hooks report the context's error, the header and
// footer hooks never fail.
func TestCtxObserver(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	o := ctxObserver{ctx: ctx}
	if o.OnHeader(1) != nil || o.OnFooter(plumbing.ZeroHash) != nil {
		t.Fatal("the header or footer hook failed")
	}
	if !errors.Is(o.OnInflatedObjectHeader(plumbing.TreeObject, 1, 0), context.Canceled) ||
		!errors.Is(o.OnInflatedObjectContent(plumbing.ZeroHash, 0, 0, nil), context.Canceled) {
		t.Fatal("a per-object hook ignored the done context")
	}
}

// TestWalkTrees_HonoursTheContext pins the walk's own context check, after a parse that finished: the storage is
// filled first, then the walk runs under a done context.
func TestWalkTrees_HonoursTheContext(t *testing.T) {
	t.Parallel()
	r := newTestRepo(t)
	root := r.files("a/b.json")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	lim := walkLimits{entries: maxTreeEntries, depth: maxTreeDepth, path: maxPathBytes}
	if _, err := walkTrees(ctx, r.st, root, plumbing.ZeroHash.String(), lim); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestAdmitDeltaTarget pins the delta header read: the source size, then the target size, both LEB128 varints.
func TestAdmitDeltaTarget(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		head []byte
		want int64
		ok   bool
	}{
		"small":           {[]byte{0x05, 0x07}, 7, true},
		"two-byte target": {[]byte{0x05, 0x80, 0x01}, 128, true},
		"over the limit":  {[]byte{0x05, 0x81, 0x80, 0x40}, 0, false},
		"no source":       {nil, 0, false},
		"source unended":  {[]byte{0x80}, 0, false},
		"target unended":  {[]byte{0x05, 0x80}, 0, false},
		"varint too long": {bytes.Repeat([]byte{0x80}, 11), 0, false},
		// Nine bytes reach shift 56, the last allowed; a tenth would shift into the sign bit.
		"nine-byte target": {append([]byte{0x05}, append(bytes.Repeat([]byte{0x80}, 8), 0x7f)...), 0, false},
		"would overflow":   {append([]byte{0x05}, append(bytes.Repeat([]byte{0x80}, 9), 0x01)...), 0, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := admitDeltaTarget(tc.head, 1<<20)
			if tc.ok != (err == nil) || got != tc.want {
				t.Fatalf("admitDeltaTarget = %d, %v; want %d, ok=%v", got, err, tc.want, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("err = %v, want ErrSpecsRejected", err)
			}
		})
	}
}

// TestWalkPack_ListsRegularFilesWithTheirBlobIDs pins the listing: regular and executable files with their blob
// ids, everything else counted as skipped, and the SHA carried through.
func TestWalkPack_ListsRegularFilesWithTheirBlobIDs(t *testing.T) {
	t.Parallel()
	r := newTestRepo(t)
	sub := r.tree(object.TreeEntry{Name: "b.json", Mode: filemode.Executable, Hash: fakeBlob("dir/b.json")})
	root := r.tree(
		object.TreeEntry{Name: "a.json", Mode: filemode.Regular, Hash: fakeBlob("a.json")},
		object.TreeEntry{Name: "dir", Mode: filemode.Dir, Hash: sub},
		object.TreeEntry{Name: "link", Mode: filemode.Symlink, Hash: fakeBlob("link")},
		object.TreeEntry{Name: "mod", Mode: filemode.Submodule, Hash: fakeBlob("mod")},
	)
	c := r.commit(root)
	l, err := walkPack(t.Context(), r.pack(0, false), c.String())
	if err != nil {
		t.Fatalf("walkPack: %v", err)
	}
	got := map[string]string{}
	for _, e := range l.Entries {
		got[e.Path] = e.Blob
	}
	want := map[string]string{"a.json": fakeBlob("a.json").String(), "dir/b.json": fakeBlob("dir/b.json").String()}
	if l.SHA != c.String() || l.Skipped != 2 || len(got) != len(want) ||
		got["a.json"] != want["a.json"] || got["dir/b.json"] != want["dir/b.json"] {
		t.Fatalf("listing = %+v", l)
	}
}

// TestWalkPack_Refusals pins every walk failure.
//
//nolint:gocognit // The 8 refusal cases share one runner.
func TestWalkPack_Refusals(t *testing.T) {
	t.Parallel()
	deep := func(t *testing.T, depth int, name string) ([]byte, string) {
		t.Helper()
		r := newTestRepo(t)
		h := r.tree(object.TreeEntry{Name: "f.json", Mode: filemode.Regular, Hash: fakeBlob("f")})
		for range depth {
			h = r.tree(object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: h})
		}
		c := r.commit(h)

		return r.pack(0, false), c.String()
	}
	dangling := func(t *testing.T, target func(r *testRepo) plumbing.Hash) ([]byte, string) {
		t.Helper()
		r := newTestRepo(t)
		c := r.commit(r.tree(object.TreeEntry{Name: "sub", Mode: filemode.Dir, Hash: target(r)}))

		return r.pack(0, false), c.String()
	}
	small := func(t *testing.T) ([]byte, string) {
		t.Helper()
		c, pack := smallRepo(t)

		return pack, c.String()
	}
	cases := map[string]struct {
		build  func(t *testing.T) ([]byte, string)
		lim    func(walkLimits) walkLimits
		ctx    func(t *testing.T) context.Context
		substr string
	}{
		"not a pack": {
			func(*testing.T) ([]byte, string) { return []byte("PACKjunk"), strings.Repeat("a", 40) },
			nil,
			nil,
			"parse pack",
		},
		"commit not in pack": {func(t *testing.T) ([]byte, string) {
			t.Helper()
			_, pack := smallRepo(t)

			return pack, strings.Repeat("b", 40)
		}, nil, nil, "commit"},
		"missing subtree": {func(t *testing.T) ([]byte, string) {
			t.Helper()

			return dangling(t, func(*testRepo) plumbing.Hash { return fakeBlob("absent") })
		}, nil, nil, "tree"},
		"subtree is a commit": {func(t *testing.T) ([]byte, string) {
			t.Helper()

			return dangling(t, func(r *testRepo) plumbing.Hash { return r.commit(r.files("x.json")) })
		}, nil, nil, "tree"},
		"too many entries": {small, func(l walkLimits) walkLimits { l.entries = 3; return l }, nil, "past"},
		"too deep": {
			func(t *testing.T) ([]byte, string) { t.Helper(); return deep(t, 5, "d") },
			func(l walkLimits) walkLimits { l.depth = 4; return l }, nil, "depth past",
		},
		"path too long": {
			func(t *testing.T) ([]byte, string) { t.Helper(); return deep(t, 3, strings.Repeat("p", 20)) },
			func(l walkLimits) walkLimits { l.path = 50; return l }, nil, "path past",
		},
		"cancelled": {small, nil, func(t *testing.T) context.Context {
			t.Helper()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			return ctx
		}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pack, sha := tc.build(t)
			lim := defaultWalkLimits()
			if tc.lim != nil {
				lim = tc.lim(lim)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}
			_, err := walkWith(ctx, pack, sha, lim)
			if name == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
			} else {
				if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), tc.substr) {
					t.Fatalf("err = %v, want ErrSpecsRejected with %q", err, tc.substr)
				}
			}
		})
	}
}

// TestFetchListing_EndToEnd pins the whole listing over the fake smart-HTTP server.
func TestFetchListing_EndToEnd(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
	l, err := FetchListing(t.Context(), clientFor(srv), testRepoURL)
	if err != nil {
		t.Fatalf("FetchListing: %v", err)
	}
	if l.SHA != commit.String() || len(l.Entries) != 2 {
		t.Fatalf("listing = %+v", l)
	}
}

// TestFetchListing_Failures pins that a fetch, preflight or walk failure each surfaces.
func TestFetchListing_Failures(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	refDeltas := func(t *testing.T) (plumbing.Hash, []byte) {
		t.Helper()
		r, c := deltaRepo(t)

		return c, r.pack(10, true)
	}
	cases := map[string]struct {
		srv    func(t *testing.T) *gitServer
		substr string
	}{
		"fetch": {func(t *testing.T) *gitServer {
			t.Helper()
			s := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
			s.advErr = errTransport

			return s
		}, "transport"},
		"preflight": {func(t *testing.T) *gitServer {
			t.Helper()
			c, p := refDeltas(t)

			return newGitServer(advertisement(t, c, fullCaps()...), uploadResponse(t, c, p))
		}, "not admitted"},
		"walk": {func(t *testing.T) *gitServer {
			t.Helper()
			other := plumbing.NewHash(strings.Repeat("c", 40))

			return newGitServer(advertisement(t, other, fullCaps()...), uploadResponse(t, other, pack))
		}, "commit"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := FetchListing(t.Context(), clientFor(tc.srv(t)), testRepoURL)
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.substr)
			}
		})
	}
}

// TestFetchListing_RefusesNonHTTPSAndUserinfo pins that FetchListing refuses non-https URLs and URLs with userinfo
// before calling fetchPack, so no request is sent.
func TestFetchListing_RefusesNonHTTPSAndUserinfo(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	cases := map[string]string{
		"http":      "http://git.example/repo",
		"userinfo":  "https://user:pass@git.example/repo",
		"malformed": "://invalid",
	}
	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
			_, err := FetchListing(t.Context(), clientFor(srv), url)
			if !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("err = %v, want ErrSpecsRejected", err)
			}
			if srv.requests() != 0 {
				t.Fatalf("sent %d requests despite URL refusal", srv.requests())
			}
		})
	}
}

// TestBounds_EdgePairs pins that every bound accepts exactly at the limit and refuses at limit+1.
//
//nolint:gocognit // The 8 bounds share one test structure.
func TestBounds_EdgePairs(t *testing.T) {
	t.Parallel()
	t.Run("object count", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Build exactly 2 objects: 1 commit + 1 tree (blobs aren't stored in pack, just referenced).
		root := r.tree(object.TreeEntry{Name: "a.json", Mode: filemode.Regular, Hash: fakeBlob("a.json")})
		r.commit(root)
		pack := r.pack(0, false)
		lim := testPackLimits()
		lim.objects = 2
		if err := preflightWith(t.Context(), pack, lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.objects = 1
		if err := preflightWith(t.Context(), pack, lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("per-object size", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Build a tree with many entries so it encodes to about 8 KB.
		var es []object.TreeEntry
		for i := range 200 {
			es = append(
				es,
				object.TreeEntry{Name: fmt.Sprintf("f%03d.json", i), Mode: filemode.Regular, Hash: fakeBlob("x")},
			)
		}
		r.commit(r.tree(es...))
		pack := r.pack(0, false)
		// Find the actual tree size from the pack.
		sc := packfile.NewScanner(bytes.NewReader(pack))
		_, n, _ := sc.Header()
		var treeSize int64
		for range n {
			h, _ := sc.NextObjectHeader()
			if h.Type == plumbing.TreeObject {
				treeSize = h.Length
				break
			}
		}
		if treeSize == 0 {
			t.Fatal("no tree in pack")
		}
		lim := testPackLimits()
		lim.object = treeSize
		if err := preflightWith(t.Context(), pack, lim); err != nil {
			t.Fatalf("at limit (%d): %v", treeSize, err)
		}
		lim.object = treeSize - 1
		if err := preflightWith(t.Context(), pack, lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("delta target", func(t *testing.T) {
		t.Parallel()
		limit := int64(1 << 20)
		// Exactly at limit.
		head := []byte{0x05, 0x80, 0x80, 0x40} // source 5, target 1048576
		if _, err := admitDeltaTarget(head, limit); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		// One byte over.
		head = []byte{0x05, 0x81, 0x80, 0x40} // target 1048577
		if _, err := admitDeltaTarget(head, limit); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("total inflated", func(t *testing.T) {
		t.Parallel()
		// Build a pack with known sizes.
		tree := rawObject(t, plumbing.TreeObject, 0, bytes.Repeat([]byte("x"), 10))
		commit := rawObject(t, plumbing.CommitObject, 0, bytes.Repeat([]byte("y"), 10))
		pack := rawPack(commit, tree)
		const totalSize = 20
		lim := testPackLimits()
		lim.total = totalSize
		if err := preflightWith(t.Context(), pack, lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.total = totalSize - 1
		if err := preflightWith(t.Context(), pack, lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		c := r.commit(r.files("a.json", "b.json"))
		pack := r.pack(0, false)
		const entryCount = 2
		lim := defaultWalkLimits()
		lim.entries = entryCount
		if _, err := walkWith(t.Context(), pack, c.String(), lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.entries = entryCount - 1
		if _, err := walkWith(t.Context(), pack, c.String(), lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		h := r.tree(object.TreeEntry{Name: "f.json", Mode: filemode.Regular, Hash: fakeBlob("f")})
		for range 3 {
			h = r.tree(object.TreeEntry{Name: "d", Mode: filemode.Dir, Hash: h})
		}
		c := r.commit(h)
		pack := r.pack(0, false)
		const maxDepth = 3
		lim := defaultWalkLimits()
		lim.depth = maxDepth
		if _, err := walkWith(t.Context(), pack, c.String(), lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.depth = maxDepth - 1
		if _, err := walkWith(t.Context(), pack, c.String(), lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("path length", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Use a simpler path to avoid hitting listingBytes first.
		c := r.commit(r.files("a.json"))
		pack := r.pack(0, false)
		const pathLen = 6 // "a.json"
		lim := defaultWalkLimits()
		lim.path = pathLen
		if _, err := walkWith(t.Context(), pack, c.String(), lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.path = pathLen - 1
		if _, err := walkWith(t.Context(), pack, c.String(), lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("listing bytes", func(t *testing.T) {
		t.Parallel()
		r := newTestRepo(t)
		// Two entries: each adds len(path) + 40 bytes. "a.json" = 6, "b.json" = 6. Total = (6+40)*2 = 92.
		c := r.commit(r.files("a.json", "b.json"))
		pack := r.pack(0, false)
		const listingBytes = 92
		lim := defaultWalkLimits()
		lim.listingBytes = listingBytes
		if _, err := walkWith(t.Context(), pack, c.String(), lim); err != nil {
			t.Fatalf("at limit: %v", err)
		}
		lim.listingBytes = listingBytes - 1
		if _, err := walkWith(t.Context(), pack, c.String(), lim); !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("over limit: %v, want ErrSpecsRejected", err)
		}
	})
}

// TestWalkPack_SharedTreeExpansion pins that a small pack with one tree referenced from many parents trips the
// listing bytes cap before the entry cap.
func TestWalkPack_SharedTreeExpansion(t *testing.T) {
	t.Parallel()
	r := newTestRepo(t)
	// One small subtree with one file.
	sub := r.tree(object.TreeEntry{Name: "f.json", Mode: filemode.Regular, Hash: fakeBlob("f")})
	// Reference it from many parents to expand the listing without hitting entry cap.
	var parents []object.TreeEntry
	for i := range 100 {
		parents = append(parents, object.TreeEntry{Name: fmt.Sprintf("d%03d", i), Mode: filemode.Dir, Hash: sub})
	}
	c := r.commit(r.tree(parents...))
	pack := r.pack(0, false)
	// With 100 parents each with path "dNNN/f.json" (10 bytes), listing bytes = 100 * (10 + 40) = 5000.
	// Set listing cap to 4999 (under the total) and entries cap to 200 (above the total of 101 entries).
	lim := defaultWalkLimits()
	lim.entries, lim.listingBytes = 200, 4999
	_, err := walkWith(t.Context(), pack, c.String(), lim)
	if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), "listing bytes") {
		t.Fatalf("err = %v, want ErrSpecsRejected with listing bytes", err)
	}
}

// TestCtxReader_ChecksContext pins that ctxReader.Read returns the context's error once it is done, proving it stops
// the parse during indexing rather than relying on the observer (which only runs during delta resolution).
func TestCtxReader_ChecksContext(t *testing.T) {
	t.Parallel()
	data := bytes.Repeat([]byte("test"), 100)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := &ctxReader{ctx: ctx, r: bytes.NewReader(data)}
	buf := make([]byte, 10)
	_, err := r.Read(buf)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Read after cancel = %v, want context.Canceled", err)
	}
}

// TestWalkWith_ContextCancelledDuringIndexing pins that walkWith reads the pack through ctxReader. The inner reader
// serves one byte per Read, so the parser has to come back for more, and cancels the context on its second Read.
// Through ctxReader no Read reaches the inner reader after that. Without ctxReader the parser keeps reading until the
// observer's next callback sees the cancelled context, so the inner reader sees Reads after the cancel.
func TestWalkWith_ContextCancelledDuringIndexing(t *testing.T) {
	t.Parallel()
	r, commit := deltaRepo(t)
	ctx, cancel := context.WithCancel(t.Context())
	src := &cancelOnRead{cancel: cancel, cancelAt: 2}
	lim := defaultWalkLimits()
	lim.wrapReader = func(r io.ReadSeeker) io.ReadSeeker { src.r = r; return src }
	if _, err := walkWith(ctx, r.pack(10, false), commit.String(), lim); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if src.reads != src.cancelAt {
		t.Fatalf("inner reader saw %d Reads, want %d: Reads reached it after the cancel", src.reads, src.cancelAt)
	}
}

// cancelOnRead serves one byte per Read and cancels its context on Read number cancelAt.
type cancelOnRead struct {
	r        io.ReadSeeker
	cancel   context.CancelFunc
	cancelAt int
	reads    int
}

func (c *cancelOnRead) Read(p []byte) (int, error) {
	c.reads++
	if c.reads == c.cancelAt {
		c.cancel()
	}

	return c.r.Read(p[:min(1, len(p))])
}

func (c *cancelOnRead) Seek(offset int64, whence int) (int64, error) { return c.r.Seek(offset, whence) }
