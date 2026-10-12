package azure

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
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
		pack func(t *testing.T) []byte
		lim  func(packLimits) packLimits
	}{
		"empty": {func(*testing.T) []byte { return nil }, nil},
		"too many": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.objects = 2; return l },
		},
		"header cut":     {func(*testing.T) []byte { return good[:trees+1] }, nil},
		"delta data cut": {func(*testing.T) []byte { return good[:delta+6] }, nil},
		"object too big": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.object = 64; return l },
		},
		"total too big": {
			func(*testing.T) []byte { return good },
			func(l packLimits) packLimits { l.total = 4096; return l },
		},
		"blob": {withBlob, nil},
		"ref delta": {
			func(t *testing.T) []byte { t.Helper(); rr, _ := deltaRepo(t); return rr.pack(10, true) },
			nil,
		},
		"no commit":      {noCommit, nil},
		"two commits":    {twoCommits, nil},
		"no checksum":    {func(*testing.T) []byte { return good[:len(good)-20] }, nil},
		"wrong checksum": {func(*testing.T) []byte { b := slices.Clone(good); b[len(b)-1] ^= 1; return b }, nil},
		"trailing bytes": {func(*testing.T) []byte { return append(slices.Clone(good), 'x') }, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lim := testPackLimits()
			if tc.lim != nil {
				lim = tc.lim(lim)
			}
			if err := preflightWith(t.Context(), tc.pack(t), lim); !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("err = %v, want ErrSpecsRejected", err)
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
		build func(t *testing.T) ([]byte, string)
		lim   func(walkLimits) walkLimits
		ctx   func(t *testing.T) context.Context
	}{
		"not a pack": {
			func(*testing.T) ([]byte, string) { return []byte("PACKjunk"), strings.Repeat("a", 40) },
			nil,
			nil,
		},
		"commit not in pack": {func(t *testing.T) ([]byte, string) {
			t.Helper()
			_, pack := smallRepo(t)

			return pack, strings.Repeat("b", 40)
		}, nil, nil},
		"missing subtree": {func(t *testing.T) ([]byte, string) {
			t.Helper()

			return dangling(t, func(*testRepo) plumbing.Hash { return fakeBlob("absent") })
		}, nil, nil},
		"subtree is a commit": {func(t *testing.T) ([]byte, string) {
			t.Helper()

			return dangling(t, func(r *testRepo) plumbing.Hash { return r.commit(r.files("x.json")) })
		}, nil, nil},
		"too many entries": {small, func(l walkLimits) walkLimits { l.entries = 3; return l }, nil},
		"too deep": {
			func(t *testing.T) ([]byte, string) { t.Helper(); return deep(t, 5, "d") },
			func(l walkLimits) walkLimits { l.depth = 4; return l }, nil,
		},
		"path too long": {
			func(t *testing.T) ([]byte, string) { t.Helper(); return deep(t, 3, strings.Repeat("p", 20)) },
			func(l walkLimits) walkLimits { l.path = 50; return l }, nil,
		},
		"cancelled": {small, nil, func(t *testing.T) context.Context {
			t.Helper()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			return ctx
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pack, sha := tc.build(t)
			lim := walkLimits{entries: maxTreeEntries, depth: maxTreeDepth, path: maxPathBytes}
			if tc.lim != nil {
				lim = tc.lim(lim)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}
			_, err := walkWith(ctx, pack, sha, lim)
			if !errors.Is(err, ErrSpecsRejected) && !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want ErrSpecsRejected or context.Canceled", err)
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
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
	cases := map[string]func(t *testing.T) *gitServer{
		"fetch": func(t *testing.T) *gitServer {
			t.Helper()
			s := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
			s.advErr = errTransport

			return s
		},
		"preflight": func(t *testing.T) *gitServer {
			t.Helper()
			c, p := refDeltas(t)

			return newGitServer(advertisement(t, c, fullCaps()...), uploadResponse(t, c, p))
		},
		"walk": func(t *testing.T) *gitServer {
			t.Helper()
			other := plumbing.NewHash(strings.Repeat("c", 40))

			return newGitServer(advertisement(t, other, fullCaps()...), uploadResponse(t, other, pack))
		},
	}
	for name, srv := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := FetchListing(t.Context(), clientFor(srv(t)), testRepoURL); err == nil {
				t.Fatal("FetchListing succeeded")
			}
		})
	}
}

// TestFetchListing_RefusesNonHTTPSAndUserinfo pins that FetchListing refuses non-https URLs and URLs with userinfo
// before calling fetchPack, so no request is sent.
func TestFetchListing_RefusesNonHTTPSAndUserinfo(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
	cases := map[string]string{
		"http":      "http://git.example/repo",
		"userinfo":  "https://user:pass@git.example/repo",
		"malformed": "://invalid",
	}
	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := FetchListing(t.Context(), clientFor(srv), url)
			if !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("err = %v, want ErrSpecsRejected", err)
			}
			if srv.uploadBody() != "" {
				t.Fatal("fetchPack was called despite URL refusal")
			}
		})
	}
}
