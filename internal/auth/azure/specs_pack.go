package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/memory"
)

const (
	// listingTimeout bounds one listing refresh: the request, the preflight, the parse and the walk.
	listingTimeout = 60 * time.Second
	// maxPackObjects bounds the objects in the pack (20,335 on 2026-10-12).
	maxPackObjects = 200_000
	// maxObjectBytes bounds any one object or delta target (largest tree 62,170 bytes on 2026-10-12).
	maxObjectBytes = 1 << 20
	// maxPackInflated bounds the declared sizes plus delta targets of all objects (22,967,083 bytes inflated).
	maxPackInflated = 128 << 20
	// maxTreeEntries bounds the tree entries walked, skipped ones included (363,140 paths on 2026-10-12).
	maxTreeEntries = 1_000_000
	// maxTreeDepth bounds the directory depth below the root tree.
	maxTreeDepth = 32
	// maxPathBytes bounds a listed path.
	maxPathBytes = 1024
	// maxListingBytes bounds the sum of path bytes plus 40 for every entry (recorded or skipped): a small pack can
	// expand to about 1 GB via shared trees without it (the real listing is 61.5 MiB over 363,140 entries at main).
	maxListingBytes = 256 << 20
	// deltaHeadBytes holds the two size varints at the start of a delta, at most nine bytes each.
	deltaHeadBytes = 18
	// varintPayload, varintMore and varintStep decode git's delta size varints: 7 bits a byte, low bits first.
	varintPayload = 0x7f
	varintMore    = 0x80
	varintStep    = 7
	// maxVarintShift is the shift of the last byte a size varint may have: its 7 payload bits end at bit 62, so the
	// value never reaches the sign bit of an int64.
	maxVarintShift = 56
)

// ListingEntry is one regular file of the specs tree.
type ListingEntry struct {
	// Path is repository-relative and '/'-separated.
	Path string
	// Blob is the file's git blob id, 40 lower-case hex digits.
	Blob string
}

// Listing is the specs tree at one commit.
type Listing struct {
	SHA     string
	Entries []ListingEntry
	// Skipped counts entries of any mode other than a directory or a regular or executable file.
	Skipped int
}

// packLimits bounds the pack preflight.
type packLimits struct {
	objects       uint32
	object, total int64
}

// walkLimits bounds the tree walk.
type walkLimits struct {
	entries, depth, path, listingBytes int
	// wrapReader wraps the pack reader before ctxReader wraps it. Production passes the reader through unchanged, and
	// tests replace it to count reads or cancel the context during the parse.
	wrapReader func(io.ReadSeeker) io.ReadSeeker
}

// defaultWalkLimits returns the production bounds with a pass-through wrapReader.
func defaultWalkLimits() walkLimits {
	return walkLimits{
		entries: maxTreeEntries, depth: maxTreeDepth, path: maxPathBytes, listingBytes: maxListingBytes,
		wrapReader: passThroughReader,
	}
}

// passThroughReader returns r unchanged.
func passThroughReader(r io.ReadSeeker) io.ReadSeeker { return r }

// FetchListing lists the specs tree at the commit repoURL's main points at, with one deadline over the fetch, the
// preflight and the walk.
func FetchListing(ctx context.Context, client *http.Client, repoURL string) (*Listing, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse url: %w", ErrSpecsRejected, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: url scheme is %s, want https", ErrSpecsRejected, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: url carries userinfo", ErrSpecsRejected)
	}
	ctx, cancel := context.WithTimeout(ctx, listingTimeout)
	defer cancel()
	sha, pack, err := fetchPack(ctx, client, repoURL)
	if err != nil {
		return nil, err
	}
	if perr := preflightPack(ctx, pack); perr != nil {
		return nil, perr
	}

	return walkPack(ctx, pack, sha)
}

// preflightPack checks a pack against the production bounds before anything is stored.
func preflightPack(ctx context.Context, pack []byte) error {
	return preflightWith(ctx, pack, packLimits{objects: maxPackObjects, object: maxObjectBytes, total: maxPackInflated})
}

// preflightWith reads every object header before any object is stored: it admits one commit, trees and OFS deltas
// only, bounds each declared size and each delta's target size, bounds their total, and requires the checksum
// trailer to be present, correct and the last bytes of the pack.
func preflightWith(ctx context.Context, pack []byte, lim packLimits) error {
	sc := packfile.NewScanner(bytes.NewReader(pack))
	_, count, err := sc.Header()
	if err != nil {
		return fmt.Errorf("%w: pack header: %w", ErrSpecsRejected, err)
	}
	if count > lim.objects {
		return fmt.Errorf("%w: pack holds %d objects, over %d", ErrSpecsRejected, count, lim.objects)
	}
	types := make(map[int64]plumbing.ObjectType, count)
	var total int64
	commits := 0
	for range count {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		h, herr := sc.NextObjectHeader()
		if herr != nil {
			return fmt.Errorf("%w: pack object header: %w", ErrSpecsRejected, herr)
		}
		size, typ, aerr := admitObject(sc, h, types, lim)
		if aerr != nil {
			return aerr
		}
		types[h.Offset] = typ
		if typ == plumbing.CommitObject {
			commits++
		}
		total += size
		if total > lim.total {
			return fmt.Errorf("%w: pack objects inflate past %d bytes", ErrSpecsRejected, lim.total)
		}
	}
	if commits != 1 {
		return fmt.Errorf("%w: pack holds %d commits, want 1", ErrSpecsRejected, commits)
	}
	if _, checkerr := sc.Checksum(); checkerr != nil {
		return fmt.Errorf("%w: pack checksum: %w", ErrSpecsRejected, checkerr)
	}
	// Seeking a bytes.Reader cannot fail; the position it moved from is where the trailer ended.
	end, _ := sc.SeekFromStart(int64(len(pack)))
	if end != int64(len(pack)) {
		return fmt.Errorf("%w: %d bytes follow the pack checksum", ErrSpecsRejected, int64(len(pack))-end)
	}

	return nil
}

// admitObject bounds one object and returns the bytes it inflates to and its type. A delta's type is its base's,
// read from the types of the objects already admitted, and it counts its own stream plus its target; a base offset
// that names no admitted object is refused.
func admitObject(
	sc *packfile.Scanner, h *packfile.ObjectHeader, types map[int64]plumbing.ObjectType, lim packLimits,
) (int64, plumbing.ObjectType, error) {
	if h.Length > lim.object {
		return 0, h.Type, fmt.Errorf("%w: pack object of %d bytes, over %d", ErrSpecsRejected, h.Length, lim.object)
	}
	switch h.Type { //nolint:exhaustive // The default refuses blobs, tags and REF deltas.
	case plumbing.CommitObject, plumbing.TreeObject:
		return h.Length, h.Type, nil
	case plumbing.OFSDeltaObject:
		base, ok := types[h.OffsetReference]
		if !ok {
			return 0, h.Type, fmt.Errorf("%w: pack delta base at offset %d names no admitted object",
				ErrSpecsRejected, h.OffsetReference)
		}
		head := &headWriter{}
		if _, _, err := sc.NextObject(head); err != nil {
			return 0, h.Type, fmt.Errorf("%w: pack delta: %w", ErrSpecsRejected, err)
		}
		target, err := admitDeltaTarget(head.buf, lim.object)

		// The delta stream is inflated too (by the parser, before it builds the target), so both count.
		return h.Length + target, base, err
	default:
		return 0, h.Type, fmt.Errorf("%w: pack object type %s is not admitted", ErrSpecsRejected, h.Type)
	}
}

// admitDeltaTarget reads the target size from the start of an inflated delta (the source size, then the target
// size) and refuses one over limit or a header that does not parse.
func admitDeltaTarget(head []byte, limit int64) (int64, error) {
	_, rest, ok := deltaVarint(head)
	target, _, ok2 := deltaVarint(rest)
	if !ok || !ok2 || target > limit {
		return 0, fmt.Errorf("%w: pack delta target unreadable or over %d bytes", ErrSpecsRejected, limit)
	}

	return target, nil
}

// deltaVarint decodes one size varint and returns the bytes after it.
func deltaVarint(b []byte) (int64, []byte, bool) {
	var v int64
	shift := 0
	for i, c := range b {
		if shift > maxVarintShift {
			return 0, nil, false
		}
		v |= int64(c&varintPayload) << shift
		if c&varintMore == 0 {
			return v, b[i+1:], true
		}
		shift += varintStep
	}

	return 0, nil, false
}

// headWriter keeps the first deltaHeadBytes written to it and discards the rest.
type headWriter struct {
	buf []byte
}

func (w *headWriter) Write(p []byte) (int, error) {
	if room := deltaHeadBytes - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}

	return len(p), nil
}

// walkPack parses a preflighted pack into memory and lists the tree of commit sha within the production bounds.
func walkPack(ctx context.Context, pack []byte, sha string) (*Listing, error) {
	return walkWith(ctx, pack, sha, defaultWalkLimits())
}

// walkWith parses pack into memory storage and walks the commit's tree with lim.
func walkWith(ctx context.Context, pack []byte, sha string, lim walkLimits) (*Listing, error) {
	st := memory.NewStorage()
	// NewParserWithStorage fails only for an unseekable source with no storage; the context-checking wrapper below
	// makes reads return ctx.Err() once the context is done, and it still seeks. The observer checks the context
	// during delta resolution; the wrapper checks it during the index phase before resolution.
	p, _ := packfile.NewParserWithStorage(
		packfile.NewScanner(&ctxReader{ctx: ctx, r: lim.wrapReader(bytes.NewReader(pack))}), st, ctxObserver{ctx: ctx},
	)
	if _, err := p.Parse(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}

		return nil, fmt.Errorf("%w: parse pack: %w", ErrSpecsRejected, err)
	}
	commit, err := object.GetCommit(st, plumbing.NewHash(sha))
	if err != nil {
		return nil, fmt.Errorf("%w: commit %s: %w", ErrSpecsRejected, sha, err)
	}

	return walkTrees(ctx, st, commit.TreeHash, sha, lim)
}

// ctxReader wraps an [io.ReadSeeker] and returns the context's error once it is done.
type ctxReader struct {
	ctx context.Context
	r   io.ReadSeeker
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}

	return c.r.Read(p)
}

func (c *ctxReader) Seek(offset int64, whence int) (int64, error) { return c.r.Seek(offset, whence) }

// ctxObserver stops a pack parse once ctx is done: go-git's parser calls it during delta resolution
// (packfile/parser.go:371, :375) and stops at the first error it returns. The ctxReader wrapper checks the context
// during the index phase before resolution. It holds its context because the observer interface passes none.
type ctxObserver struct{ ctx context.Context }

func (o ctxObserver) OnHeader(uint32) error { return nil }

func (o ctxObserver) OnInflatedObjectHeader(plumbing.ObjectType, int64, int64) error {
	return o.ctx.Err()
}

func (o ctxObserver) OnInflatedObjectContent(plumbing.Hash, int64, uint32, []byte) error {
	return o.ctx.Err()
}

func (o ctxObserver) OnFooter(plumbing.Hash) error { return nil }

// walkFrame is one tree still to read.
type walkFrame struct {
	hash   plumbing.Hash
	prefix string
	depth  int
}

// walkTrees lists every regular and executable file under root. Unlike go-git's TreeWalker, a missing or
// wrong-type subtree fails the walk instead of ending it early.
func walkTrees(
	ctx context.Context, st storer.EncodedObjectStorer, root plumbing.Hash, sha string, lim walkLimits,
) (*Listing, error) {
	l := &Listing{SHA: sha}
	stack := []walkFrame{{hash: root}}
	seen := 0
	listingBytes := 0
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		tree, err := object.GetTree(st, f.hash)
		if err != nil {
			return nil, fmt.Errorf("%w: tree %s at %q: %w", ErrSpecsRejected, f.hash, f.prefix, err)
		}
		for _, e := range tree.Entries {
			seen++
			p := joinTreePath(f.prefix, e.Name)
			const blobIDBytes = 40
			listingBytes += len(p) + blobIDBytes
			if seen > lim.entries || len(p) > lim.path || (e.Mode == filemode.Dir && f.depth+1 > lim.depth) ||
				listingBytes > lim.listingBytes {
				return nil, fmt.Errorf(
					"%w: tree past %d entries, %d listing bytes, a path past %d bytes or depth past %d at %q",
					ErrSpecsRejected, lim.entries, lim.listingBytes, lim.path, lim.depth, p,
				)
			}
			switch e.Mode { //nolint:exhaustive // The default counts symlinks, submodules and other modes as skipped.
			case filemode.Dir:
				stack = append(stack, walkFrame{hash: e.Hash, prefix: p, depth: f.depth + 1})
			case filemode.Regular, filemode.Executable:
				l.Entries = append(l.Entries, ListingEntry{Path: p, Blob: e.Hash.String()})
			default:
				l.Skipped++
			}
		}
	}

	return l, nil
}

// joinTreePath joins a tree prefix and an entry name with '/'; it never cleans the path, so a name the index
// grammar rejects stays visible to it.
func joinTreePath(prefix, name string) string {
	if prefix == "" {
		return name
	}

	return prefix + "/" + name
}
