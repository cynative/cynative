package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Streaming-pass bounds. The pass runs on every root and document body before anything decodes it into maps,
// slices or structs, so a hostile body is refused at the cost of its tokens rather than of the Go values a decode
// would build.
const (
	// MaxScanDepth is the deepest nesting of objects and arrays the pass accepts.
	MaxScanDepth = 128
	// MaxDocumentElements bounds the counted elements of a group-version document.
	MaxDocumentElements = 100_000
	// MaxRootElements bounds the counted elements of the /openapi/v3 root.
	MaxRootElements = 10_000
	// MaxKeyBytes bounds every decoded object key at any depth. Keys become paths, media types and parameter and
	// header names that later steps copy, compare and render per operation and per lookup; the longest key in the
	// live documents of a 1.34 cluster is 90 bytes.
	MaxKeyBytes = 4096
	// maxCountedDepth is the deepest container whose members or elements are counted. The pre-pass and the core
	// decode a document into maps, slices and structs no deeper than this; every deeper value they read is held as
	// raw JSON or decoded into a string, so it costs its bytes and no Go values.
	maxCountedDepth = 9
	// scanCheckEvery is how many tokens the pass reads between context checks.
	scanCheckEvery = 4096
)

// ErrScanRefused marks a body the streaming pass refused. Its text is fixed host text that names the cap, never
// cluster text.
var ErrScanRefused = errors.New("refused by the streaming pass")

// scanFrame is one open container: its depth (the top-level value is 1), whether it is an object waiting for a
// key, and the facts the components.schemas pruning rule needs.
type scanFrame struct {
	object     bool
	wantKey    bool
	depth      int
	pruned     bool
	components bool
	schemas    bool
	key        string
	// seen holds the folded keys of a counted object, so a repeated key is refused.
	seen map[string]struct{}
}

// Scan reads body token by token, keeping only the stack of open containers, and refuses it when it is not UTF-8, when it nests deeper than
// MaxScanDepth, when an object key is longer than MaxKeyBytes, when it counts more than maxElements elements, or when
// it is not one JSON value. A counted element is an object member or an array element in a container at depth
// maxCountedDepth or less, except anything below a member of components.schemas. Numbers are kept as text (UseNumber),
// so an out-of-range literal in a subtree no decode reads does not fail the pass. It returns the count.
func Scan(ctx context.Context, body []byte, maxElements int) (int, error) {
	// The decoder replaces each invalid byte with a three-byte U+FFFD, and its unquoting buffers grow past that, so
	// a body of invalid bytes costs many times its size. JSON is UTF-8 (RFC 8259); anything else is refused first.
	if !utf8.Valid(body) {
		return 0, fmt.Errorf("%w: not UTF-8", ErrScanRefused)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var stack []scanFrame
	count, tokens := 0, 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return count, scanEnd(err, len(stack))
		}
		if tokens++; tokens%scanCheckEvery == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return count, cerr
			}
		}
		var counted bool
		if stack, counted, err = scanStep(stack, tok); err != nil {
			return count, err
		}
		if counted {
			if count++; count > maxElements {
				return count, fmt.Errorf("%w: more than %d elements", ErrScanRefused, maxElements)
			}
		}
		if len(stack) == 0 {
			return count, scanTrailing(dec)
		}
	}
}

// scanEnd maps a decoder error: end of input with containers still open, or any syntax error, is not JSON.
func scanEnd(err error, open int) error {
	if errors.Is(err, io.EOF) && open == 0 {
		return fmt.Errorf("%w: empty body", ErrScanRefused)
	}

	return fmt.Errorf("%w: not JSON", ErrScanRefused)
}

// scanTrailing requires the body to end after its first value.
func scanTrailing(dec *json.Decoder) error {
	if _, err := dec.Token(); errors.Is(err, io.EOF) {
		return nil
	}

	return fmt.Errorf("%w: not one JSON value", ErrScanRefused)
}

// scanStep applies one token to the stack and reports whether it starts a counted element.
func scanStep(stack []scanFrame, tok json.Token) ([]scanFrame, bool, error) {
	if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
		stack = stack[:len(stack)-1]
		valueDone(stack)

		return stack, false, nil
	}
	if len(stack) == 0 {
		return openValue(stack, nil, tok)
	}
	top := &stack[len(stack)-1]
	if top.object && top.wantKey {
		// encoding/json returns every object key as a string token.
		top.key, _ = tok.(string)
		if len(top.key) > MaxKeyBytes {
			return stack, false, fmt.Errorf("%w: an object key longer than %d bytes", ErrScanRefused, MaxKeyBytes)
		}
		if err := top.firstKey(); err != nil {
			return stack, false, err
		}
		top.wantKey = false

		return stack, countable(top), nil
	}
	counted := !top.object && countable(top)
	stack, _, err := openValue(stack, top, tok)

	return stack, counted, err
}

// firstKey refuses a key f already holds. The pre-pass and the core decode the counted containers into structs,
// slices and maps, and encoding/json binds a repeated key, or one that differs only by case, to the same field: a
// raw field keeps the last value while a slice or struct merges it into the earlier one, so the two passes could
// read different values. Keys are compared folded as encoding/json folds them; only counted objects are tracked.
func (f *scanFrame) firstKey() error {
	if !countable(f) {
		return nil
	}
	k := foldKey(f.key)
	if _, dup := f.seen[k]; dup {
		return fmt.Errorf("%w: a duplicate object key", ErrScanRefused)
	}
	if f.seen == nil {
		f.seen = map[string]struct{}{}
	}
	f.seen[k] = struct{}{}

	return nil
}

// foldKey folds a key as encoding/json does when it matches a key to a field: ASCII letters to upper case, any
// other rune to the smallest rune of its case-folding orbit.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < utf8.RuneSelf {
			b.WriteRune(unicode.ToUpper(r))
			continue
		}
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			low = min(low, f)
		}
		b.WriteRune(low)
	}

	return b.String()
}

// countable reports whether a member or element of f is counted.
func countable(f *scanFrame) bool {
	return f.depth <= maxCountedDepth && !f.pruned
}

// openValue pushes a frame when tok opens a container; a scalar completes its value at once. parent is the frame
// the value belongs to, nil for the top-level value.
func openValue(stack []scanFrame, parent *scanFrame, tok json.Token) ([]scanFrame, bool, error) {
	d, ok := tok.(json.Delim)
	if !ok {
		valueDone(stack)

		return stack, false, nil
	}
	if len(stack) == MaxScanDepth {
		return stack, false, fmt.Errorf("%w: nesting deeper than %d containers", ErrScanRefused, MaxScanDepth)
	}
	f := scanFrame{object: d == '{', wantKey: d == '{', depth: len(stack) + 1}
	if parent != nil {
		f.pruned = parent.pruned || parent.schemas
		f.components = parent.object && f.depth == 2 && strings.EqualFold(parent.key, "components")
		f.schemas = parent.components && strings.EqualFold(parent.key, "schemas")
	}

	return append(stack, f), false, nil
}

// valueDone marks the innermost object, if any, as waiting for its next key.
func valueDone(stack []scanFrame) {
	if len(stack) > 0 && stack[len(stack)-1].object {
		stack[len(stack)-1].wantKey = true
	}
}
