package authreq

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// escapePairLen is the length of a two-byte JSON escape sequence (a backslash
// and the character it escapes), which is what a scan steps over to keep an
// escaped quote from ending the string.
const escapePairLen = 2

// projectBlock returns the raw value stored under key in the top-level object
// of toolCall, or nil when there is no such key.
//
// It slices the value out of toolCall in place rather than decoding into a
// map[string]json.RawMessage, because that map copies every top-level value to
// retain one. The tool call carries the model-authored request body, so the
// copy is unbounded and every one of it is discarded except the auth block.
//
// [json.Valid] runs first and scans without allocating, so everything below
// walks a document already known to be well formed and only has to find
// boundaries, never validate them. Anything [json.Valid] rejects, and any
// top-level value that is not an object, is handed back to encoding/json so the
// caller sees the error it would have produced rather than one invented here.
//
// FuzzProjectBlock pins the whole walk against the map decode it replaced, on
// both the error verdict and the extracted bytes.
func projectBlock(toolCall json.RawMessage, key string) (json.RawMessage, error) {
	if json.Valid(toolCall) {
		i := skipSpace(toolCall, 0)

		if i < len(toolCall) && toolCall[i] == '{' {
			return findKey(toolCall, i+1, key), nil
		}

		// A top-level null decodes into a nil map, which reads as "key absent"
		// and matches how the tool call's own arguments have always been
		// treated. json.Valid passed, so an 'n' here can only begin null.
		if i < len(toolCall) && toolCall[i] == 'n' {
			return nil, nil
		}
	}

	// Reached only for input encoding/json rejects: malformed JSON, or a
	// top-level value that is not an object and so cannot carry an auth block.
	var fields map[string]json.RawMessage

	return nil, json.Unmarshal(toolCall, &fields)
}

// findKey walks the members of a well-formed object whose body starts at i and
// returns the raw value of the member named key, or nil.
//
// It keeps walking after a match rather than returning, because a duplicated
// key must resolve the way encoding/json resolves it: the last occurrence wins.
// Returning the first would let a tool call carrying the key twice show a gate
// one block while the tool schema decoded the other, which is the same
// one-fact-two-sources split this narrowing exists to close.
func findKey(d []byte, i int, key string) json.RawMessage {
	var found json.RawMessage

	for {
		i = skipSpace(d, i)
		if i >= len(d) || d[i] != '"' {
			return found // The closing brace, so every member has been seen.
		}

		nameStart := i
		i = endOfString(d, i)
		name := d[nameStart:i]

		i = skipSpace(d, i)
		if i >= len(d) {
			return found
		}

		i = skipSpace(d, i+1) // Step over the name/value colon.
		valueStart := i
		i = endOfValue(d, i)

		if keyEquals(name, key) {
			found = json.RawMessage(d[valueStart:i])
		}

		i = skipSpace(d, i)
		if i >= len(d) || d[i] != ',' {
			return found
		}

		i++
	}
}

// keyEquals reports whether the quoted member name raw denotes key, deciding it
// the way encoding/json would.
//
// A name that is unescaped and valid UTF-8 survives decoding byte for byte, so
// it is compared in place. Anything else is decoded first, because both an
// escape and an invalid byte change what the name means: encoding/json unquotes
// the escape, and it substitutes U+FFFD for the invalid byte, so raw bytes that
// merely look equal are not. Deciding this by eye would be the wrong way to be
// wrong for a connector that treats absent arguments as allow.
func keyEquals(raw []byte, key string) bool {
	if bytes.IndexByte(raw, '\\') < 0 && utf8.Valid(raw) {
		return len(raw) == len(key)+2 && string(raw[1:len(raw)-1]) == key
	}

	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return false
	}

	return name == key
}

// skipSpace returns the index of the first byte at or after i that is not JSON
// insignificant whitespace.
func skipSpace(d []byte, i int) int {
	for i < len(d) {
		switch d[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}

	return i
}

// endOfString returns the index just past the closing quote of the string
// starting at i, never past the end of d.
//
// The clamp is load bearing. A string truncated mid-escape steps the index two
// bytes over a slice with one left, and callers slice d with what this returns,
// so an unclamped result is a panic rather than a miss.
func endOfString(d []byte, i int) int {
	for i++; i < len(d); i++ {
		switch d[i] {
		case '\\':
			i += escapePairLen - 1 // The loop's own i++ steps over the second byte.
		case '"':
			return i + 1
		}
	}

	return min(i, len(d))
}

// endOfValue returns the index just past the JSON value starting at i.
func endOfValue(d []byte, i int) int {
	if i >= len(d) {
		return i
	}

	switch d[i] {
	case '"':
		return endOfString(d, i)
	case '{', '[':
		return endOfContainer(d, i)
	default:
		return endOfScalar(d, i)
	}
}

// endOfContainer returns the index just past the object or array starting at i,
// counting nesting and stepping over strings so a brace inside one cannot close
// it early.
func endOfContainer(d []byte, i int) int {
	depth := 0

	for i < len(d) {
		switch d[i] {
		case '"':
			i = endOfString(d, i)

			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}

		i++
	}

	return i
}

// endOfScalar returns the index just past the number, true, false or null
// starting at i, all of which run until a structural byte or whitespace.
func endOfScalar(d []byte, i int) int {
	for ; i < len(d); i++ {
		switch d[i] {
		case ',', '}', ']', ' ', '\t', '\r', '\n':
			return i
		}
	}

	return i
}
