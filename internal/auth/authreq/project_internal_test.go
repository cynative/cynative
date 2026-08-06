package authreq

import "testing"

// The walk's helpers are only ever reached through projectBlock, which runs
// json.Valid first, so no truncated input can arrive by that route. These
// exercise them directly anyway: each is a total function whose bounds guard is
// what keeps a truncated document from running off the end of the slice, and
// that has to hold on its own rather than because of a check in a different
// function that a later edit could reorder away.

func TestSkipSpace_RunsOutOfInput(t *testing.T) {
	t.Parallel()

	d := []byte(" \t\r\n")
	if got := skipSpace(d, 0); got != len(d) {
		t.Errorf("skipSpace(all space) = %d, want %d", got, len(d))
	}

	if got := skipSpace(nil, 0); got != 0 {
		t.Errorf("skipSpace(nil) = %d, want 0", got)
	}
}

// TestEndOfString_Unterminated covers the clamp. `"abc\` is the case that
// matters: the trailing escape steps the index two bytes over the one byte
// left, so without the clamp this returns len(d)+1 and the caller's slice of d
// panics instead of missing.
func TestEndOfString_Unterminated(t *testing.T) {
	t.Parallel()

	for _, d := range []string{`"abc`, `"abc\`, `"`, `"\`} {
		if got := endOfString([]byte(d), 0); got != len(d) {
			t.Errorf("endOfString(%q) = %d, want %d", d, got, len(d))
		}
	}
}

// TestFindKey_TruncatedMidEscape drives the clamp through its caller: findKey
// slices d with what endOfString returns, so an unclamped result panics here.
// Whatever it returns must stay inside d; a truncated value coming back as
// truncated bytes is fine, because Parse then fails to decode it.
func TestFindKey_TruncatedMidEscape(t *testing.T) {
	t.Parallel()

	for _, d := range []string{`{"aws\`, `{"aws_auth":"v\`, `{"a":{"b":"\`, `{"aws_auth":1\`} {
		if got := findKey([]byte(d), 1, "aws_auth"); len(got) > len(d) {
			t.Errorf("findKey(%q) = %q, which is longer than its input", d, got)
		}
	}
}

func TestEndOfValue_PastEnd(t *testing.T) {
	t.Parallel()

	d := []byte(`{}`)
	if got := endOfValue(d, len(d)); got != len(d) {
		t.Errorf("endOfValue past the end = %d, want %d", got, len(d))
	}
}

func TestEndOfContainer_Unterminated(t *testing.T) {
	t.Parallel()

	for _, d := range []string{`{"a":1`, `[1,2`, `{"a":"x`} {
		if got := endOfContainer([]byte(d), 0); got != len(d) {
			t.Errorf("endOfContainer(%q) = %d, want %d", d, got, len(d))
		}
	}
}

func TestEndOfScalar_RunsToEnd(t *testing.T) {
	t.Parallel()

	d := []byte(`123`)
	if got := endOfScalar(d, 0); got != len(d) {
		t.Errorf("endOfScalar(%q) = %d, want %d", d, got, len(d))
	}
}

func TestFindKey_TruncatedAfterName(t *testing.T) {
	t.Parallel()

	// The name is complete but the colon and value are not, so the walk has to
	// stop rather than index past the end.
	if got := findKey([]byte(`{"aws_auth"`), 1, "aws_auth"); got != nil {
		t.Errorf("findKey(truncated after name) = %q, want nil", got)
	}
}

func TestKeyEquals_UndecodableName(t *testing.T) {
	t.Parallel()

	// A backslash sends this down the decode path, and the escape is not one
	// JSON defines, so the name cannot be decoded and cannot match.
	if keyEquals([]byte(`"\q"`), "q") {
		t.Error(`keyEquals("\\q", "q") = true, want false: an undecodable name matches nothing`)
	}
}
