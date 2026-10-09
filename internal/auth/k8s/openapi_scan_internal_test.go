package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// nested returns a body of n nested arrays.
func nested(n int) []byte {
	return []byte(strings.Repeat("[", n) + strings.Repeat("]", n))
}

// members returns {"paths":{...}} whose paths object holds n members, so the body counts n+1 elements.
func members(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"paths":{`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"/p%d":0`, i)
	}
	b.WriteString(`}}`)

	return []byte(b.String())
}

func TestScan_Depth(t *testing.T) {
	t.Parallel()
	if _, err := Scan(t.Context(), nested(MaxScanDepth), MaxDocumentElements); err != nil {
		t.Fatalf("depth %d: %v", MaxScanDepth, err)
	}
	_, err := Scan(t.Context(), nested(MaxScanDepth+1), MaxDocumentElements)
	if !errors.Is(err, ErrScanRefused) || !strings.Contains(err.Error(), "nesting deeper than 128 containers") {
		t.Fatalf("depth %d: err = %v", MaxScanDepth+1, err)
	}
}

func TestScan_KeyLength(t *testing.T) {
	t.Parallel()
	doc := func(key string) []byte { return []byte(`{"paths":{"/p":{"x":[{"` + key + `":1}]}}}`) }
	if _, err := Scan(t.Context(), doc(strings.Repeat("k", MaxKeyBytes)), MaxDocumentElements); err != nil {
		t.Fatalf("a %d-byte key: %v", MaxKeyBytes, err)
	}
	// The cap applies to the decoded key at any depth, counted or not, so an escaped spelling is no shorter.
	for _, key := range []string{strings.Repeat("k", MaxKeyBytes+1), strings.Repeat(`\u006b`, MaxKeyBytes+1)} {
		deep := []byte(string(nested(12)[:12]) + `{"` + key + `":1}` + string(nested(12)[12:]))
		for _, body := range [][]byte{doc(key), deep} {
			_, err := Scan(t.Context(), body, MaxDocumentElements)
			if !errors.Is(err, ErrScanRefused) || err.Error() != fmt.Sprintf(
				"refused by the streaming pass: an object key longer than %d bytes", MaxKeyBytes) {
				t.Errorf("a %d-byte body: err = %v", len(body), err)
			}
		}
	}
}

func TestScan_RefusesInvalidUTF8(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"a":"` + "\xff" + `"}`, `{"` + "\xc3" + `":1}`, "\xef\xbb\xbf{}"} {
		_, err := Scan(t.Context(), []byte(body), MaxDocumentElements)
		want := "refused by the streaming pass: not UTF-8"
		if body == "\xef\xbb\xbf{}" {
			want = "refused by the streaming pass: not JSON"
		}
		if !errors.Is(err, ErrScanRefused) || err.Error() != want {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
	if _, err := Scan(t.Context(), []byte(`{"a":"é ☃ \u00e9"}`), MaxDocumentElements); err != nil {
		t.Errorf("valid UTF-8: %v", err)
	}
}

func TestScan_ElementCaps(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{MaxRootElements, MaxDocumentElements} {
		n, err := Scan(t.Context(), members(limit-1), limit)
		if err != nil || n != limit {
			t.Fatalf("cap %d at the boundary: n=%d err=%v", limit, n, err)
		}
		_, err = Scan(t.Context(), members(limit), limit)
		if !errors.Is(err, ErrScanRefused) || err.Error() != fmt.Sprintf(
			"refused by the streaming pass: more than %d elements", limit) {
			t.Fatalf("cap %d past the boundary: err = %v", limit, err)
		}
	}
}

func TestScan_Counting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want int
	}{
		{"scalar", `5`, 0},
		{"object members and array elements", `{"a":[1,2,{"b":3}],"c":null}`, 6},
		{"members at depth 9 count, depth 10 does not", strings.Repeat(`{"k":`, 9) + `{"x":1,"y":2}` +
			strings.Repeat(`}`, 9), 9},
		{"arrays at depth 10 do not count", strings.Repeat(`[`, 9) + `[1,2]` + strings.Repeat(`]`, 9), 9},
		{"schema names count, their bodies do not", `{"components":{"schemas":{"A":{"x":1,"y":[1,2]},"B":{}}}}`, 4},
		{"spellings fold", `{"Components":{"SCHEMAS":{"A":{"x":1,"y":2}}}}`, 3},
		{"parameters are not pruned", `{"components":{"parameters":{"A":{"x":1}}}}`, 4},
		{"schemas below another key count", `{"paths":{"schemas":{"A":{"x":1}}}}`, 4},
		{"components below the top does not prune", `{"a":{"components":{"schemas":{"A":{"x":1}}}}}`, 5},
		{"a components array does not prune", `{"components":[{"schemas":{"A":{"x":1}}}]}`, 5},
		{"an out-of-range number in an extension", `{"x-n":1e400,"info":{"x-big":[1e400]}}`, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := Scan(t.Context(), []byte(tc.body), MaxDocumentElements)
			if err != nil || n != tc.want {
				t.Fatalf("Scan(%s) = %d, %v; want %d", tc.body, n, err, tc.want)
			}
		})
	}
}

func TestScan_RefusesWhatIsNotOneValue(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]string{
		``:          "refused by the streaming pass: empty body",
		`{"a":`:     "refused by the streaming pass: not JSON",
		`{"a" 1}`:   "refused by the streaming pass: not JSON",
		`{} {}`:     "refused by the streaming pass: not one JSON value",
		`{"a":1}]`:  "refused by the streaming pass: not one JSON value",
		`<html>`:    "refused by the streaming pass: not JSON",
		`[1,2,3`:    "refused by the streaming pass: not JSON",
		`"x" "tail`: "refused by the streaming pass: not one JSON value",
	} {
		if _, err := Scan(t.Context(), []byte(body), MaxDocumentElements); err == nil || err.Error() != want {
			t.Errorf("Scan(%q) err = %v, want %q", body, err, want)
		}
	}
}

func TestScan_ChecksTheContextEvery4096Tokens(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// "[", 4093 numbers and "]" are 4095 tokens, so the pass ends before its first check.
	short := "[" + strings.Repeat("0,", scanCheckEvery-4) + "0]"
	if _, err := Scan(ctx, []byte(short), MaxDocumentElements); err != nil {
		t.Fatalf("4095 tokens: %v", err)
	}
	long := "[" + strings.Repeat("0,", scanCheckEvery-3) + "0]"
	if _, err := Scan(ctx, []byte(long), MaxDocumentElements); !errors.Is(err, context.Canceled) {
		t.Fatalf("4096 tokens: err = %v, want context.Canceled", err)
	}
}
