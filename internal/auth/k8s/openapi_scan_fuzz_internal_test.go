package k8s

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// FuzzScan checks that the streaming pass never panics, accepts only one valid JSON value, and refuses only with
// its own sentinel. The seeds reach every branch: each refusal (an over-long key and invalid UTF-8 included), the pruning rule, a top-level scalar and an
// out-of-range number.
func FuzzScan(f *testing.F) {
	for _, s := range []string{
		``, `5`, `"x"`, `{}`, `[]`, `{"a":[1,{"b":null}]}`, `{"a":`, `{"a" 1}`, `{} {}`, `[1]]`,
		`{"components":{"schemas":{"A":{"x":[1,2]}}}}`, `{"Components":{"SCHEMAS":{"A":{}}}}`,
		`{"components":[{"schemas":{}}]}`, `{"x-n":1e400}`, string(nested(MaxScanDepth + 1)), string(members(3)),
		`{"` + strings.Repeat("k", MaxKeyBytes+1) + `":1}`,
		"{\"a\":\"\xff\"}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, err := Scan(t.Context(), body, 64)
		if err == nil && !json.Valid(body) {
			t.Fatalf("accepted invalid JSON %q", body)
		}
		if err != nil && !errors.Is(err, ErrScanRefused) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}
