package azure

import (
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"
)

// FuzzSummarize guards the file summary against hostile spec bytes: it never panics, fails only with
// ErrSpecsRejected, is deterministic, and lists only operations with an id and an upper-case Swagger method.
func FuzzSummarize(f *testing.F) {
	for _, seed := range []string{
		`not json`,
		`{}`,
		`{"info":{"version":"2024-01-01"},"paths":{"/a":{"get":{"operationId":"A_Get"}}}}`,
		`{"x-ms-paths":{"/a?x":{"post":{"operationId":"A_Do"}}}}`,
		`{"paths":{"/a":{"parameters":[],"x-ext":{},"get":{}}}}`,
		`{"paths":{"/a":{"get":{"operationId":7}}}}`,
		`{"paths":{"/a":[]}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := Summarize(body)
		if err != nil {
			if !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("error %v is not ErrSpecsRejected", err)
			}
			return
		}
		again, _ := Summarize(body)
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("summarize is not deterministic")
		}
		for _, op := range got.Ops {
			if op.ID == "" || !swaggerMethods[strings.ToLower(op.Method)] || op.Method != strings.ToUpper(op.Method) {
				t.Fatalf("bad op %+v", op)
			}
		}
	})
}

// FuzzRefPath guards ref confinement: an accepted ref names a clean ref target of the index.
func FuzzRefPath(f *testing.F) {
	for _, seed := range []string{
		"", "things.json", "../../common/v1/common.json", "/abs.json", "https://e/x.json", `..\x.json`,
		"%2e%2e/x.json", "a.json?q=1", "%zz",
	} {
		f.Add(seed)
	}
	ix := refIndex(testOpFile, commonFile, localFile)
	f.Fuzz(func(t *testing.T, file string) {
		got, err := refPath(testOpFile, file, ix)
		if err != nil {
			if !errors.Is(err, errRefConfined) {
				t.Fatalf("error %v is not errRefConfined", err)
			}
			return
		}
		if _, ok := ix.Refs[got]; !ok || got != path.Clean(got) || strings.Contains(got, "..") {
			t.Fatalf("refPath(%q) = %q, not a clean ref target", file, got)
		}
	})
}
