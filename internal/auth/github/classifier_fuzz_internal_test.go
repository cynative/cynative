package github

import (
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

const fuzzMiniOpenAPI = `{"paths":{
  "/user": {"get": {"x-github": {"category":"users","subcategory":"users"}}},
  "/markdown": {"post": {"x-github": {"category":"markdown","subcategory":"markdown"}}},
  "/repos/{owner}/{repo}/issues": {"post": {"x-github": {"category":"issues","subcategory":"issues"}}},
  "/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}}
}}`

//nolint:gochecknoglobals // fuzz table built once; immutable after DistillOpenAPI.
var (
	fuzzTblOnce sync.Once
	fuzzTbl     *Table
	errFuzzTbl  error
)

func fuzzTable(t *testing.T) *Table {
	t.Helper()
	fuzzTblOnce.Do(func() {
		fuzzTbl, errFuzzTbl = DistillOpenAPI([]byte(fuzzMiniOpenAPI))
	})
	if errFuzzTbl != nil {
		t.Fatalf("DistillOpenAPI: %v", errFuzzTbl)
	}

	return fuzzTbl
}

// FuzzIsGraphQLEndpoint pins panic-freedom over arbitrary paths (#181).
func FuzzIsGraphQLEndpoint(f *testing.F) {
	f.Add("/graphql")
	f.Add("/graphql/")
	f.Add("/users/octo")
	f.Add("")

	f.Fuzz(func(_ *testing.T, path string) {
		_ = IsGraphQLEndpoint(path)
	})
}

// FuzzRequiredLevel pins panic-freedom; unknown methods fail closed (#181).
func FuzzRequiredLevel(f *testing.F) {
	f.Add(http.MethodGet, "/user")
	f.Add(http.MethodPost, "/markdown")
	f.Add(http.MethodPost, "/repos/o/r/issues")
	f.Add("FOO", "/user")

	f.Fuzz(func(t *testing.T, method, path string) {
		lvl, err := RequiredLevel(method, path)
		if err != nil {
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("RequiredLevel(%q,%q) err=%v, want ErrUnclassifiable", method, path, err)
			}
			if lvl != exposure.LevelNone {
				t.Fatalf("err path level=%v, want LevelNone", lvl)
			}

			return
		}
		if lvl != exposure.LevelRead && lvl != exposure.LevelWrite {
			t.Fatalf("unexpected level %v", lvl)
		}
	})
}

// FuzzClassifyRequest pins panic-freedom over method/path with a fixed table (#181).
func FuzzClassifyRequest(f *testing.F) {
	f.Add(http.MethodGet, "/user")
	f.Add(http.MethodGet, "/nope")
	f.Add(http.MethodGet, "/repos/o/r/secret-scanning/alerts")
	f.Add("FOO", "/user")

	f.Fuzz(func(t *testing.T, method, path string) {
		acc, err := ClassifyRequest(fuzzTable(t), method, path)
		if err != nil {
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("ClassifyRequest err=%v, want ErrUnclassifiable", err)
			}

			return
		}
		if acc.Route.Category == "" {
			t.Fatal("success with empty category")
		}
	})
}

// FuzzLookup pins panic-freedom of table routing (#181).
func FuzzLookup(f *testing.F) {
	f.Add("GET", "/user")
	f.Add("GET", "/unknown")
	f.Add("GET", "/repos/o/r/contents/src/a/b.go")

	f.Fuzz(func(t *testing.T, method, path string) {
		_, _ = fuzzTable(t).Lookup(method, path)
	})
}

// FuzzDistillOpenAPI pins panic-freedom; failures are ErrTableRejected (#181).
func FuzzDistillOpenAPI(f *testing.F) {
	f.Add([]byte(fuzzMiniOpenAPI))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"paths":{}}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		tbl, err := DistillOpenAPI(raw)
		if err == nil {
			if tbl == nil {
				t.Fatal("nil table on success")
			}

			return
		}
		if !errors.Is(err, ErrTableRejected) {
			t.Fatalf("err=%v, want ErrTableRejected", err)
		}
		if tbl != nil {
			t.Fatal("non-nil table on error")
		}
	})
}
