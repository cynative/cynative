package gitlab

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

const fuzzMiniOpenAPI = `openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: ["Projects"]
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
  /api/v4/markdown:
    post:
      tags: ["Markdown"]
`

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

// FuzzIsGraphQLEndpoint pins panic-freedom over arbitrary escaped paths (#181).
func FuzzIsGraphQLEndpoint(f *testing.F) {
	f.Add("/api/graphql")
	f.Add("/api/%67raphql")
	f.Add("/gitlab/api/graphql")
	f.Add("/files/x%2Fapi%2Fgraphql")
	f.Add("/api/v4/projects")

	f.Fuzz(func(_ *testing.T, path string) {
		_ = IsGraphQLEndpoint(path)
	})
}

// FuzzRequiredLevel pins panic-freedom; unknown methods fail closed (#181).
func FuzzRequiredLevel(f *testing.F) {
	f.Add(http.MethodGet, "/api/v4/projects")
	f.Add(http.MethodPost, "/api/v4/markdown")
	f.Add(http.MethodPost, "/api/v4/projects")
	f.Add("FROBNICATE", "/api/v4/x")

	f.Fuzz(func(t *testing.T, method, path string) {
		lvl, err := RequiredLevel(method, path)
		if err != nil {
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("err=%v, want ErrUnclassifiable", err)
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
	f.Add(http.MethodGet, "/api/v4/projects")
	f.Add(http.MethodGet, "/api/v4/unknown/route")
	f.Add(http.MethodHead, "/api/v4/projects/1/issues")
	f.Add("FROBNICATE", "/api/v4/projects")

	f.Fuzz(func(t *testing.T, method, path string) {
		acc, err := ClassifyRequest(fuzzTable(t), method, path)
		if err != nil {
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("err=%v, want ErrUnclassifiable", err)
			}

			return
		}
		if acc.Category == "" {
			t.Fatal("success with empty category")
		}
	})
}

// FuzzLookup pins root-anchor: non-root api/v4 must never match (#181).
func FuzzLookup(f *testing.F) {
	f.Add("GET", "/api/v4/projects")
	f.Add("GET", "/group/api/v4/projects/42/issues")
	f.Add("GET", "/gitlab/api/v4/projects")

	f.Fuzz(func(t *testing.T, method, path string) {
		route, ok := fuzzTable(t).Lookup(method, path)
		if ok && route.Category == "" {
			t.Fatal("match with empty category")
		}
		for _, bad := range []string{"/group/api/v4/", "/gitlab/api/v4/"} {
			if strings.HasPrefix(path, bad) && ok {
				t.Fatalf("non-root anchor matched: %q → %+v", path, route)
			}
		}
	})
}

// FuzzDistillOpenAPI pins panic-freedom; failures are ErrTableRejected (#181).
func FuzzDistillOpenAPI(f *testing.F) {
	f.Add([]byte(fuzzMiniOpenAPI))
	f.Add([]byte("not yaml"))
	f.Add([]byte("openapi: \"3.0.0\"\npaths: {}\n"))

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
