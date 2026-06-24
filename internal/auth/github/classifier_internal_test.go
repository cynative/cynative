package github

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// classTable is a small table covering the routes the classifier tests hit.
func classTable(t *testing.T) *Table {
	t.Helper()
	tbl, err := DistillOpenAPI([]byte(`{"paths":{
		"/user": {"get": {"x-github": {"category":"users","subcategory":"users"}}, "patch": {"x-github": {"category":"users","subcategory":"users"}}},
		"/markdown": {"post": {"x-github": {"category":"markdown","subcategory":"markdown"}}},
		"/repos/{owner}/{repo}/issues": {"post": {"x-github": {"category":"issues","subcategory":"issues"}}},
		"/repos/{owner}/{repo}/secret-scanning/alerts": {"get": {"x-github": {"category":"secret-scanning","subcategory":"secret-scanning"}}}
	}}`))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	return tbl
}

func TestIsGraphQLEndpoint(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/graphql":    true,
		"/graphql/":   true,
		"/graphql//":  true,
		"/users/octo": false,
		"/repos/a/b":  false,
		"/graphqlx":   false,
		"/v3/graphql": false,
	}
	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if got := IsGraphQLEndpoint(path); got != want {
				t.Fatalf("IsGraphQLEndpoint(%q) = %v, want %v", path, got, want)
			}
		})
	}
}

func TestClassifyRequest_REST(t *testing.T) {
	t.Parallel()

	tbl := classTable(t)
	cases := []struct {
		name, method, path string
		wantCat            string
		wantLevel          exposure.Level
		wantErr            error
	}{
		{"get is read", http.MethodGet, "/user", "users", exposure.LevelRead, nil},
		{"patch is write", http.MethodPatch, "/user", "users", exposure.LevelWrite, nil},
		{"post markdown is read", http.MethodPost, "/markdown", "markdown", exposure.LevelRead, nil},
		{"post issues is write", http.MethodPost, "/repos/o/r/issues", "issues", exposure.LevelWrite, nil},
		{
			"secret-scanning category via table",
			http.MethodGet, "/repos/o/r/secret-scanning/alerts", "secret-scanning", exposure.LevelRead, nil,
		},
		{"unknown route fails closed", http.MethodGet, "/nope", "", exposure.LevelNone, ErrUnclassifiable},
		{"unknown method fails closed", "FOO", "/user", "", exposure.LevelNone, ErrUnclassifiable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ClassifyRequest(tbl, c.method, c.path)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("ClassifyRequest(%q,%q) err=%v, want %v", c.method, c.path, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyRequest(%q,%q) unexpected err %v", c.method, c.path, err)
			}
			if got.Level != c.wantLevel {
				t.Fatalf("ClassifyRequest(%q,%q) level=%v, want %v", c.method, c.path, got.Level, c.wantLevel)
			}
			if got.Route.Category != c.wantCat {
				t.Fatalf("ClassifyRequest(%q,%q) cat=%q, want %q", c.method, c.path, got.Route.Category, c.wantCat)
			}
		})
	}
}

// TestClassifyRequest_HEAD_OPTIONS verifies that HEAD and OPTIONS probe the GET
// route in the table so legitimate read requests are not denied (F4).
func TestClassifyRequest_HEAD_OPTIONS(t *testing.T) {
	t.Parallel()

	tbl := classTable(t)
	cases := []struct {
		name, method, path string
		wantCat            string
		wantLevel          exposure.Level
	}{
		{"HEAD /user classifies read", http.MethodHead, "/user", "users", exposure.LevelRead},
		{"OPTIONS /user classifies read", http.MethodOptions, "/user", "users", exposure.LevelRead},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ClassifyRequest(tbl, c.method, c.path)
			if err != nil {
				t.Fatalf("ClassifyRequest(%q,%q) unexpected err %v", c.method, c.path, err)
			}
			if got.Level != c.wantLevel {
				t.Fatalf("level=%v, want %v", got.Level, c.wantLevel)
			}
			if got.Route.Category != c.wantCat {
				t.Fatalf("category=%q, want %q", got.Route.Category, c.wantCat)
			}
		})
	}
}
