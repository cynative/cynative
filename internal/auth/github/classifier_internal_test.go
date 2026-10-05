package github

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
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
			if len(got.Routes) != 1 {
				t.Fatalf("ClassifyRequest(%q,%q) routes=%+v, want one", c.method, c.path, got.Routes)
			}
			if got.Routes[0].Category != c.wantCat {
				t.Fatalf("ClassifyRequest(%q,%q) cat=%q, want %q", c.method, c.path, got.Routes[0].Category, c.wantCat)
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
			if len(got.Routes) != 1 {
				t.Fatalf("routes=%+v, want one", got.Routes)
			}
			if got.Routes[0].Category != c.wantCat {
				t.Fatalf("category=%q, want %q", got.Routes[0].Category, c.wantCat)
			}
		})
	}
}

func TestClassifyRequest_NoTemplateIsUnmatched(t *testing.T) {
	t.Parallel()
	tbl := classTable(t)
	_, err := ClassifyRequest(tbl, "GET", "/no/such/route")
	var um *authreq.UnmatchedRequestError
	if !errors.As(err, &um) || !errors.Is(err, ErrUnclassifiable) {
		t.Fatalf("got %v", err)
	}
	_, err = ClassifyRequest(tbl, "BREW", "/user")
	if errors.As(err, &um) || !errors.Is(err, ErrUnclassifiable) {
		t.Fatalf("an unrecognized method is not an unmatched route: %v", err)
	}
}

func TestClassifyRequest_ShadowedRoutesAllMethodsReadAsGet(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(shadowOpenAPI))
	if err != nil {
		t.Fatalf("DistillOpenAPI: %v", err)
	}
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		got, mErr := ClassifyRequest(tbl, m, "/repos/o/r/branches/main/protection")
		if mErr != nil {
			t.Fatalf("%s: %v", m, mErr)
		}
		if want := []Route{{"branches", "branch-protection"}}; !slices.Equal(got.Routes, want) {
			t.Errorf("%s: routes = %+v, want %+v", m, got.Routes, want)
		}
		if got.Level != exposure.LevelRead {
			t.Errorf("%s: level = %v, want %v", m, got.Level, exposure.LevelRead)
		}
	}
	got, tieErr := ClassifyRequest(tbl, http.MethodGet, "/user/codespaces/secrets/machines")
	if tieErr != nil {
		t.Fatalf("tie: %v", tieErr)
	}
	if want := []Route{{"codespaces", "machines"}, {"codespaces", "secrets"}}; !slices.Equal(got.Routes, want) {
		t.Errorf("tie routes = %+v, want %+v", got.Routes, want)
	}
	var unmatched *authreq.UnmatchedRequestError
	if _, uErr := ClassifyRequest(tbl, http.MethodGet, "/b/x/"); !errors.As(uErr, &unmatched) {
		t.Errorf("unmatched err = %v, want UnmatchedRequestError", uErr)
	}
}

func TestClassifyRequest_DotSegmentsFailClosed(t *testing.T) {
	t.Parallel()

	tbl := shadowTable(t)
	denied := []string{
		"/repos/o/r/branches/x/../../../../../users/octocat",
		"/repos/o/r/branches/x/%2e%2e/%2E%2e/%2e%2e/%2e%2e/%2e%2e/users/octocat",
		"/repos/o/r/branches/x/./y",
		"/repos/o/r/branches/x/.%2e/y",
	}
	for _, path := range denied {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := ClassifyRequest(tbl, http.MethodGet, path)
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("ClassifyRequest(%q) err = %v, want ErrUnclassifiable", path, err)
			}
			if _, ok := errors.AsType[*authreq.UnmatchedRequestError](err); ok {
				t.Fatalf("ClassifyRequest(%q) err = %v, a dot segment must not be an unmatched route", path, err)
			}
		})
	}

	for _, path := range []string{"/repos/o/r/contents/v1.2/a...b/file.go", "/repos/o/r/contents/.../x"} {
		t.Run("dots inside a segment: "+path, func(t *testing.T) {
			t.Parallel()
			got, err := ClassifyRequest(tbl, http.MethodGet, path)
			if err != nil {
				t.Fatalf("ClassifyRequest(%q) err = %v, want nil", path, err)
			}
			if want := []Route{{"repos", "contents"}}; !slices.Equal(got.Routes, want) {
				t.Fatalf("routes = %+v, want %+v", got.Routes, want)
			}
		})
	}
}
