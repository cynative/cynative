package gitlab

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

func TestIsGraphQLEndpoint(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/api/graphql":             true,
		"/api/graphql/":            true,
		"/api/%67raphql":           true, // encoded 'g'
		"/api/graphql.json":        true, // Rails .:format
		"/gitlab/api/graphql":      true, // defensive: deny GraphQL even on a trailing-segment form (REST subpath installs remain unsupported)
		"/api/v4/projects":         false,
		"/api/graphql/foo":         false,
		"/files/x%2Fapi%2Fgraphql": false, // encoded slash stays one segment
		"/api/%zz":                 false, // invalid percent-encoding fails the segment match.
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

func TestRequiredLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		method, path   string
		wantLevel      exposure.Level
		wantUnclassErr bool
	}{
		{"GET is read", http.MethodGet, "/api/v4/projects", exposure.LevelRead, false},
		{"HEAD is read", http.MethodHead, "/api/v4/projects", exposure.LevelRead, false},
		{"OPTIONS is read", http.MethodOptions, "/api/v4/projects", exposure.LevelRead, false},
		{"POST is write", http.MethodPost, "/api/v4/projects", exposure.LevelWrite, false},
		{"PUT is write", http.MethodPut, "/api/v4/projects/1", exposure.LevelWrite, false},
		{"PATCH is write", http.MethodPatch, "/api/v4/projects/1", exposure.LevelWrite, false},
		{"DELETE is write", http.MethodDelete, "/api/v4/projects/1", exposure.LevelWrite, false},
		{
			"POST /api/v4/markdown is read",
			http.MethodPost,
			"/api/v4/markdown",
			exposure.LevelRead,
			false,
		},
		{
			"POST non-markdown is write",
			http.MethodPost,
			"/api/v4/projects",
			exposure.LevelWrite,
			false,
		},
		{"POST markdown subpath suffix is read", http.MethodPost, "/gitlab/api/v4/markdown", exposure.LevelRead, false},
		{"POST markdown encoded endpoint is read", http.MethodPost, "/api/v4/%6Darkdown", exposure.LevelRead, false},
		{"POST markdown format suffix is read", http.MethodPost, "/api/v4/markdown.json", exposure.LevelRead, false},
		// Percent-encoded slashes (%2F) must NOT forge the read-only markdown suffix:
		// a repository-files create whose escaped path ends with "%2Fmarkdown" stays
		// one segment and is a write. (Callers pass EscapedPath, not the decoded path.)
		{
			"POST encoded-slash forged markdown is write", http.MethodPost,
			"/api/v4/projects/1/repository/files/x%2Fapi%2Fv4%2Fmarkdown", exposure.LevelWrite, false,
		},
		// Short path (fewer segments than the endpoint) and an invalid-percent segment
		// both safely fall through to the method switch.
		{"POST short path is write", http.MethodPost, "/foo", exposure.LevelWrite, false},
		{"GET invalid percent path is read", http.MethodGet, "/api/%zz", exposure.LevelRead, false},
		{"unknown method is unclassifiable", "FROBNICATE", "/api/v4/x", exposure.LevelNone, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lvl, err := RequiredLevel(c.method, c.path)
			if lvl != c.wantLevel {
				t.Errorf(
					"RequiredLevel(%q, %q) = %v, want %v",
					c.method,
					c.path,
					lvl,
					c.wantLevel,
				)
			}
			if c.wantUnclassErr {
				if !errors.Is(err, ErrUnclassifiable) {
					t.Errorf(
						"RequiredLevel(%q, %q) err = %v, want ErrUnclassifiable",
						c.method,
						c.path,
						err,
					)
				}
			} else if err != nil {
				t.Errorf(
					"RequiredLevel(%q, %q) unexpected err %v",
					c.method,
					c.path,
					err,
				)
			}
		})
	}
}

func TestClassifyRequest(t *testing.T) {
	t.Parallel()

	// Build a small table for testing.
	raw := []byte(`openapi: "3.0.0"
paths:
  /api/v4/projects:
    get:
      tags: ["Projects"]
    post:
      tags: ["Projects"]
  /api/v4/projects/{id}/issues:
    get:
      tags: ["Issues"]
    post:
      tags: ["Issues"]
`)
	tbl, tableErr := DistillOpenAPI(raw)
	if tableErr != nil {
		t.Fatalf("DistillOpenAPI failed: %v", tableErr)
	}

	cases := []struct {
		name           string
		method, path   string
		wantCategory   string
		wantLevel      exposure.Level
		wantUnclassErr bool
	}{
		{
			"POST projects is write",
			http.MethodPost,
			"/api/v4/projects",
			"projects",
			exposure.LevelWrite,
			false,
		},
		{
			"GET projects is read",
			http.MethodGet,
			"/api/v4/projects",
			"projects",
			exposure.LevelRead,
			false,
		},
		{
			"HEAD issues looks up as GET with read level",
			http.MethodHead,
			"/api/v4/projects/1/issues",
			"issues",
			exposure.LevelRead,
			false,
		},
		{
			"OPTIONS issues looks up as GET with read level",
			http.MethodOptions,
			"/api/v4/projects/1/issues",
			"issues",
			exposure.LevelRead,
			false,
		},
		{
			"unknown route is unclassifiable",
			http.MethodGet,
			"/api/v4/unknown/route",
			"",
			exposure.LevelNone,
			true,
		},
		{
			"unknown method through ClassifyRequest is unclassifiable",
			"FROBNICATE",
			"/api/v4/projects",
			"",
			exposure.LevelNone,
			true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			acc, classifyErr := ClassifyRequest(tbl, c.method, c.path)
			checkClassifyResult(t, c, acc, classifyErr)
		})
	}
}

func checkClassifyResult(
	t *testing.T,
	c struct {
		name           string
		method, path   string
		wantCategory   string
		wantLevel      exposure.Level
		wantUnclassErr bool
	},
	acc Access,
	classifyErr error,
) {
	if c.wantUnclassErr {
		if !errors.Is(classifyErr, ErrUnclassifiable) {
			t.Errorf(
				"ClassifyRequest(%q, %q) err = %v, want ErrUnclassifiable",
				c.method,
				c.path,
				classifyErr,
			)
		}
		return
	}

	if classifyErr != nil {
		t.Errorf(
			"ClassifyRequest(%q, %q) unexpected err %v",
			c.method,
			c.path,
			classifyErr,
		)
		return
	}

	if acc.Category != c.wantCategory {
		t.Errorf(
			"ClassifyRequest(%q, %q).Category = %q, want %q",
			c.method,
			c.path,
			acc.Category,
			c.wantCategory,
		)
	}

	if acc.Level != c.wantLevel {
		t.Errorf(
			"ClassifyRequest(%q, %q).Level = %v, want %v",
			c.method,
			c.path,
			acc.Level,
			c.wantLevel,
		)
	}
}
