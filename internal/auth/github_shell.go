package auth

import (
	"encoding/json"
	"io"
	"net/http"
)

// githubUserURL is the GitHub REST endpoint for the authenticated user.
// A var (not const) so tests can point it at an httptest server.
//
//nolint:gochecknoglobals // test-overridable endpoint, like other shell seams.
var githubUserURL = "https://api.github.com/user"

// parseGithubLogin extracts "@<login>" from a /user response, or "" on any
// non-200 / parse failure / empty login.
func parseGithubLogin(status int, body io.Reader) string {
	if status != http.StatusOK {
		return ""
	}
	var u struct {
		Login string `json:"login"`
	}
	if json.NewDecoder(body).Decode(&u) != nil || u.Login == "" {
		return ""
	}

	return "@" + u.Login
}
