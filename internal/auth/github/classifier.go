package github

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// graphQLPath is GitHub's GraphQL endpoint path. GraphQL is unsupported, so the
// provider denies any request to it.
const graphQLPath = "/graphql"

// readOnlyPOSTPaths are the documented POST endpoints that render content
// without mutating any resource (Markdown rendering); they classify as Read.
var readOnlyPOSTPaths = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"/markdown":     true,
	"/markdown/raw": true,
}

// Access is the classification of a request: the GitHub category/subcategory it
// belongs to and the access level it requires.
type Access struct {
	Route Route
	Level exposure.Level
}

// IsGraphQLEndpoint reports whether path targets GitHub's GraphQL endpoint,
// tolerant of trailing slashes. GraphQL is not supported; the caller denies it.
func IsGraphQLEndpoint(path string) bool {
	return strings.TrimRight(path, "/") == graphQLPath
}

// RequiredLevel returns the read/write level a REST request requires, from the
// HTTP method (honoring the read-only POST exceptions). Method is upper-cased; an
// unrecognized method fails closed. It needs no table, so the post-response drift
// audit (audit.go) can reuse it.
func RequiredLevel(method, path string) (exposure.Level, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	return methodLevel(method, path)
}

// ClassifyRequest resolves a REST request to its (Route, required Level). It
// derives the level (RequiredLevel) and looks the route up in the table — a route
// absent from the table fails closed (ErrUnclassifiable). Secret-scanning routes
// are protected by the admission guard and the secret-scanning:none baseline.
func ClassifyRequest(t *Table, method, path string) (Access, error) {
	method = strings.ToUpper(strings.TrimSpace(method))

	lvl, err := RequiredLevel(method, path)
	if err != nil {
		return Access{}, err
	}

	// HEAD and OPTIONS are read probes of the same resource a GET would return.
	lookupMethod := method
	if method == http.MethodHead || method == http.MethodOptions {
		lookupMethod = http.MethodGet
	}
	route, ok := t.Lookup(lookupMethod, path)
	if !ok {
		return Access{}, fmt.Errorf("%w: %s %s", ErrUnclassifiable, method, path)
	}
	return Access{Route: route, Level: lvl}, nil
}

// methodLevel maps an HTTP method to its required level, honoring the read-only
// POST exceptions. An unrecognized method fails closed.
func methodLevel(method, path string) (exposure.Level, error) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return exposure.LevelRead, nil
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if method == http.MethodPost && readOnlyPOSTPaths[path] {
			return exposure.LevelRead, nil
		}
		return exposure.LevelWrite, nil
	default:
		return exposure.LevelNone, fmt.Errorf("%w: unrecognized HTTP method %q", ErrUnclassifiable, method)
	}
}
