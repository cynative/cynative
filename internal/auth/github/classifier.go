package github

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cynative/cynative/internal/auth/authreq"
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

// Access is the classification of a request: every GitHub category/subcategory
// it may run as (at least one) and the access level it requires.
type Access struct {
	Routes []Route
	Level  exposure.Level
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

// ClassifyRequest resolves a REST request to the routes it may run as and its
// required Level. It derives the level (RequiredLevel) and looks the route set up
// in the table; a request that matches no route fails closed (ErrUnclassifiable).
// Secret-scanning routes are protected by the admission guard and the
// secret-scanning:none baseline.
func ClassifyRequest(t *Table, method, path string) (Access, error) {
	method = strings.ToUpper(strings.TrimSpace(method))

	lvl, err := RequiredLevel(method, path)
	if err != nil {
		return Access{}, err
	}

	// GitHub resolves "." and ".." segments before it routes, so the path as sent can name a different operation
	// from the one served. This is not an unmatched route, so it carries no api_reference hint.
	if authreq.HasDotSegment(path) {
		return Access{}, fmt.Errorf("%w: dot segment in %s %s", ErrUnclassifiable, method, path)
	}

	// HEAD and OPTIONS are read probes of the same resource a GET would return.
	lookupMethod := method
	if method == http.MethodHead || method == http.MethodOptions {
		lookupMethod = http.MethodGet
	}
	routes := t.Lookup(lookupMethod, path)
	if routes == nil {
		return Access{}, &authreq.UnmatchedRequestError{Err: fmt.Errorf("%w: %s %s", ErrUnclassifiable, method, path)}
	}
	return Access{Routes: routes, Level: lvl}, nil
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
