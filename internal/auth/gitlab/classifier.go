package gitlab

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// graphQLSegments are the trailing path segments of GitLab's GraphQL endpoint.
// Requests to this endpoint are detected for denial — GraphQL is not supported.
// Matched by trailing segments so a subpath-mounted instance (e.g.
// /gitlab/api/graphql) is also caught.
//
//nolint:gochecknoglobals // stateless endpoint-segment list.
var graphQLSegments = []string{"api", "graphql"}

// markdownSegments are the trailing path segments of the documented POST endpoint
// that renders content without mutating any resource; it classifies as Read.
//
//nolint:gochecknoglobals // stateless endpoint-segment list.
var markdownSegments = []string{"api", "v4", "markdown"}

// IsGraphQLEndpoint reports whether path targets GitLab's GraphQL endpoint
// (/api/graphql), tolerant of a trailing slash and evasion-resistant via the same
// per-segment percent-decode and Rails ".:format" handling as REST routing.
// GraphQL is not supported; the caller denies it.
func IsGraphQLEndpoint(path string) bool {
	return pathEndsWith(strings.TrimRight(path, "/"), graphQLSegments)
}

// pathEndsWith reports whether the request path's trailing segments equal want.
// path is the raw EscapedPath; it is split on literal '/' FIRST and each segment
// is then percent-decoded individually. This catches an encoded endpoint letter
// (e.g. /api/%67raphql decodes to /api/graphql) while keeping an encoded slash
// (%2F) WITHIN a single segment so it cannot forge a multi-segment endpoint suffix
// (e.g. .../files/x%2Fapi%2Fv4%2Fmarkdown stays one segment, never matching). An
// optional Rails ".:format" suffix on the LAST segment is stripped, so a
// format-suffixed endpoint (e.g. /api/graphql.json) still matches the endpoint
// GitLab routes it to.
func pathEndsWith(path string, want []string) bool {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < len(want) {
		return false
	}

	tail := segs[len(segs)-len(want):]
	for i, w := range want {
		decoded, err := url.PathUnescape(tail[i])
		if err != nil {
			return false
		}
		if i == len(want)-1 {
			decoded = stripFormatSuffix(decoded) // Rails optional ".:format".
		}
		if decoded != w {
			return false
		}
	}

	return true
}

// stripFormatSuffix removes a trailing Rails ".:format" suffix (the part after the
// last '.') from a path segment, so "graphql.json" matches the "graphql" endpoint.
func stripFormatSuffix(seg string) string {
	if i := strings.LastIndexByte(seg, '.'); i >= 0 {
		return seg[:i]
	}

	return seg
}

// Access is the classification of a request: its category and required level.
type Access struct {
	Category string
	Level    exposure.Level
}

// RequiredLevel returns the read/write level a REST request requires from the
// HTTP method, honoring the read-only POST /api/v4/markdown exception. Method is
// upper-cased; an unrecognized method fails closed.
func RequiredLevel(method, escapedPath string) (exposure.Level, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return exposure.LevelRead, nil
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if method == http.MethodPost && pathEndsWith(escapedPath, markdownSegments) {
			return exposure.LevelRead, nil
		}
		return exposure.LevelWrite, nil
	default:
		return exposure.LevelNone, fmt.Errorf("%w: unrecognized HTTP method %q", ErrUnclassifiable, method)
	}
}

// ClassifyRequest resolves a REST request to its (Category, required Level). A
// route absent from the table fails closed (ErrUnclassifiable). HEAD/OPTIONS look
// up as GET (read probes of the same resource).
func ClassifyRequest(t *Table, method, escapedPath string) (Access, error) {
	lvl, err := RequiredLevel(method, escapedPath)
	if err != nil {
		return Access{}, err
	}
	lookupMethod := strings.ToUpper(strings.TrimSpace(method))
	if lookupMethod == http.MethodHead || lookupMethod == http.MethodOptions {
		lookupMethod = http.MethodGet
	}
	route, ok := t.Lookup(lookupMethod, escapedPath)
	if !ok {
		return Access{}, fmt.Errorf("%w: %s %s", ErrUnclassifiable, method, escapedPath)
	}
	return Access{Category: route.Category, Level: lvl}, nil
}
