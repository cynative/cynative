package authreq

import (
	"net/url"
	"slices"
	"strings"
)

// PathReadings returns every way the server on the far end might segment this
// request's path, wire-faithful reading first: the EscapedPath split on literal
// '/' with each segment then percent-decoded, and the decoded Path split on
// '/'. The second is dropped when it is identical to the first, which is every
// request carrying no percent-encoding.
//
// A gate that segments a path classifies every reading and authorizes the union
// of what they name, because the servers disagree about which reading is
// theirs: Lambda binds a percent-encoded slash inside one segment, S3 decodes
// the path once and only then splits bucket from key, and Google's frontend
// routes the escaped form. Picking one reading authorizes an operation the
// server need not be running.
//
// Each reading drops the leading '/' and keeps every other segment, empty ones
// included, so "/a//b" reads as {"a", "", "b"} and "/" as {""}. An empty path
// reads as "/", which is what net/http writes as the request target for one. A
// segment that fails to unescape is kept as it arrived; decoding cannot then
// introduce a separator.
func (v View) PathReadings() [][]string {
	wire := pathSegments(v.EscapedPath)
	for i, seg := range wire {
		if decoded, err := url.PathUnescape(seg); err == nil {
			wire[i] = decoded
		}
	}

	decoded := pathSegments(v.Path)
	if slices.Equal(wire, decoded) {
		return [][]string{wire}
	}

	return [][]string{wire, decoded}
}

// pathSegments splits a request path on '/', dropping the leading one. An empty
// path is the "/" the wire carries for it.
func pathSegments(p string) []string {
	if p == "" {
		p = "/"
	}

	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}
