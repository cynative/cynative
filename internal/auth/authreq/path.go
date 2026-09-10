package authreq

import (
	"slices"
	"strings"
)

// PathReadings returns every way the server on the far end might segment this
// request's path. The wire reading is the path exactly as sent, split only on
// the separators the wire carries, and nothing in it is percent-decoded,
// because decoding after the split turns an encoded byte back into structure
// the server never saw. Two proven instances: a '/' that no gate's server saw
// as a separator, and a ':' that Google's custom-verb routing never saw. The
// decoded reading is the decoded Path split on '/'. The second is dropped when
// it is identical to the first, which is every request carrying no
// percent-encoding.
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
// reads as "/", which is what net/http writes as the request target for one.
func (v View) PathReadings() [][]string {
	wire := pathSegments(v.EscapedPath)
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
