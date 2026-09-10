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
// A reading that ends in an empty segment also appears with that one trailing
// empty segment dropped. A trailing slash is a separator some servers ignore,
// and S3 answers a path-style GET /bucket/ with the bucket listing because the
// key binds to the empty string rather than the bucket name absorbing the
// slash. Only the one trailing empty segment goes: a second one still names a
// real segment, so /bucket// keeps addressing the object literally named "/".
// A one-element reading is never trimmed, so the root path "/" stays the
// single reading {""} and never grows a second; offering a reading that would
// name nothing costs nothing, since a gate only ever unions or intersects what
// the readings name.
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
	readings := appendReading(nil, pathSegments(v.EscapedPath))
	readings = appendReading(readings, pathSegments(v.Path))

	// Offer the trailing-slash-dropped form of each reading gathered so far.
	// original pins the count before this loop can grow it, so a reading this
	// loop appends is never itself trimmed again.
	original := len(readings)
	for _, r := range readings[:original] {
		readings = appendReading(readings, dropTrailingEmpty(r))
	}

	return readings
}

// appendReading appends segs to readings unless readings already holds an
// identical reading.
func appendReading(readings [][]string, segs []string) [][]string {
	for _, r := range readings {
		if slices.Equal(r, segs) {
			return readings
		}
	}

	return append(readings, segs)
}

// dropTrailingEmpty drops the one empty segment a single trailing '/' leaves.
// It never trims a reading down to nothing, so a one-element reading such as
// the root's {""} comes back unchanged.
func dropTrailingEmpty(segs []string) []string {
	if len(segs) > 1 && segs[len(segs)-1] == "" {
		return segs[:len(segs)-1]
	}

	return segs
}

// pathSegments splits a request path on '/', dropping the leading one. An empty
// path is the "/" the wire carries for it.
func pathSegments(p string) []string {
	if p == "" {
		p = "/"
	}

	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}
