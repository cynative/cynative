package gcp

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// Classify resolves v to exactly one Discovery method id from idx, or returns
// ErrClassifierUnknownOp on zero or multiple survivors; zero survivors is also
// marked *authreq.UnmatchedRequestError. Every reading of the path is
// classified and the survivors are pooled: Google's frontend routes the path as
// sent, so a percent-encoded slash stays inside its segment there while the
// decoded path splits on it, and a request whose readings name different
// methods is an ambiguity the gate denies. Within one reading the most specific
// template wins when every match spells its literals exactly (see
// appendSurvivors). Deterministic. Pure.
func Classify(idx MethodIndex, v authreq.View) (string, error) {
	return classify(idx, v, v.PathReadings())
}

// ClassifyAsSent is [Classify] over the wire reading alone, for a service whose
// server routes the path exactly as sent. Cloud Storage's JSON API is one: GET
// .../o/x%2Facl reads the object named x/acl, while the decoded reading names
// the object ACL list, and pooling both readings would deny the object read as
// ambiguous.
func ClassifyAsSent(idx MethodIndex, v authreq.View) (string, error) {
	return classify(idx, v, v.WireReadings())
}

func classify(idx MethodIndex, v authreq.View, readings [][]string) (string, error) {
	method := strings.ToUpper(v.Method)

	keys := slices.Sorted(maps.Keys(idx)) // deterministic iteration.

	seen := map[string]bool{}

	var survivors []string

	for _, segs := range readings {
		survivors = appendSurvivors(survivors, seen, idx, keys, method, trimEmptyEdges(segs))
	}

	switch len(survivors) {
	case 1:
		return survivors[0], nil
	case 0:
		// Only a miss is marked: the unmatched-request hint can help it, while an ambiguous match already named
		// several methods.
		return "", &authreq.UnmatchedRequestError{
			Err: fmt.Errorf("%w: no method matches %s %s", ErrClassifierUnknownOp, method, v.EscapedPath),
		}
	default:
		return "", fmt.Errorf(
			"%w: %d methods match %s %s (ambiguous)",
			ErrClassifierUnknownOp,
			len(survivors),
			method,
			v.EscapedPath,
		)
	}
}

// appendSurvivors appends the methods in idx that win reqSegs and that no
// earlier reading already named. Among the methods whose template matches, only
// the most specific win (see moreSpecific). The ranking applies only when every
// match spells its literals exactly as the request does: a template literal
// matches up to case here, but the path matcher moreSpecific follows looks
// literals up exactly, so for GET .../sslPolicies/listavailablefeatures it never
// sees listAvailableFeatures and routes to {sslPolicy}. Ranking such a match
// could pick the method the server did not, so every match is kept and two
// distinct methods stay ambiguous. A literal that matched only up to case
// disables the ranking even on a losing match: the gate keeps the rule
// conservative rather than modeling which matches the server would skip. The
// authoritative Discovery id (md.ID)
// is used, never the map key: the multi-version merge may store a method under a
// disambiguated key when its id collides with a sibling version (see
// mergeServiceDocs). Deduping by id keeps two index entries that resolve to the
// same operation one survivor rather than a false ambiguity.
func appendSurvivors(
	survivors []string,
	seen map[string]bool,
	idx MethodIndex,
	keys []string,
	method string,
	reqSegs []string,
) []string {
	var (
		best    []string
		winners []string
		matched []string
		folded  bool
	)

	for _, key := range keys {
		md := idx[key]
		if !strings.EqualFold(md.HTTPMethod, method) {
			continue
		}

		tSegs := splitSegments(effectiveTemplate(md))
		if !matchTemplate(tSegs, reqSegs) {
			continue
		}

		matched = append(matched, md.ID)
		folded = folded || !literalsExact(tSegs, reqSegs)

		rank := 1
		if winners != nil {
			rank = moreSpecific(tSegs, best)
		}

		switch {
		case rank > 0:
			best, winners = tSegs, []string{md.ID}
		case rank == 0:
			winners = append(winners, md.ID)
		}
	}

	if folded {
		winners = matched
	}

	for _, id := range winners {
		if !seen[id] {
			seen[id] = true
			survivors = append(survivors, id)
		}
	}

	return survivors
}

// moreSpecific compares two templates that match the same request, so they have
// the same length. At the first segment where one is a literal and the other a
// placeholder, the literal wins: it returns 1 when a wins there, -1 when b does,
// and 0 when no segment tells them apart. This is the precedence of the path
// matcher in grpc-httpjson-transcoding, the open-source HTTP-to-gRPC
// transcoder for Google's HTTP rules (PathMatcherNode::LookupPath tries the
// exact literal child before the {param} child and backtracks only when that
// subtree has no match), so a literal last segment such as
// sslPolicies/listAvailableFeatures routes to its own method, not to the
// sibling get's {sslPolicy}. A custom verb does not count: two segments that
// match the same request carry the same verb, and only the base is compared.
func moreSpecific(a, b []string) int {
	for i := range a {
		aLit, bLit := !isPlaceholder(segmentBase(a[i])), !isPlaceholder(segmentBase(b[i]))
		if aLit != bLit {
			if aLit {
				return 1
			}

			return -1
		}
	}

	return 0
}

// literalsExact reports whether every literal segment of tSegs is spelled in
// rSegs exactly, not only up to case. The custom verb is left out because
// segmentEqual already compares it exactly.
func literalsExact(tSegs, rSegs []string) bool {
	for i, ts := range tSegs {
		if base := segmentBase(ts); !isPlaceholder(base) && base != segmentBase(rSegs[i]) {
			return false
		}
	}

	return true
}

// segmentBase returns a template segment without its custom verb.
func segmentBase(seg string) string {
	base, _, _ := strings.Cut(seg, ":")

	return base
}

// trimEmptyEdges drops the empty segments a leading or trailing '/' leaves, so a
// reading lines up with the templates, which carry neither. It is the segment
// form of the [strings.Trim] the classifier used to apply to the whole path.
func trimEmptyEdges(segs []string) []string {
	for len(segs) > 0 && segs[0] == "" {
		segs = segs[1:]
	}

	for len(segs) > 0 && segs[len(segs)-1] == "" {
		segs = segs[:len(segs)-1]
	}

	return segs
}

// effectiveTemplate returns the full request-path template: the servicePath
// prefix joined with the method's flatPath (falling back to servicePath+path for
// storage v1, which omits flatPath). Discovery flatPath/path are RELATIVE to
// servicePath, so the servicePath MUST be prepended to match the real request
// path (e.g. /compute/v1/projects/{project}/zones/{zone}/instances).
func effectiveTemplate(md MethodDescriptor) string {
	rel := md.FlatPath
	if rel == "" {
		rel = md.Path
	}

	return strings.Trim(strings.TrimSuffix(md.ServicePath, "/")+"/"+strings.TrimPrefix(rel, "/"), "/")
}

// matchTemplate reports whether rSegs matches tSegs anchored, full-segment,
// treating {placeholder} segments as single-segment wildcards. The custom-verb
// (:verb) and literal-verb (/start) discriminators fall out of segment
// matching: a template with a trailing /start or :encrypt only matches a request
// carrying that suffix (the verb exactly, the literal up to case).
func matchTemplate(tSegs, rSegs []string) bool {
	if len(tSegs) != len(rSegs) {
		return false
	}

	for i, ts := range tSegs {
		if isPlaceholder(ts) {
			// A bare placeholder is a single-segment wildcard, but must NOT swallow
			// a custom verb: a request segment carrying a ":verb" only matches a
			// template segment that declares that verb (handled by segmentEqual).
			if strings.Contains(rSegs[i], ":") {
				return false
			}

			continue
		}

		if !segmentEqual(ts, rSegs[i]) {
			return false
		}
	}

	return true
}

func splitSegments(p string) []string {
	if p == "" {
		return nil
	}

	return strings.Split(p, "/")
}

func isPlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// segmentEqual compares a template segment to a request segment, accounting for
// a trailing colon custom-verb on the final segment ("{resource}:getIamPolicy"
// vs the literal verb) by matching the literal verb suffix exactly.
func segmentEqual(tSeg, rSeg string) bool {
	if strings.Contains(tSeg, ":") {
		tBase, tVerb, _ := strings.Cut(tSeg, ":")
		rBase, rVerb, _ := strings.Cut(rSeg, ":")

		if tVerb != rVerb {
			return false
		}

		return isPlaceholder(tBase) || strings.EqualFold(tBase, rBase)
	}

	return strings.EqualFold(tSeg, rSeg)
}
