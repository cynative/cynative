package gcp

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// Classify resolves v to exactly one Discovery method id from idx, or returns
// ErrClassifierUnknownOp on zero or multiple survivors. Every reading of the
// path is classified and the survivors are pooled: Google's frontend routes the
// path as sent, so a percent-encoded slash stays inside its segment there while
// the decoded path splits on it, and a request whose readings name different
// methods is an ambiguity the gate denies. Deterministic. Pure.
func Classify(idx MethodIndex, v authreq.View) (string, error) {
	method := strings.ToUpper(v.Method)

	keys := slices.Sorted(maps.Keys(idx)) // deterministic iteration.

	seen := map[string]bool{}

	var survivors []string

	for _, segs := range v.PathReadings() {
		survivors = appendSurvivors(survivors, seen, idx, keys, method, trimEmptyEdges(segs))
	}

	switch len(survivors) {
	case 1:
		return survivors[0], nil
	case 0:
		return "", fmt.Errorf("%w: no method matches %s %s", ErrClassifierUnknownOp, method, v.EscapedPath)
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

// appendSurvivors appends every method in idx whose template matches reqSegs and
// that no earlier reading already named. The authoritative Discovery id (md.ID)
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
	for _, key := range keys {
		md := idx[key]
		if !strings.EqualFold(md.HTTPMethod, method) {
			continue
		}

		if matchTemplate(effectiveTemplate(md), reqSegs) && !seen[md.ID] {
			seen[md.ID] = true
			survivors = append(survivors, md.ID)
		}
	}

	return survivors
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

// matchTemplate reports whether rSegs matches template anchored, full-segment,
// treating {placeholder} segments as single-segment wildcards. The custom-verb
// (:verb) and literal-verb (/start) discriminators fall out of exact segment
// matching: a template with a trailing /start or :encrypt only matches a request
// carrying that exact suffix.
func matchTemplate(template string, rSegs []string) bool {
	tSegs := splitSegments(template)

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
