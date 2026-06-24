package gcp

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// Classify resolves req to exactly one Discovery method id from idx, or returns
// ErrClassifierUnknownOp on zero or multiple survivors. Deterministic. Pure.
func Classify(idx MethodIndex, req *http.Request) (string, error) {
	method := strings.ToUpper(req.Method)
	path := strings.Trim(req.URL.Path, "/")

	ids := slices.Sorted(maps.Keys(idx)) // deterministic iteration.

	var survivors []string

	for _, id := range ids {
		md := idx[id]
		if !strings.EqualFold(md.HTTPMethod, method) {
			continue
		}

		if matchTemplate(effectiveTemplate(md), path) {
			survivors = append(survivors, id)
		}
	}

	switch len(survivors) {
	case 1:
		return survivors[0], nil
	case 0:
		return "", fmt.Errorf("%w: no method matches %s %s", ErrClassifierUnknownOp, method, req.URL.Path)
	default:
		return "", fmt.Errorf(
			"%w: %d methods match %s %s (ambiguous)",
			ErrClassifierUnknownOp,
			len(survivors),
			method,
			req.URL.Path,
		)
	}
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

// matchTemplate reports whether reqPath matches template anchored, full-segment,
// treating {placeholder} segments as single-segment wildcards. The custom-verb
// (:verb) and literal-verb (/start) discriminators fall out of exact segment
// matching: a template with a trailing /start or :encrypt only matches a request
// carrying that exact suffix.
func matchTemplate(template, reqPath string) bool {
	tSegs := splitSegments(template)
	rSegs := splitSegments(reqPath)

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
