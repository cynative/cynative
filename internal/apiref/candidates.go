package apiref

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// maxEditDistance is the largest edit distance between a request's literal
// segment and a template's that still counts as a near miss.
const maxEditDistance = 2

// maxHintPathBytes is the longest escaped request path a hint will inspect.
// The path is model-supplied, so a longer one yields no candidates rather than
// work proportional to its length for every route.
const maxHintPathBytes = 2048

// Route is one documented operation's method and path template, as a
// candidate source for hints. Templates use {Label} for one segment and
// {Label+} for a greedy tail; a "?" and anything after it is ignored.
type Route struct{ Operation, Method, Template string }

// Candidates returns at most MaxCandidates "Name (METHOD /template)" strings:
// first the routes whose template matches path under another method; if none,
// the same-method routes whose template differs from path in exactly one
// literal segment by an edit distance of at most two. More qualifying routes
// than MaxCandidates, or none, yield nil. Output is sorted and deduplicated.
func Candidates(routes []Route, method, escapedPath string) []string {
	hits := candidateRoutes(routes, method, escapedPath)
	out := make([]string, 0, len(hits))
	for _, r := range hits {
		out = append(out, r.Operation+" ("+strings.ToUpper(r.Method)+" "+r.Template+")")
	}
	return Bound(out)
}

// CandidateOperations returns the operation names behind Candidates' result,
// in the same order.
func CandidateOperations(routes []Route, method, escapedPath string) []string {
	hits := candidateRoutes(routes, method, escapedPath)
	out := make([]string, 0, len(hits))
	for _, r := range hits {
		out = append(out, r.Operation)
	}
	return Bound(out)
}

// Bound sorts and deduplicates candidate lines and returns nil when there are
// none or more than MaxCandidates. Candidates and connector-specific hint
// rules share it.
func Bound(out []string) []string {
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 || len(out) > MaxCandidates {
		return nil
	}
	return out
}

func candidateRoutes(routes []Route, method, escapedPath string) []Route {
	if len(escapedPath) > maxHintPathBytes {
		return nil
	}
	segs := splitPath(escapedPath)
	var other, near []Route
	for _, r := range routes {
		tpl := splitPath(templatePath(r.Template))
		sameMethod := strings.EqualFold(r.Method, method)
		switch {
		case !sameMethod && matches(tpl, segs):
			other = append(other, r)
		case sameMethod && nearMiss(tpl, segs):
			near = append(near, r)
		}
	}
	if len(other) > 0 {
		return other
	}
	return near
}

func templatePath(tpl string) string {
	path, _, _ := strings.Cut(tpl, "?")
	return path
}

// splitPath splits on "/" after dropping the leading slash: "/" yields [""].
func splitPath(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func isLabel(seg string) bool { return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") }

func isGreedy(seg string) bool { return isLabel(seg) && strings.HasSuffix(seg, "+}") }

func matches(tpl, segs []string) bool {
	for i, t := range tpl {
		if isGreedy(t) {
			return matchGreedy(tpl[i+1:], segs, i)
		}
		if i >= len(segs) || !segMatches(t, segs[i]) {
			return false
		}
	}
	return len(tpl) == len(segs)
}

// matchGreedy matches a greedy label starting at path index i, followed by the
// template segments in suffix. The label takes every segment the suffix leaves
// and needs at least one; a single empty segment does not count, as in the gate.
func matchGreedy(suffix, segs []string, i int) bool {
	end := len(segs) - len(suffix)
	if end <= i || (end == i+1 && segs[i] == "") {
		return false
	}
	for j, t := range suffix {
		if !segMatches(t, segs[end+j]) {
			return false
		}
	}
	return true
}

func segMatches(t, s string) bool {
	if isLabel(t) {
		return s != ""
	}
	return t == s
}

// nearMiss reports whether tpl and segs have the same length, no greedy label,
// and exactly one mismatching literal segment within maxEditDistance.
func nearMiss(tpl, segs []string) bool {
	if len(tpl) != len(segs) {
		return false
	}
	misses := 0
	for i, t := range tpl {
		if isGreedy(t) {
			return false
		}
		if segMatches(t, segs[i]) {
			continue
		}
		if isLabel(t) || !withinEditDistance(t, segs[i]) {
			return false
		}
		misses++
	}
	return misses == 1
}

// withinEditDistance reports whether a and b differ by at most maxEditDistance
// edits. It rejects on rune counts first, so the quadratic work only runs on
// strings of nearly the same length.
func withinEditDistance(a, b string) bool {
	ca, cb := utf8.RuneCountInString(a), utf8.RuneCountInString(b)
	if ca-cb > maxEditDistance || cb-ca > maxEditDistance {
		return false
	}
	return editDistance(a, b) <= maxEditDistance
}

// editDistance is the Levenshtein distance between a and b, by rune.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev, cur := make([]int, len(rb)+1), make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
