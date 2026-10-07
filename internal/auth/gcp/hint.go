package gcp

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// HintNote is the sentence every gcp unmatched-request message carries after its candidates.
const HintNote = "Without model, the lookup searches the API's vN versions and may ask for model when several " +
	`define the method; pass "model" with a version label to read any other version, such as a beta.`

// Hint suggests methods for a request the classifier matched to none, from the gate's own method index for the
// service, which methods returns. An over-long path gets no candidates and never reads the index. Only routes whose
// last segment carries a custom verb exactly when the request's does are matched, as the classifier requires; the
// verb is then split into its own segment on both sides, so the shared near-miss rule can compare it. Each
// candidate shows the route that matched, so two versions' routes for one method id stay apart.
func Hint(methods func() MethodIndex, v authreq.View) apiref.Hint {
	h := apiref.Hint{Note: HintNote}
	if apiref.HintPathTooLong(v.EscapedPath) {
		return h
	}
	// The classifier never lets a label take a segment holding ":", so a colon before the last segment (an
	// unencoded domain-scoped project, example.com:proj) has no near miss worth naming.
	segs := strings.Split(strings.TrimPrefix(v.EscapedPath, "/"), "/")
	if slices.ContainsFunc(segs[:len(segs)-1], func(s string) bool { return strings.Contains(s, ":") }) {
		return h
	}
	idx := methods()
	verb := hasVerb(v.EscapedPath)
	var shown, split []apiref.Route
	for _, key := range slices.Sorted(maps.Keys(idx)) {
		md := idx[key]
		tpl := "/" + effectiveTemplate(md)
		if hasVerb(tpl) != verb {
			continue
		}
		// The route's index stands in for its operation, so the matcher counts and returns routes, not ids.
		split = append(split, apiref.Route{
			Operation: strconv.Itoa(len(shown)), Method: md.HTTPMethod, Template: splitVerb(tpl),
		})
		shown = append(shown, apiref.Route{Operation: md.ID, Method: md.HTTPMethod, Template: tpl})
	}
	var lines, ops []string
	for _, key := range apiref.CandidateOperations(split, v.Method, splitVerb(v.EscapedPath)) {
		i, _ := strconv.Atoi(key) // Every key is an index this function wrote.
		lines = append(lines, apiref.RouteLine(shown[i]))
		if !slices.Contains(ops, shown[i].Operation) {
			ops = append(ops, shown[i].Operation)
		}
	}
	h.Candidates = apiref.Bound(lines)
	if len(ops) == 1 {
		h.Operation = ops[0]
	}
	return h
}

// hasVerb reports a ':' in the last segment of a path or template.
func hasVerb(p string) bool {
	return strings.Contains(p[strings.LastIndex(p, "/")+1:], ":")
}

// splitVerb turns the first ':' of the last path segment into "/:", so "{endpointsId}:predict" and "123:predict"
// both read as two segments.
func splitVerb(p string) string {
	last := strings.LastIndex(p, "/") + 1
	if i := strings.Index(p[last:], ":"); i >= 0 {
		return p[:last+i] + "/" + p[last+i:]
	}
	return p
}
