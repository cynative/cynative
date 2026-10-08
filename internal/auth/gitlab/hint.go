package gitlab

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// namespaceLabel is the template segment after projects or groups that takes a numeric ID or an encoded
// namespace path.
const namespaceLabel = "{id}"

// maxNamespaceSegments bounds the fold. A GitLab group has at most 20 ancestors (Group::NUMBER_OF_ANCESTORS_ALLOWED),
// so a project's full path has at most 22 segments: 21 group levels plus the project. A longer fold could only fold
// an endpoint into the namespace.
const maxNamespaceSegments = 22

// Hint suggests operations for a request the gate's table matched to none. It tries the shared candidate rules
// over every documented route and, when they find nothing, the namespace rule. An over-long path gets nothing.
func Hint(d *openapidoc.OperationDocs, v authreq.View) apiref.Hint {
	return hint(d.Routes(), v)
}

// RecognizedHint is Hint over the routes t, the gate's live table, classifies, so it never suggests a route the
// gate would deny as unmatched.
func RecognizedHint(d *openapidoc.OperationDocs, v authreq.View, t *Table) apiref.Hint {
	routes := slices.DeleteFunc(d.Routes(), func(r apiref.Route) bool { return !Recognizes(t, r.Method, r.Template) })
	return hint(routes, v)
}

// hint runs the shared candidate rules over routes and, when they find nothing, the namespace rule.
func hint(routes []apiref.Route, v authreq.View) apiref.Hint {
	if apiref.HintPathTooLong(v.EscapedPath) {
		return apiref.Hint{}
	}
	// The gate looks HEAD and OPTIONS up as GET, so the hint does too.
	method := openapidoc.LookupMethod(v.Method)
	if cands := apiref.Candidates(routes, method, v.EscapedPath); len(cands) > 0 {
		h := apiref.Hint{Candidates: cands}
		if ops := apiref.CandidateOperations(routes, method, v.EscapedPath); len(ops) == 1 {
			h.Operation = ops[0]
		}
		return h
	}
	return namespaceHint(routes, method, v.EscapedPath)
}

// namespaceHint handles the most common GitLab mistake, a project or group path sent unencoded. For a request
// under /api/v4/projects/ or /api/v4/groups/ it folds the first n segments after that word into one %2F-joined
// segment, for n from 2 up, and matches the folded path against the same-method templates whose next segment is
// {id}, up to maxNamespaceSegments. The smallest n with any match wins, so the fold keeps as much of the request's endpoint as it can; that n
// must name exactly one operation, or the rule suggests nothing. It cannot tell a deeper namespace from an
// unknown endpoint, so its sentence is conditional.
func namespaceHint(routes []apiref.Route, method, escapedPath string) apiref.Hint {
	segs := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
	if len(segs) < 5 || segs[0] != apiSegment || segs[1] != "v4" || (segs[2] != "projects" && segs[2] != "groups") {
		return apiref.Hint{}
	}
	var scoped []apiref.Route
	for _, r := range routes {
		tpl := strings.Split(strings.TrimPrefix(r.Template, "/"), "/")
		if strings.EqualFold(r.Method, method) && len(tpl) > 3 && tpl[2] == segs[2] && tpl[3] == namespaceLabel {
			scoped = append(scoped, r)
		}
	}
	rest := segs[3:]
	for n := 2; n <= min(len(rest), maxNamespaceSegments); n++ {
		folded := strings.Join(rest[:n], "%2F")
		path := "/" + strings.Join(append([]string{apiSegment, "v4", segs[2], folded}, rest[n:]...), "/")
		lines, ops := foldMatches(scoped, path)
		if len(ops) == 0 {
			continue
		}
		if len(ops) > 1 {
			return apiref.Hint{}
		}
		return apiref.Hint{
			Candidates: apiref.Bound(lines),
			Operation:  ops[0],
			Note: fmt.Sprintf("If %q is the namespace path, send it as one segment: %q.",
				apiref.Truncate(strings.Join(rest[:n], "/"), apiref.MaxPathEcho),
				apiref.Truncate(folded, apiref.MaxPathEcho)),
		}
	}
	return apiref.Hint{}
}

// foldMatches returns the candidate lines of the routes path fits, and their distinct operations.
func foldMatches(routes []apiref.Route, path string) ([]string, []string) {
	var lines, ops []string
	for _, r := range routes {
		if !apiref.Match(r.Template, path) {
			continue
		}
		lines = append(lines, apiref.RouteLine(r))
		if !slices.Contains(ops, r.Operation) {
			ops = append(ops, r.Operation)
		}
	}
	return lines, ops
}
