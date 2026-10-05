package github

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Route is the GitHub-authored classification of an operation.
type Route struct {
	Category    string `json:"c"`
	Subcategory string `json:"s"`
}

// Templ is one distilled path template plus its route, pre-split into segments.
type Templ struct {
	Segments []string `json:"p"` // template segments; a "{...}" segment is a parameter.
	Route    Route    `json:"r"`
}

// Table maps (method, concrete path) to a Route. It is built from the public
// OpenAPI and is safe for concurrent reads (immutable after construction).
type Table struct {
	// byMethod indexes templates by upper-case method.
	byMethod map[string][]Templ
	// multiSegment is the set of parameter names (without braces) that carry
	// x-multi-segment:true in the GitHub OpenAPI. These params may contain "/"
	// and span segments wherever they sit in a template (e.g. "path", "basehead");
	// a last one also takes zero segments.
	multiSegment map[string]bool
}

// tableWire is the on-disk/cache serialization of a Table.
type tableWire struct {
	ByMethod     map[string][]Templ `json:"m"`
	MultiSegment map[string]bool    `json:"ms,omitempty"`
}

// xGitHub is the per-operation vendor extension we read.
type xGitHub struct {
	Category    string `json:"category"`
	Subcategory string `json:"subcategory"`
}

// openAPIDoc is the minimal slice of the OpenAPI we read: paths → key → raw
// operation. Operation values are kept raw so a non-method path-item key (a
// future "$ref"/"summary" string, etc.) is skipped without failing the whole
// parse — robustness over strictness.
type openAPIDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// httpMethods is the set of OpenAPI keys under a path that are HTTP operations
// (path items also carry "parameters", "summary", etc., which are not methods).
var httpMethods = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"get": true, "head": true, "post": true, "put": true, "patch": true, "delete": true, "options": true,
}

// DistillOpenAPI parses the bundled GitHub OpenAPI and reduces it to a routing
// Table of (method, path-template) → category/subcategory. It fails closed on
// invalid JSON or an empty operation set.
//
// The x-multi-segment vendor extension (GitHub OpenAPI) marks path parameters
// whose values may contain "/" (e.g. "path", "basehead", "ref"). These are
// identified by scanning all JSON objects for {"x-multi-segment": true, "name":
// "<param-name>"} and stored in Table.multiSegment so matchTemplate lets a
// {name} segment span several request segments.
func DistillOpenAPI(raw []byte) (*Table, error) {
	// Parse once into a generic value so we can both extract the typed paths
	// view and walk the full document for x-multi-segment annotations.
	var rawFull any
	if err := json.Unmarshal(raw, &rawFull); err != nil {
		return nil, fmt.Errorf("%w: parse openapi: %w", ErrTableRejected, err)
	}

	// Re-use the already-parsed bytes for the typed paths view. This second
	// unmarshal into openAPIDoc is infallible when the first succeeded because
	// openAPIDoc is a strict subset of the full document.
	var doc openAPIDoc
	_ = json.Unmarshal(raw, &doc) // infallible: same bytes already validated above.

	multiSeg := collectMultiSegment(rawFull)

	t := &Table{byMethod: map[string][]Templ{}, multiSegment: multiSeg}
	for path, ops := range doc.Paths {
		segs := splitPath(path)
		for method, rawOp := range ops {
			if !httpMethods[method] {
				continue // non-method path-item key (e.g. a future "$ref"); skip.
			}
			var op struct {
				XGitHub xGitHub `json:"x-github"`
			}
			if err := json.Unmarshal(rawOp, &op); err != nil {
				return nil, fmt.Errorf("%w: parse %s %s: %w", ErrTableRejected, method, path, err)
			}
			if op.XGitHub.Category == "" {
				// An operation with no GitHub category cannot be governed by the
				// category ceiling; reject the table rather than let it resolve
				// through `default` (fail closed).
				return nil, fmt.Errorf("%w: %s %s has no x-github.category", ErrTableRejected, method, path)
			}
			m := strings.ToUpper(method)
			t.byMethod[m] = append(t.byMethod[m], Templ{
				Segments: segs,
				Route:    Route{Category: op.XGitHub.Category, Subcategory: op.XGitHub.Subcategory},
			})
		}
	}
	if len(t.byMethod) == 0 {
		return nil, fmt.Errorf("%w: openapi produced no routes", ErrTableRejected)
	}
	sortTemplates(t.byMethod)
	return t, nil
}

// collectMultiSegment walks an arbitrary JSON value recursively and collects
// the "name" string from every JSON object that carries both "x-multi-segment":
// true and a non-empty "name" string. These correspond to GitHub's documented
// path parameters whose values may span multiple URL segments (contain "/").
func collectMultiSegment(v any) map[string]bool {
	result := map[string]bool{}
	walkAny(v, result)
	return result
}

// walkAny recurses into maps and slices to find multi-segment parameter objects.
func walkAny(v any, out map[string]bool) {
	switch node := v.(type) {
	case map[string]any:
		xms, hasXMS := node["x-multi-segment"]
		name, hasName := node["name"]
		if hasXMS && hasName {
			if b, bOK := xms.(bool); bOK && b {
				if n, nOK := name.(string); nOK && n != "" {
					out[n] = true
				}
			}
		}
		for _, child := range node {
			walkAny(child, out)
		}
	case []any:
		for _, child := range node {
			walkAny(child, out)
		}
	}
}

// sortTemplates orders each method's templates by joined segments so the
// serialized table is reproducible regardless of the OpenAPI map iteration
// order. Lookup does not depend on the order.
func sortTemplates(byMethod map[string][]Templ) {
	for m := range byMethod {
		ts := byMethod[m]
		sort.Slice(ts, func(i, j int) bool {
			return strings.Join(ts[i].Segments, "/") < strings.Join(ts[j].Segments, "/")
		})
	}
}

// maxPathSegments is the longest path Lookup will classify. GitHub answers 414 below it (at about 8000 segments), so
// a longer path cannot name an operation, and the cap bounds the matcher's recursion depth and the size of its memo.
const maxPathSegments = 8192

// splitPath splits a URL path on "/" with the leading slash dropped. An empty
// path yields no segments.
func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// isParam reports whether a template segment is a "{param}" placeholder.
func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// Lookup returns the routes a request may run, or nil when no template matches
// (the caller fails closed). Among the templates matching the escaped path, the
// ones with the most literal segments win; when several win with different
// routes, GitHub's own router decides which runs, so the caller must allow every
// one. When the path ends in exactly one '/' after a non-empty segment, some
// GitHub routes ignore that slash and others keep it as part of the value, so
// the winners of the path without it are added too. That reading only adds
// routes: a path whose escaped form matches nothing stays unmatched. The result
// is sorted by category then subcategory and has no duplicates, whatever order
// the templates are stored in.
func (t *Table) Lookup(method, path string) []Route {
	tmpls := t.byMethod[strings.ToUpper(method)]
	// Count the separators first: splitting allocates every segment, and a path with more separators than the cap
	// has more segments than the cap.
	if strings.Count(path, "/") > maxPathSegments {
		return nil
	}
	segs := splitPath(path)
	routes := t.best(tmpls, segs)
	if routes == nil {
		return nil
	}
	if trimmed, ok := dropOneTrailingSlash(segs); ok {
		routes = append(routes, t.best(tmpls, trimmed)...)
	}
	slices.SortFunc(routes, func(a, b Route) int {
		return cmp.Or(strings.Compare(a.Category, b.Category), strings.Compare(a.Subcategory, b.Subcategory))
	})

	return slices.Compact(routes)
}

// best returns the routes of the matching templates with the most literal
// segments, or nil when none matches. For two fixed-length templates matching
// one request, literals plus params equal the request length, so more literals
// means fewer params.
func (t *Table) best(tmpls []Templ, segs []string) []Route {
	var out []Route
	top := -1
	for i := range tmpls {
		if !t.matchTemplate(tmpls[i].Segments, segs) {
			continue
		}
		switch lit := literals(tmpls[i].Segments); {
		case lit > top:
			top, out = lit, []Route{tmpls[i].Route}
		case lit == top:
			out = append(out, tmpls[i].Route)
		}
	}

	return out
}

// isMultiSegment reports whether a template segment is a param whose name is
// marked x-multi-segment:true in the OpenAPI, so its value may contain '/'.
func (t *Table) isMultiSegment(seg string) bool {
	return isParam(seg) && t.multiSegment[seg[1:len(seg)-1]]
}

// matchTemplate reports whether tmpl matches req. A literal matches one equal
// segment and an ordinary param any one segment, empty included. A
// multi-segment param that is not last takes one or more segments, any of them
// empty, as GitHub routes /branches/main//protection to branch protection; one
// that is last takes whatever is left, nothing included, so the root contents
// path matches.
func (t *Table) matchTemplate(tmpl, req []string) bool {
	if !slices.ContainsFunc(tmpl, t.isMultiSegment) {
		return matchFixed(tmpl, req)
	}
	if !t.prefixMatches(tmpl, req) {
		return false
	}
	m := matcher{t: t, tmpl: tmpl, req: req, failed: make([]bool, (len(tmpl)+1)*(len(req)+1))}

	return m.match(0, 0)
}

// prefixMatches reports whether req matches the segments of tmpl before its first multi-segment param under the rules
// of matchFixed. It lets matchTemplate reject a request before it allocates the memo for a walk that cannot succeed.
func (t *Table) prefixMatches(tmpl, req []string) bool {
	prefix := tmpl[:slices.IndexFunc(tmpl, t.isMultiSegment)]
	if len(req) < len(prefix) {
		return false
	}
	for i, seg := range prefix {
		if !isParam(seg) && req[i] != seg {
			return false
		}
	}

	return true
}

// matchFixed matches a template with no multi-segment param: the lengths must be
// equal, a literal needs an equal segment and a param takes any one segment.
func matchFixed(tmpl, req []string) bool {
	if len(tmpl) != len(req) {
		return false
	}
	for i, seg := range tmpl {
		if !isParam(seg) && req[i] != seg {
			return false
		}
	}

	return true
}

// matcher walks (template index, request index) states. Every step moves at
// least one index forward, and a state that failed is never explored again, so
// the work is bounded by the number of states however many multi-segment
// params the template has. Lookup caps the request at maxPathSegments, which
// bounds the recursion depth and the memo, not only the number of states.
type matcher struct {
	t         *Table
	tmpl, req []string
	failed    []bool
}

func (m *matcher) match(ti, ri int) bool {
	if ti == len(m.tmpl) {
		return ri == len(m.req)
	}
	k := ti*(len(m.req)+1) + ri
	if m.failed[k] {
		return false
	}
	if m.step(ti, ri) {
		return true
	}
	m.failed[k] = true

	return false
}

// step matches template segment ti starting at request segment ri. A
// multi-segment param that is not last takes the segment at ri, then either
// stops or takes another.
func (m *matcher) step(ti, ri int) bool {
	seg := m.tmpl[ti]
	if m.t.isMultiSegment(seg) {
		if ti == len(m.tmpl)-1 {
			return true
		}

		return ri < len(m.req) && (m.match(ti+1, ri+1) || m.match(ti, ri+1))
	}
	if ri == len(m.req) || (!isParam(seg) && m.req[ri] != seg) {
		return false
	}

	return m.match(ti+1, ri+1)
}

// literals counts the non-param segments of a template.
func literals(segs []string) int {
	n := 0
	for _, s := range segs {
		if !isParam(s) {
			n++
		}
	}

	return n
}

// dropOneTrailingSlash returns segs without the empty segment a single trailing
// '/' leaves. It declines when the segment before it is empty too, since GitHub
// keeps a doubled slash as part of the value, and when nothing else is left.
func dropOneTrailingSlash(segs []string) ([]string, bool) {
	n := len(segs)
	if n < 2 || segs[n-1] != "" || segs[n-2] == "" {
		return nil, false
	}

	return segs[:n-1], true
}

// Knows reports whether key (a "category" or "category/subcategory") names a real
// route family in the table.
func (t *Table) Knows(key string) bool {
	for _, ts := range t.byMethod {
		for i := range ts {
			r := ts[i].Route
			if r.Category == key || r.Category+"/"+r.Subcategory == key {
				return true
			}
		}
	}
	return false
}

// Routes returns every (route, template-segments) pair for admission scanning.
func (t *Table) Routes() []Templ {
	var out []Templ
	for _, ts := range t.byMethod {
		out = append(out, ts...)
	}
	return out
}

// Serialize returns the distilled table's cache form (~101 KiB). [json.Marshal] of
// the plain tableWire is infallible, so there is no error to return (avoiding an
// uncoverable error branch under the 100% gate).
func (t *Table) Serialize() []byte {
	w := tableWire{ByMethod: t.byMethod, MultiSegment: t.multiSegment}
	b, _ := json.Marshal(w) //nolint:errchkjson // infallible for tableWire.
	return b
}

// UnmarshalTable deserializes a table produced by Serialize, failing closed on a
// malformed or empty blob.
func UnmarshalTable(b []byte) (*Table, error) {
	var w tableWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("%w: unmarshal table: %w", ErrTableRejected, err)
	}
	if len(w.ByMethod) == 0 {
		return nil, fmt.Errorf("%w: table has no routes", ErrTableRejected)
	}
	ms := w.MultiSegment
	if ms == nil {
		ms = map[string]bool{}
	}
	return &Table{byMethod: w.ByMethod, multiSegment: ms}, nil
}
