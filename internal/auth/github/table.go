package github

import (
	"encoding/json"
	"fmt"
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
	// byMethod indexes templates by upper-case method then by segment count, so a
	// lookup only scans templates of the matching arity (plus catch-alls).
	byMethod map[string][]Templ
	// multiSegment is the set of parameter names (without braces) that carry
	// x-multi-segment:true in the GitHub OpenAPI — these params may contain "/"
	// and therefore act as greedy trailing catch-alls (e.g. "path", "basehead").
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
// "<param-name>"} and stored in Table.multiSegment so matchTemplate can treat
// trailing {name} segments as greedy catch-alls.
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

// sortTemplates orders each method's templates deterministically (by joined
// segments) so Lookup's equal-score tie-break is reproducible regardless of the
// OpenAPI map iteration order.
func sortTemplates(byMethod map[string][]Templ) {
	for m := range byMethod {
		ts := byMethod[m]
		sort.Slice(ts, func(i, j int) bool {
			return strings.Join(ts[i].Segments, "/") < strings.Join(ts[j].Segments, "/")
		})
	}
}

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

// Lookup resolves a concrete request to its Route, or false when no template
// matches (the caller fails closed). Among matches the lowest score (fewest
// param segments = most literal) wins; byMethod slices are sorted at build time
// (DistillOpenAPI/UnmarshalTable), so equal-score ties resolve deterministically
// by the first match in sorted order.
func (t *Table) Lookup(method, path string) (Route, bool) {
	reqSegs := splitPath(path)
	tmpls := t.byMethod[strings.ToUpper(method)]
	bestIdx, bestScore := -1, 0
	for i := range tmpls {
		score, ok := t.matchTemplate(tmpls[i].Segments, reqSegs)
		if ok && (bestIdx == -1 || score < bestScore) {
			bestIdx, bestScore = i, score
		}
	}
	if bestIdx == -1 {
		return Route{}, false
	}
	return tmpls[bestIdx].Route, true
}

// isCatchAll reports whether a template segment is a multi-segment catch-all
// param — i.e. its inner name is marked x-multi-segment:true in the OpenAPI.
// Greedy-trailing is harmless for a single-segment value (no slash).
func (t *Table) isCatchAll(seg string) bool {
	if !isParam(seg) {
		return false
	}
	name := seg[1 : len(seg)-1] // strip braces
	return t.multiSegment[name]
}

// matchTemplate reports whether tmpl matches req and a score (count of param
// segments; lower is more literal, hence preferred). A trailing catch-all param
// (x-multi-segment:true) matches zero-or-more remaining segments; any other
// param matches exactly one, so a non-catch-all template requires an exact
// segment-count match.
func (t *Table) matchTemplate(tmpl, req []string) (int, bool) {
	score := 0
	for i, seg := range tmpl {
		isLast := i == len(tmpl)-1
		catchAll := isLast && t.isCatchAll(seg)
		if catchAll {
			// Catch-all: match zero-or-more remaining request segments.
			score++
			return score, true
		}
		if i >= len(req) {
			return 0, false
		}
		if isParam(seg) {
			score++
			continue
		}
		if req[i] != seg {
			return 0, false
		}
	}
	if len(req) != len(tmpl) {
		return 0, false // non-catch-all tail: lengths must match exactly.
	}
	return score, true
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
// malformed or empty blob. The stored order is already sorted (Serialize is
// called on a sorted table), so Lookup stays deterministic.
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
