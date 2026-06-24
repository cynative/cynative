package gitlab

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Route is the resolved category for an operation.
type Route struct {
	Category string `json:"c"`
}

// Templ is one distilled path template plus its route, pre-split into segments.
// Segments retain the leading "api","v4" segments; Lookup anchors against them.
type Templ struct {
	Segments []string `json:"p"`
	Route    Route    `json:"r"`
}

// Table maps (method, concrete path) to a Route, built from GitLab's OpenAPI v3.
// Immutable after construction; safe for concurrent reads.
type Table struct {
	byMethod map[string][]Templ
}

// tableWire is the on-disk/cache serialization of a Table.
type tableWire struct {
	ByMethod map[string][]Templ `json:"m"`
}

// openAPIDoc is the minimal slice of the OpenAPI we read: paths → method → op.
// Operation values are kept raw so a non-method path-item key (parameters,
// summary, $ref) is skipped without failing the whole parse.
type openAPIDoc struct {
	Paths map[string]map[string]yaml.Node `yaml:"paths"`
}

// httpMethods is the set of path-item keys that are HTTP operations.
var httpMethods = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"get": true, "head": true, "post": true, "put": true,
	"patch": true, "delete": true, "options": true,
}

// nonAlnumRun matches a run of non-alphanumeric characters, collapsed to one "-".
var nonAlnumRun = regexp.MustCompile(`[^a-z0-9]+`)

// multiSlash matches a run of two or more "/", collapsed to a single "/".
var multiSlash = regexp.MustCompile(`/{2,}`)

// NormalizeTag converts an OpenAPI tag name ("CI variables") to a category key
// ("ci-variables"): lowercase, each run of non-alphanumeric chars → one "-",
// trimmed. GitLab's 157 tags normalize to 157 distinct keys (collision-free).
func NormalizeTag(tag string) string {
	return strings.Trim(nonAlnumRun.ReplaceAllString(strings.ToLower(tag), "-"), "-")
}

// DistillOpenAPI parses GitLab's OpenAPI v3 (YAML) and reduces it to a routing
// Table of (method, path-template) → category (the operation's normalized
// tags[0]). An operation with no tag is skipped (its route stays unclassifiable
// → denied). Fails closed on invalid YAML or an empty route set.
func DistillOpenAPI(raw []byte) (*Table, error) {
	var doc openAPIDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse openapi: %w", ErrTableRejected, err)
	}
	t := &Table{byMethod: map[string][]Templ{}}
	for path, ops := range doc.Paths {
		// GitLab's OpenAPI carries Grape route syntax the literal splitter mishandles:
		// optional "(...)" groups (e.g. "(-/)", "(/{x})") that GitLab serves in BOTH the
		// present and absent forms, and escaped "\(\)" parens that are LITERAL "()" (OData).
		// Expand each raw path into the concrete path string(s) it represents before
		// splitting, so every real endpoint form registers and classifies.
		for _, concrete := range expandOptionalGroups(path) {
			segs := splitPathSegs(concrete)
			registerOps(t.byMethod, segs, ops)
		}
	}
	if len(t.byMethod) == 0 {
		return nil, fmt.Errorf("%w: openapi produced no routes", ErrTableRejected)
	}
	sortTemplates(t.byMethod)
	return t, nil
}

// registerOps appends one Templ per HTTP operation under a single concrete path's
// pre-split segments. A non-method path-item key (parameters, summary, $ref) or an
// untagged operation is skipped (the route stays absent → unclassifiable → denied).
func registerOps(byMethod map[string][]Templ, segs []string, ops map[string]yaml.Node) {
	for method, node := range ops {
		if !httpMethods[method] {
			continue
		}
		cat := firstTagCategory(node)
		if cat == "" {
			continue // untagged → skip → unclassifiable → denied.
		}
		// A template with a literal "variables" segment is a CI/CD-variable endpoint
		// whose reads return plaintext secret values; force the ci-variables category
		// regardless of the operation's own tag (GitLab scatters variable endpoints
		// across Pipelines / Pipeline schedules / CI variables tags). Operating on the
		// trusted spec TEMPLATE segments — not the user-controlled request path — means
		// a "variables" value in a path PARAMETER (e.g. a file named "variables") does
		// NOT inherit the sensitive category.
		if hasVariablesSegment(segs) {
			cat = ciVariablesKey
		}
		m := strings.ToUpper(method)
		byMethod[m] = append(byMethod[m], Templ{Segments: segs, Route: Route{Category: cat}})
	}
}

// expandOptionalGroups rewrites GitLab's Grape route syntax in a raw OpenAPI path
// into the set of concrete path strings it represents, so each real endpoint form
// can be split and registered. Two cases:
//
//   - Escaped parens "\(" / "\)" are LITERAL "(" / ")" (Grape OData routes, e.g.
//     ".../FindPackagesById\(\)") — they are unescaped to bare "()" and NOT treated
//     as an optional group, so a single concrete form with literal parens results.
//   - An UNESCAPED "(...)" group is an OPTIONAL segment Grape serves in both forms,
//     e.g. "(-/)", "(/{settings_context_hash})", "(ref/{ref}/)". Each such group
//     yields TWO variants — group present (parens stripped, inner content kept) and
//     group absent (the whole group removed) — multiplied across all groups, so N
//     groups yield up to 2^N concrete paths. Leading/trailing slashes are collapsed
//     so neither variant produces a "//".
//
// A path with no Grape syntax returns a single-element slice (itself), so the
// common case is unchanged.
func expandOptionalGroups(rawPath string) []string {
	// Sentinels for the literal escaped parens so they survive optional-group
	// scanning, then are restored to bare "(" / ")" at the end. The runes are
	// non-printable controls that never appear in an OpenAPI path.
	const litOpen, litClose = "\x00", "\x01"
	masked := strings.NewReplacer(`\(`, litOpen, `\)`, litClose).Replace(rawPath)
	out := []string{}
	for _, p := range expandFirstGroup(masked) {
		out = append(out, strings.NewReplacer(litOpen, "(", litClose, ")").Replace(p))
	}
	return out
}

// expandFirstGroup finds the first unescaped "(...)" group in p and returns the
// concrete paths produced by recursively expanding every group; a path with no
// group returns itself. The matching ")" is the next ")" after the "(" (GitLab's
// optional groups do not nest).
func expandFirstGroup(p string) []string {
	open := strings.IndexByte(p, '(')
	if open < 0 {
		return []string{p}
	}
	shut := strings.IndexByte(p[open:], ')')
	if shut < 0 {
		return []string{p} // unbalanced "(" — leave verbatim (won't match → denied).
	}
	shut += open
	inner := p[open+1 : shut]
	present := collapseSlashes(p[:open] + inner + p[shut+1:])
	absent := collapseSlashes(p[:open] + p[shut+1:])
	var out []string
	out = append(out, expandFirstGroup(present)...)
	out = append(out, expandFirstGroup(absent)...)
	return out
}

// collapseSlashes replaces any run of "/" with a single "/", so removing or
// inlining an optional group (e.g. "(-/)" or "(/{x})") never yields "//".
func collapseSlashes(p string) string {
	return multiSlash.ReplaceAllString(p, "/")
}

// firstTagCategory extracts and normalizes the first tag from an operation node.
// Returns "" when the operation has no non-empty tag.
func firstTagCategory(node yaml.Node) string {
	var op struct {
		Tags []string `yaml:"tags"`
	}
	if err := node.Decode(&op); err != nil {
		return ""
	}
	for _, tag := range op.Tags {
		if n := NormalizeTag(tag); n != "" {
			return n
		}
	}
	return ""
}

// splitPathSegs splits an OpenAPI path on "/" with the leading slash dropped.
func splitPathSegs(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// sortTemplates orders each method's templates deterministically so Lookup's
// equal-score tie-break is reproducible regardless of map iteration order.
func sortTemplates(byMethod map[string][]Templ) {
	for m := range byMethod {
		ts := byMethod[m]
		sort.Slice(ts, func(i, j int) bool {
			return strings.Join(ts[i].Segments, "/") < strings.Join(ts[j].Segments, "/")
		})
	}
}

// isParam reports whether a template segment is a "{param}" placeholder.
func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// decodeSegs splits the ESCAPED request path on literal "/" and percent-decodes
// each segment individually. A segment that fails to decode is left as-is. This
// keeps a %2F-encoded value inside one segment (it cannot forge an extra split)
// while decoding an encoded letter (so /%61pi decodes to api).
func decodeSegs(escapedPath string) []string {
	rawSegs := splitPathSegs(escapedPath)
	out := make([]string, len(rawSegs))
	for i, s := range rawSegs {
		if d, err := url.PathUnescape(s); err == nil {
			out[i] = d
		} else {
			out[i] = s
		}
	}
	return out
}

// anchorIndex returns 0 when the path's first two decoded segments are exactly
// "api","v4" (the API root), or -1 otherwise. The anchor is pinned to the ROOT:
// the connector serves the API at the host root only, and a non-root "api/v4"
// (e.g. /group/api/v4/... or a subpath install /gitlab/api/v4/...) must NOT
// classify — it would attach the Bearer token to a non-API path. Subpath installs
// cannot register anyway (the eager /api/v4/user probe runs at the host root), so
// a root-only anchor closes that de-facto non-API carve-out.
func anchorIndex(segs []string) int {
	if len(segs) >= 2 && segs[0] == "api" && segs[1] == "v4" {
		return 0
	}
	return -1
}

// Lookup resolves a concrete (escaped) request path to its Route, or false when
// no template matches (the caller fails closed). It anchors at the ROOT: the path's
// first two decoded segments must be "api","v4", so a non-root "api/v4" (e.g.
// /group/api/v4/... or a subpath install /gitlab/api/v4/...) returns false and is
// denied — the connector serves the API at the host root only. GitLab routes an
// optional Rails ".:format" suffix on the last segment to the bare endpoint (e.g.
// /api/v4/projects.json → projects), so the last segment's format suffix is stripped
// before matching; this is safe because a "{param}" last segment matches any value
// while a literal one now matches its format-suffixed form.
func (t *Table) Lookup(method, escapedPath string) (Route, bool) {
	segs := decodeSegs(escapedPath)
	at := anchorIndex(segs)
	if at < 0 {
		return Route{}, false
	}
	reqSegs := segs[at:]
	// Strip the optional Rails ".:format" suffix from the last segment so a literal
	// endpoint matches its format-suffixed form. segs is local to this call, so the
	// in-place write is safe. A "{param}" last segment matches any value, so this
	// never changes which template wins.
	if n := len(reqSegs); n > 0 {
		reqSegs[n-1] = stripFormatSuffix(reqSegs[n-1])
	}
	tmpls := t.byMethod[strings.ToUpper(method)]
	bestIdx, bestScore := -1, 0
	for i := range tmpls {
		score, ok := matchTemplate(tmpls[i].Segments, reqSegs)
		if ok && (bestIdx == -1 || score < bestScore) {
			bestIdx, bestScore = i, score
		}
	}
	if bestIdx == -1 {
		return Route{}, false
	}
	return tmpls[bestIdx].Route, true
}

// matchTemplate reports whether tmpl matches req and a score (count of param
// segments; lower is more literal, hence preferred). A "{param}" matches exactly
// one segment; GitLab has no x-multi-segment catch-alls, so lengths must match.
func matchTemplate(tmpl, req []string) (int, bool) {
	if len(tmpl) != len(req) {
		return 0, false
	}
	score := 0
	for i, seg := range tmpl {
		if isParam(seg) {
			score++
			continue
		}
		if req[i] != seg {
			return 0, false
		}
	}
	return score, true
}

// Knows reports whether key names a real category in the table.
func (t *Table) Knows(key string) bool {
	for _, ts := range t.byMethod {
		for i := range ts {
			if ts[i].Route.Category == key {
				return true
			}
		}
	}
	return false
}

// Routes returns every template for admission scanning.
func (t *Table) Routes() []Templ {
	var out []Templ
	for _, ts := range t.byMethod {
		out = append(out, ts...)
	}
	return out
}

// Serialize returns the distilled table's compact cache form. [json.Marshal] of
// tableWire is infallible.
func (t *Table) Serialize() []byte {
	b, _ := json.Marshal(tableWire{ByMethod: t.byMethod}) //nolint:errchkjson // infallible for tableWire.
	return b
}

// UnmarshalTable deserializes a table produced by Serialize, failing closed on a
// malformed or empty blob. The stored order is already sorted, so Lookup stays
// deterministic.
func UnmarshalTable(b []byte) (*Table, error) {
	var w tableWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("%w: unmarshal table: %w", ErrTableRejected, err)
	}
	if len(w.ByMethod) == 0 {
		return nil, fmt.Errorf("%w: table has no routes", ErrTableRejected)
	}
	return &Table{byMethod: w.ByMethod}, nil
}
