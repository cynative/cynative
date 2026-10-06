package gitlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

const (
	docProtocol       = "rest-json"
	docSourceName     = "gitlab-org/gitlab"
	docSourceDocument = "doc/api/openapi/openapi_v3.yaml"
	docPage           = "page"
	docPerPage        = "per_page"
	docOffsetLimit    = "pagination is inferred from the page and per_page query parameters; follow the " +
		`X-Next-Page response header (or rel="next" in the Link header)`
	docMasterLimit = "the document describes GitLab's master branch; a self-managed instance may run an older " +
		"version that lacks this operation"
	docDriftLimit  = "the docs and the gitlab gate's table can be read from different downloads of the document"
	docNotAdmitted = "rendered path is not admitted by the gitlab gate"
	// docPlaceholder fills every label when the rendered path is checked against the gate's table. It is no
	// literal segment of GitLab's document and has no dot, so the format-suffix strip leaves it whole.
	docPlaceholder = "x"
)

// docLabel matches a {label} anywhere in a rendered path, including inside a segment.
var docLabel = regexp.MustCompile(`\{([^{}]+)\}`)

// DistillDocs distills GitLab's OpenAPI v3 YAML into operation docs for api_reference and the unmatched-request
// hint. It is separate from the gate's table distiller. It runs when the docs cache loads, which a cold
// unmatched-request hint does synchronously on the denial path. The docs hash the YAML bytes as fetched.
func DistillDocs(raw []byte) (*openapidoc.OperationDocs, error) {
	js, err := yamlToJSON(raw)
	if err != nil {
		return nil, err
	}
	d, err := openapidoc.Distill(js, docProfile("", nil))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	d.SHA256 = hex.EncodeToString(sum[:])
	admitted := tableAdmits(raw)
	for id, op := range d.Ops {
		d.Ops[id] = renderOp(op, admitted)
	}
	return d, nil
}

// tableAdmits builds the gate's table from the same bytes and returns a check that a rendered path, every label
// filled with docPlaceholder, classifies under its method. A document the table distiller rejects admits nothing.
func tableAdmits(raw []byte) func(method, path string) bool {
	table, err := DistillOpenAPI(raw)
	if err != nil {
		return func(string, string) bool { return false }
	}
	return func(method, path string) bool {
		_, cerr := ClassifyRequest(table, method, docLabel.ReplaceAllString(path, docPlaceholder))
		return cerr == nil
	}
}

// renderOp rewrites one operation's Grape path to the concrete form with every optional group present, keeps the
// other forms as hint alternatives, makes every label in the rendered path a required path input, and records a
// gap when the gate's table does not admit the rendered path.
func renderOp(op openapidoc.OperationDoc, admitted func(method, path string) bool) openapidoc.OperationDoc {
	forms := expandOptionalGroups(literalGroups(op.Path))
	op.Path = forms[0]
	for _, alt := range forms[1:] {
		if alt != op.Path && !slices.Contains(op.Alt, alt) {
			op.Alt = append(op.Alt, alt)
		}
	}
	op.Params = labelParams(op.Path, op.Params)
	if !admitted(op.Method, op.Path) {
		op.Gaps = append(op.Gaps, docNotAdmitted)
	}
	return op
}

// literalGroups escapes every unescaped "(...)" group with no "/" inside, so expandOptionalGroups keeps it as
// written. Such a group is a literal OData call, as in NuGet's FindPackagesById() or
// Packages(Id='{package_name}',Version='{package_version}'), not an optional part of the path: every optional
// group GitLab documents holds a "/". The gate's table still expands these groups; a rendered path it cannot
// classify gets the not-admitted gap.
func literalGroups(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '\\' && i+1 < len(path) {
			b.WriteString(path[i : i+2])
			i++
			continue
		}
		if c == '(' {
			if end := strings.IndexByte(path[i:], ')'); end > 0 && !strings.ContainsAny(path[i+1:i+end], "/(") {
				b.WriteString(`\(` + path[i+1:i+end] + `\)`)
				i += end
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// labelParams makes every {label} in path a required path input: a declared one is required whatever the
// metadata says, and an undeclared one is added as a string with no description.
func labelParams(path string, params []openapidoc.DocParam) []openapidoc.DocParam {
	out := slices.Clone(params)
	for _, m := range docLabel.FindAllStringSubmatch(path, -1) {
		i := slices.IndexFunc(out, func(p openapidoc.DocParam) bool {
			return p.Name == m[1] && p.In == string(apiref.LocationPath)
		})
		if i < 0 {
			out = append(out, openapidoc.DocParam{
				Name: m[1], In: string(apiref.LocationPath), Type: "string", Required: true,
			})
			continue
		}
		out[i].Required = true
	}
	return out
}

// Reference looks q up in GitLab's docs. endpoint is the served API base URL, supplied at lookup because the
// cache stores no host, and refuse reports an input the connector rejects whatever the permission level.
func Reference(
	d *openapidoc.OperationDocs, q apiref.Query, endpoint string, refuse func(apiref.Location, string) bool,
) apiref.Result {
	prof := docProfile(endpoint, refuse)
	res := d.Reference(q, prof)
	if res.Outcome != apiref.OutcomeNotFound {
		return res
	}
	// The quoted echo is bounded before the guidance is appended, so the guidance always fits within MaxReason; the
	// outer Truncate only keeps the hard bound.
	notFound := fmt.Sprintf("no operation %s in gitlab", apiref.Truncate(strconv.Quote(q.Operation), apiref.MaxChoice))
	// Models copy GitHub's "repos/get" naming and prefix a correct GitLab id ("projects/getApiV4..."). Name the
	// operation the part after the last slash resolves to, without answering for it.
	tail := q.Operation[strings.LastIndex(q.Operation, "/")+1:]
	if tail != q.Operation {
		sub := q
		sub.Operation = tail
		if r := d.Reference(sub, prof); r.Reference != nil {
			res.Reason = apiref.Truncate(fmt.Sprintf("%s; GitLab operation names carry no prefix: did you mean %q?",
				notFound, r.Reference.Operation), apiref.MaxReason)
			return res
		}
	}
	res.Reason = apiref.Truncate(notFound+"; "+docNameFormat, apiref.MaxReason)
	return res
}

// docNameFormat tells a model what a GitLab operation name looks like, after a lookup found none.
const docNameFormat = "GitLab operation names are the document's camelCase operationId, the method plus the " +
	"path, for example getApiV4ProjectsIdMergeRequests"

// docProfile is the gitlab connector's reference profile. Distill runs it with no endpoint, so the document's
// https://{hostname} server is ignored. The document often omits response content (162 GETs declare a 200 with
// none), so a contentless response is reported as unspecified rather than as no body.
func docProfile(endpoint string, refuse func(apiref.Location, string) bool) openapidoc.Profile {
	return openapidoc.Profile{
		Connector:      "gitlab",
		Protocol:       docProtocol,
		SourceName:     docSourceName,
		SourceDocument: docSourceDocument,
		Endpoint:       endpoint,
		ScalarUnion:    true,
		Paged:          offsetPaged,
		Paging:         apiref.Pagination{Style: "offset", InputToken: docPage, PageSize: docPerPage},
		PagingLimit:    docOffsetLimit,
		Limitations:    []string{docMasterLimit, docDriftLimit},
		Refuse:         refuse,

		UnspecifiedResponse: true,
	}
}

// offsetPaged reports an operation with both page and per_page query parameters. Keyset pagination is never
// inferred.
func offsetPaged(params []openapidoc.DocParam, _ []string) bool {
	inQuery := func(name string) bool {
		return slices.ContainsFunc(params, func(p openapidoc.DocParam) bool {
			return p.Name == name && p.In == string(apiref.LocationQuery)
		})
	}
	return inQuery(docPage) && inQuery(docPerPage)
}

// yamlToJSON re-encodes a YAML document as JSON for the shared OpenAPI decoder. YAML allows mapping keys that are
// not strings (an unquoted response code decodes as an int) and JSON does not, so every key becomes its string
// form first.
func yamlToJSON(raw []byte) ([]byte, error) {
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("%w: parse openapi: %w", openapidoc.ErrDocsRejected, err)
	}
	js, err := json.Marshal(stringKeys(tree))
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode openapi: %w", openapidoc.ErrDocsRejected, err)
	}
	return js, nil
}

// stringKeys returns v with every mapping key in it converted to its string form.
func stringKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = stringKeys(e)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(k)] = stringKeys(e)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = stringKeys(e)
		}
		return t
	}
	return v
}
