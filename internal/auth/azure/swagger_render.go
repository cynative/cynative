package azure

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

// The fixed values of every azure reference.
const (
	refConnector    = "azure"
	refProtocol     = "rest-json"
	refAuthField    = "azure_auth"
	refSourceName   = "Azure/azure-rest-api-specs"
	refJSONMedia    = "application/json"
	refDescMaxBytes = 8 << 10
	apiVersionParam = "api-version"
	providerless    = "Microsoft.Resources"
	// paginationNextLink is the style of an x-ms-pageable operation: follow the next-page URL the response carries.
	paginationNextLink = "next-link"
	// namespacePlaceholder stands for azure_auth.service when the path does not fix the namespace.
	namespacePlaceholder = "<Namespace>"
	defaultNextLink      = "nextLink"
	defaultItems         = "value"
	inQuery              = "query"
	inHeader             = "header"
	inPath               = "path"
	inBody               = "body"
	inFormData           = "formData"
	typeArray            = "array"
	// parentPathSuffix ends the name of a greedy label that holds a parent path, which can be empty.
	parentPathSuffix = "Path"
	typeString       = "string"
)

// The reference text the reader adds.
const (
	refPublished = "the api-version is published in Azure/azure-rest-api-specs at commit %s; that does not show " +
		"that this cloud or resource type serves it, and ARM's error for an unserved version lists the ones it does"
	refBodyGap      = "request body is not a JSON object the template can render"
	refOptionalBody = "optional request body is not rendered"
	refLongRunning  = "a long-running operation: poll the URL in the Azure-AsyncOperation or Location response " +
		"header until it reports a terminal status"
	refNextLink = "the next page is the nextLink URL exactly as returned: send a GET to it unchanged, with the " +
		"same auth_provider and azure_auth; it carries its own api-version"
	refBadPageable    = "the operation's x-ms-pageable extension is malformed; pagination is not described"
	refGenericVersion = "api-version is an input: this generic operation serves many resource types, so send a " +
		"version the target resource type supports (ARM's error for a wrong one lists them)"
	refEnumVersions   = "the api-version parameter lists %s; send one of them"
	refNoAPIVersion   = "the operation declares no api-version parameter; the template sends the document's version"
	refNamespaceInput = "azure_auth.service must equal the namespace after the last /providers/ of the final URL"
	refOtherNamespace = "the path's namespace is %s, not the lookup's service %s; azure_auth.service must be %s"
	refEmptyGreedy    = "leave no empty segment (//) when %s is empty, which the gate denies; prefer the {scope} " +
		"form of the operation where one exists"
	refLeadingGreedy = "%s is a full resource ID: drop its leading '/' when you substitute it, since the path " +
		"already starts with one"
	refAsReturnedDesc = "already URL-encoded: send the value as returned (for example a resource ID), without " +
		"percent-encoding it again; "
	refAsReturned = "%s takes a value as returned (already URL-encoded): do not percent-encode it again, which " +
		"overrides the per-segment encoding the note gives for a <Name+> value"
	refOptionalFormat = "optional input %s (collectionFormat %s) is not listed"
	refUnresolved     = "a parameter could not be resolved: "
	refPathSegment    = "a path segment"
	refCSV            = "(comma-separated) "
)

// pathLabel matches a {label} in a path template, greedy {label+} included.
var pathLabel = regexp.MustCompile(`\{([^{}]+)\}`)

// scalarTypes are the body property types a template can render.
//
//nolint:gochecknoglobals // immutable lookup table.
var scalarTypes = map[string]bool{typeString: true, "integer": true, "number": true, "boolean": true}

// renderInput is one matched operation and everything its reference names.
type renderInput struct {
	Doc      *swaggerDoc
	File     IndexFile
	Dir      IndexDir
	Group    string
	Op       OpSummary
	Commit   string
	Endpoint string
	Service  string
	SHA256   string
	Selector string
	Resolver *refResolver
}

// resolvedParam is a parameter after its $ref chain, with the file it lives in.
type resolvedParam struct {
	swaggerParam

	from   string
	shared bool
}

// renderer builds one reference.
type renderer struct {
	in     renderInput
	ref    *apiref.Reference
	inputs []apiref.Input
	// asReturned names the greedy path inputs that carry x-ms-skip-url-encoding, whose values are sent as returned.
	asReturned []string
}

// renderOperation describes one operation. A budget stop, a context error or a file that cannot be loaded is
// returned; a ref that cannot be followed becomes a gap.
func renderOperation(ctx context.Context, in renderInput) (*apiref.Reference, error) {
	op, common, err := in.Doc.operation(in.Op)
	if err != nil {
		return nil, err
	}
	if err = in.Resolver.add(in.File.Path, in.Doc); err != nil {
		return nil, err
	}
	r := &renderer{in: in, ref: newReference(in, op)}
	params, err := r.resolveParams(ctx, slices.Concat(common, op.Parameters))
	if err != nil {
		return nil, err
	}
	r.renderPath(params)
	r.renderVersion(params)
	r.renderParams(params)
	if err = r.renderBody(ctx, params); err != nil {
		return nil, err
	}
	r.finishInputs()
	r.renderResponse(op)
	r.renderService()
	r.renderAsReturned()

	return r.ref, nil
}

// derivedService is the namespace the gate reads from a rendered path, through the gate's own resolveNamespace. It
// reports false when the path does not fix it: the namespace segment is a label, or a greedy label after the last
// literal providers segment can carry another one.
func derivedService(p string) (string, bool) {
	segs := splitPath(p)
	last := -1
	for i, s := range segs {
		if strings.EqualFold(s, segProviders) {
			last = i
		}
	}
	if slices.ContainsFunc(segs[last+1:], isGreedyLabel) {
		return "", false
	}
	ns, _, ok := resolveNamespace(segs)
	switch {
	case !ok:
		return providerless, true
	case pathLabel.MatchString(ns):
		return "", false
	}

	return ns, true
}

// isGreedyLabel reports whether a path segment is a {label+} that spans segments.
func isGreedyLabel(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "+}")
}

func newReference(in renderInput, op swaggerOp) *apiref.Reference {
	summary := cmp.Or(op.Summary, op.Description)

	return &apiref.Reference{
		Connector:    refConnector,
		Model:        in.Selector,
		Operation:    in.Op.ID,
		Protocol:     refProtocol,
		Method:       in.Op.Method,
		Summary:      apiref.StripMarkupCut(summary, refDescMaxBytes, apiref.MaxSummary),
		Endpoint:     in.Endpoint,
		Inputs:       []apiref.Input{},
		BodyEncoding: apiref.BodyNone,
		AuthField:    refAuthField,
		Response:     apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"},
		Pagination:   apiref.Pagination{Style: apiref.PaginationUnspecified},
		Source: apiref.Source{
			Name: refSourceName, Document: sourceDocument(in), Version: in.Commit, SHA256: in.SHA256,
		},
		Limitations: []string{fmt.Sprintf(refPublished, in.Commit)},
	}
}

// sourceDocument names the spec file and the version it declares, so the reference keeps the file's own version
// when the api-version it sends is another (a single-value enum, as Key Vault's Vaults_List sends 2015-11-01 from a
// 2026-05-15 file). The dir is in the path.
func sourceDocument(in renderInput) string {
	if in.Doc.Info.Version == "" {
		return in.File.Path
	}

	return in.File.Path + " (info.version " + in.Doc.Info.Version + ")"
}

// resolveParams resolves the path item's parameters, then the operation's, an operation parameter replacing a path
// item one of the same name and location.
func (r *renderer) resolveParams(ctx context.Context, raws []json.RawMessage) ([]resolvedParam, error) {
	var out []resolvedParam
	for _, raw := range raws {
		p, from, shared, err := r.in.Resolver.param(ctx, r.in.File.Path, raw)
		switch {
		case err == nil:
		case refGap(err):
			r.ref.Gaps = append(r.ref.Gaps, apiref.Truncate(refUnresolved+err.Error(), apiref.MaxReason))

			continue
		default:
			return nil, err
		}
		rp := resolvedParam{swaggerParam: p, from: from, shared: shared}
		if i := slices.IndexFunc(out, func(o resolvedParam) bool { return o.Name == p.Name && o.In == p.In }); i >= 0 {
			out[i] = rp

			continue
		}
		out = append(out, rp)
	}

	return out, nil
}

// renderPath builds the path template from the paths or x-ms-paths key: a single-value enum path parameter becomes
// its literal value, an x-ms-skip-url-encoding one becomes greedy, and an x-ms-paths query part keeps only the pairs
// no parameter models.
func (r *renderer) renderPath(params []resolvedParam) {
	base, query, _ := strings.Cut(r.in.Op.Path, "?")
	if r.in.Op.XMs {
		r.pathQuery(query, params)
	}
	r.ref.PathTemplate = pathLabel.ReplaceAllStringFunc(base, func(m string) string {
		p, ok := findParam(params, inPath, m[1:len(m)-1])
		switch {
		case ok && len(p.Enum) == 1:
			return url.PathEscape(enumValue(p.Enum[0]))
		case ok && p.SkipURLEncoding:
			return "{" + p.Name + "+}"
		}

		return m
	})
}

// pathQuery keeps an x-ms-paths key's k=v pairs that no query parameter models; a bare name is a disambiguator.
func (r *renderer) pathQuery(query string, params []resolvedParam) {
	for kv := range strings.SplitSeq(query, "&") {
		k, v, hasValue := strings.Cut(kv, "=")
		if !hasValue || k == "" {
			continue
		}
		// Decode the key and value from the x-ms-paths URL encoding, then re-encode for FixedQuery.
		if kDec, err := url.QueryUnescape(k); err == nil {
			k = kDec
		}
		if vDec, err := url.QueryUnescape(v); err == nil {
			v = vDec
		}
		if _, modeled := findParam(params, inQuery, k); !modeled {
			r.ref.FixedQuery = append(r.ref.FixedQuery, apiref.Param{Key: queryEscape(k), Value: queryEscape(v)})
		}
	}
}

// renderVersion fixes the api-version the template sends, or makes it an input for a generic operation.
func (r *renderer) renderVersion(params []resolvedParam) {
	docVersion := r.in.Doc.Info.Version
	if !validVersion(docVersion) {
		docVersion = r.in.Dir.Name
	}
	p, ok := findParam(params, inQuery, apiVersionParam)
	switch {
	case !ok:
		r.fixVersion(docVersion)
		r.ref.Limitations = append(r.ref.Limitations, refNoAPIVersion)
	case len(p.Enum) == 1:
		r.fixVersion(enumValue(p.Enum[0]))
	case slices.Contains(enumValues(p.Enum), docVersion), len(p.Enum) == 0 && p.shared:
		r.fixVersion(docVersion)
	case len(p.Enum) > 1:
		r.inputs = append(r.inputs, r.input(p, apiref.LocationQuery, true))
		r.ref.Limitations = append(r.ref.Limitations, fmt.Sprintf(refEnumVersions, formatEnumList(p.Enum)))
	default:
		r.inputs = append(r.inputs, r.input(p, apiref.LocationQuery, true))
		r.ref.Limitations = append(r.ref.Limitations, refGenericVersion)
	}
}

func (r *renderer) fixVersion(v string) {
	r.ref.FixedQuery = append(r.ref.FixedQuery, apiref.Param{Key: apiVersionParam, Value: queryEscape(v)})
	r.ref.APIVersion = v
}

// queryEscape escapes a fixed query key or value exactly once, because the tool joins FixedQuery into the URL as
// given (apiref.ParamPairs). A space becomes %20, never '+', so no server reads it back as a literal plus; '$' stays
// literal, as ARM's OData names ($filter, $expand) are written and as RFC 3986 allows in a query.
func queryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"), "%24", "$")
}

// renderParams lists the path, query and header inputs, then any path label no parameter declares.
func (r *renderer) renderParams(params []resolvedParam) {
	for _, p := range params {
		switch p.In {
		case inBody, inFormData:
		case inPath:
			if len(p.Enum) != 1 {
				r.inputs = append(r.inputs, r.pathInput(p))
			}
		case inQuery, inHeader:
			if p.Name != apiVersionParam || p.In != inQuery {
				r.queryOrHeader(p)
			}
		default:
			if p.Required {
				r.ref.Gaps = append(r.ref.Gaps, fmt.Sprintf("required input %s (in %s) cannot be rendered",
					p.Name, p.In))
			}
		}
	}
	for _, m := range pathLabel.FindAllStringSubmatch(r.ref.PathTemplate, -1) {
		name := strings.TrimSuffix(m[1], "+")
		if _, declared := findParam(params, inPath, name); !declared {
			r.inputs = append(r.inputs, apiref.Input{
				Name: name, WireName: name, Location: apiref.LocationPath, Required: true, Type: typeString,
				Renderable: true, Description: refPathSegment,
			})
		}
	}
}

// queryOrHeader places one query or header parameter: a required single-value enum is a fixed value, an optional
// array in a format other than csv is left out, anything else is an input.
func (r *renderer) queryOrHeader(p resolvedParam) {
	switch {
	case p.Required && len(p.Enum) == 1:
		// A header value travels as it is; a query pair is escaped once for the URL.
		if p.In == inQuery {
			r.ref.FixedQuery = append(r.ref.FixedQuery,
				apiref.Param{Key: queryEscape(p.Name), Value: queryEscape(enumValue(p.Enum[0]))})
		} else {
			r.ref.FixedHeaders = append(r.ref.FixedHeaders, apiref.Param{Key: p.Name, Value: enumValue(p.Enum[0])})
		}
	case p.Type == typeArray && !csvFormat(p.CollectionFormat) && !p.Required:
		r.ref.Limitations = append(r.ref.Limitations, fmt.Sprintf(refOptionalFormat, p.Name, p.CollectionFormat))
	default:
		r.inputs = append(r.inputs, r.input(p, apiref.Location(p.In), p.Required))
	}
}

// pathInput renders a path parameter. One that carries x-ms-skip-url-encoding and is greedy in the template holds a
// value that is already URL-encoded, so its description says to send it as returned, ahead of the declared text.
func (r *renderer) pathInput(p resolvedParam) apiref.Input {
	in := r.input(p, apiref.LocationPath, true)
	if p.SkipURLEncoding && strings.Contains(r.ref.PathTemplate, "{"+p.Name+"+}") {
		in.Description = apiref.Truncate(
			strings.TrimSuffix(refAsReturnedDesc+in.Description, "; "),
			apiref.MaxInputDescription,
		)
		r.asReturned = append(r.asReturned, p.Name)
	}

	return in
}

// renderAsReturned adds the one limitation naming the inputs that take a value as returned.
func (r *renderer) renderAsReturned() {
	if len(r.asReturned) > 0 {
		r.ref.Limitations = append(r.ref.Limitations,
			fmt.Sprintf(refAsReturned, strings.Join(r.asReturned, ", ")))
	}
}

func (r *renderer) input(p resolvedParam, loc apiref.Location, required bool) apiref.Input {
	in := apiref.Input{
		Name:        p.Name,
		WireName:    p.Name,
		Location:    loc,
		Required:    required,
		Type:        cmp.Or(p.Type, typeString),
		Renderable:  true,
		Description: apiref.StripMarkupCut(p.Description, refDescMaxBytes, apiref.MaxInputDescription),
	}
	if p.Type != typeArray {
		return in
	}
	if csvFormat(p.CollectionFormat) {
		in.Description = apiref.Truncate(refCSV+in.Description, apiref.MaxInputDescription)
	} else {
		in.Renderable = false
		in.Type = "array, collectionFormat " + p.CollectionFormat
	}

	return in
}

// renderBody applies the body rules: a required form body is a gap, an optional body is not rendered, and a required
// JSON body lists its required top-level scalars.
func (r *renderer) renderBody(ctx context.Context, params []resolvedParam) error {
	for _, p := range params {
		switch {
		case p.In == inFormData && p.Required:
			r.ref.Gaps = append(r.ref.Gaps, refBodyGap)
		case p.In == inBody && !p.Required:
			r.ref.Limitations = append(r.ref.Limitations, refOptionalBody)
		case p.In == inBody:
			if err := r.jsonBody(ctx, p); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *renderer) jsonBody(ctx context.Context, p resolvedParam) error {
	shape, err := r.in.Resolver.body(ctx, p.from, p.Schema)
	if err != nil && !refGap(err) {
		return err
	}
	if err != nil || !shape.object {
		r.ref.Gaps = append(r.ref.Gaps, refBodyGap)

		return nil //nolint:nilerr // a gap error becomes a gap, not a returned error.
	}
	r.ref.BodyEncoding = apiref.BodyJSON
	r.ref.FixedHeaders = append(r.ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: refJSONMedia})
	for _, name := range slices.Sorted(maps.Keys(shape.required)) {
		prop, known := shape.props[name]
		if prop.ReadOnly {
			continue
		}
		typ := prop.Type
		if !known {
			typ = "unknown"
		}
		r.inputs = append(r.inputs, apiref.Input{
			Name: name, WireName: name, Location: apiref.LocationBody, Required: true, Type: cmp.Or(typ, "object"),
			Renderable:  scalarTypes[typ],
			Description: apiref.StripMarkupCut(prop.Description, refDescMaxBytes, apiref.MaxInputDescription),
		})
	}

	return nil
}

// finishInputs orders the inputs required first, keeps at most apiref.MaxOptionalInputs optional ones, and adds a
// gap for every required input the template cannot render.
func (r *renderer) finishInputs() {
	slices.SortStableFunc(r.inputs, func(a, b apiref.Input) int {
		return boolRank(b.Required) - boolRank(a.Required)
	})
	optional := 0
	for _, in := range r.inputs {
		switch {
		case !in.Required && optional == apiref.MaxOptionalInputs:
			r.ref.InputsTruncated = true

			continue
		case !in.Required:
			optional++
		case !in.Renderable:
			r.ref.Gaps = append(r.ref.Gaps, fmt.Sprintf("required input %s (%s in %s) cannot be rendered",
				in.Name, in.Type, in.Location))
		}
		r.ref.Inputs = append(r.ref.Inputs, in)
	}
}

// renderResponse adds the long-running limitation and the next-link pagination of x-ms-pageable.
func (r *renderer) renderResponse(op swaggerOp) {
	if op.LongRunning {
		r.ref.Limitations = append(r.ref.Limitations, refLongRunning)
	}
	if len(op.Pageable) == 0 {
		return
	}
	var pg struct {
		NextLinkName json.RawMessage `json:"nextLinkName"`
		ItemName     string          `json:"itemName"`
	}
	next := defaultNextLink
	if json.Unmarshal(op.Pageable, &pg) != nil {
		r.ref.Limitations = append(r.ref.Limitations, refBadPageable)

		return
	}
	switch {
	case string(pg.NextLinkName) == "null":
		return
	case len(pg.NextLinkName) > 0 && json.Unmarshal(pg.NextLinkName, &next) != nil:
		r.ref.Limitations = append(r.ref.Limitations, refBadPageable)

		return
	}
	r.ref.Pagination = apiref.Pagination{
		Style: paginationNextLink, OutputToken: next,
		Items: cmp.Or(pg.ItemName, defaultItems),
	}
	r.ref.Limitations = append(r.ref.Limitations, refNextLink)
}

// renderService sets azure_auth.service to the namespace the gate derives from the path, a placeholder when the
// path does not fix it, and adds the greedy-label limitations.
func (r *renderer) renderService() {
	ns, ok := derivedService(r.ref.PathTemplate)
	r.ref.Service = ns
	switch {
	case !ok:
		ns, r.ref.Service = namespacePlaceholder, r.in.Service
		r.ref.Limitations = append(r.ref.Limitations, refNamespaceInput)
	case !strings.EqualFold(ns, r.in.Service):
		r.ref.Limitations = append(r.ref.Limitations, fmt.Sprintf(refOtherNamespace, ns, r.in.Service, ns))
	}
	r.ref.AuthArgs = map[string]string{"service": ns}
	segs := splitPath(r.ref.PathTemplate)
	for i, s := range segs {
		if !isGreedyLabel(s) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(s, "{"), "+}")
		switch {
		case i == 0:
			r.ref.Limitations = append(r.ref.Limitations, fmt.Sprintf(refLeadingGreedy, name))
		// A parent path ({parentResourcePath}) is empty for a top-level resource; a mid-path greedy label of another
		// name does not get the limitation.
		case i < len(segs)-1 && strings.HasSuffix(name, parentPathSuffix):
			r.ref.Limitations = append(r.ref.Limitations, fmt.Sprintf(refEmptyGreedy, name))
		}
	}
}

func findParam(params []resolvedParam, in, name string) (resolvedParam, bool) {
	i := slices.IndexFunc(params, func(p resolvedParam) bool { return p.In == in && p.Name == name })
	if i < 0 {
		return resolvedParam{}, false
	}

	return params[i], true
}

// enumValue is an enum value as the wire carries it: a JSON string's text, anything else as written.
func enumValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}

	return string(raw)
}

func enumValues(raws []json.RawMessage) []string {
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		out = append(out, enumValue(raw))
	}

	return out
}

// formatEnumList formats up to 5 enum values, then "and N more" if there are more.
func formatEnumList(raws []json.RawMessage) string {
	const maxShow = 5
	vals := enumValues(raws)
	if len(vals) <= maxShow {
		return strings.Join(vals, ", ")
	}

	return strings.Join(vals[:maxShow], ", ") + fmt.Sprintf(", and %d more", len(vals)-maxShow)
}

func csvFormat(f string) bool { return f == "" || f == "csv" }

func boolRank(b bool) int {
	if b {
		return 1
	}

	return 0
}
