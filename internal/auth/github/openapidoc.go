package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// ErrDocsRejected reports operation docs that are unparseable or empty.
var ErrDocsRejected = errors.New("github_hardening: operation docs rejected")

const (
	docEndpoint        = "https://api.github.com"
	docProtocol        = "rest-json"
	docSourceName      = "github/rest-api-description"
	docSourceDocument  = "descriptions/api.github.com/api.github.com.json"
	docAccept          = "application/vnd.github+json"
	docUnknownType     = "unknown"
	docParamRefPrefix  = "#/components/parameters/"
	docSchemaRefPrefix = "#/components/schemas/"
	docJSONMedia       = "application/json"
	docBodySkipped     = "optional request body is not rendered"
	docBodyGap         = "request body is not a JSON object the template can render"
	docServerGap       = "operation is served from %s, not from the github connector's API host " + docEndpoint
	docVersionLimit    = "the connector strips X-GitHub-Api-Version, so the server's default API version applies"
	docLinkLimit       = `pagination is inferred from per_page/page parameters and a declared Link header; ` +
		`follow rel="next" in the Link response header`
	docOKStatus = "200"
	docPerPage  = "per_page"
	docPage     = "page"
	docLink     = "Link"
)

// DocParam is one documented parameter or required body property.
type DocParam struct {
	Name        string `json:"n"`
	In          string `json:"i"`
	Type        string `json:"t"`
	Required    bool   `json:"r,omitempty"`
	Description string `json:"d,omitempty"`
}

// OperationDoc is the documentation distilled from one OpenAPI operation.
type OperationDoc struct {
	Method  string     `json:"m"`
	Path    string     `json:"p"`
	Summary string     `json:"s,omitempty"`
	Params  []DocParam `json:"a,omitempty"`
	// BodyFields are the required top-level JSON body properties; Type is "unknown" when not a plain scalar.
	BodyFields []DocParam `json:"b,omitempty"`
	// BodyRequired is set when a required body is a renderable JSON object, even one with no required fields.
	BodyRequired bool `json:"q,omitempty"`
	// BodyGap is non-empty when a required body is not a JSON object the template can render.
	BodyGap string `json:"g,omitempty"`
	// BodySkipped is set when an optional body is not a JSON object the template can render.
	BodySkipped bool `json:"u,omitempty"`
	// ResponseType is the first media type of the 200 (else first 2xx) response; "" when it has no content.
	ResponseType string `json:"rt,omitempty"`
	LinkPaged    bool   `json:"l,omitempty"`
	// Server is the operation's server URL (operation over path item over document), "" when it is the default.
	Server string `json:"sv,omitempty"`
}

// OperationDocs is the distilled documentation of every operation, keyed by operation ID.
type OperationDocs struct {
	Version string                  `json:"v"`
	SHA256  string                  `json:"h"`
	Ops     map[string]OperationDoc `json:"o"`
	// MultiSegment lists, sorted, the path parameter names the gate treats as catch-alls (x-multi-segment).
	MultiSegment []string `json:"x,omitempty"`
}

// docRawParam keeps every field except $ref untyped, so one parameter with an odd value (a non-string
// description, say) degrades only that field instead of rejecting the whole document.
type docRawParam struct {
	Ref         string `json:"$ref"`
	Name        any    `json:"name"`
	In          any    `json:"in"`
	Required    any    `json:"required"`
	Description any    `json:"description"`
	Schema      any    `json:"schema"`
}

type docRawProp struct {
	Type        any    `json:"type"`
	Description string `json:"description"`
	OneOf       []any  `json:"oneOf"`
	AnyOf       []any  `json:"anyOf"`
	AllOf       []any  `json:"allOf"`
}

type docRawSchema struct {
	Ref        string                `json:"$ref"`
	Type       any                   `json:"type"`
	Required   []string              `json:"required"`
	Properties map[string]docRawProp `json:"properties"`
}

// docRawBody holds each media type's schema undecoded: an inline schema is decoded only when its operation's
// body is rendered, so one malformed schema cannot reject the whole document.
type docRawBody struct {
	Ref      string `json:"$ref"`
	Required bool   `json:"required"`
	Content  map[string]struct {
		Schema json.RawMessage `json:"schema"`
	} `json:"content"`
}

type docRawResponse struct {
	Content map[string]json.RawMessage `json:"content"`
	Headers map[string]json.RawMessage `json:"headers"`
}

type docRawServer struct {
	URL string `json:"url"`
}

type docRawOp struct {
	Servers     []docRawServer            `json:"servers"`
	OperationID string                    `json:"operationId"`
	Summary     string                    `json:"summary"`
	Parameters  []docRawParam             `json:"parameters"`
	RequestBody *docRawBody               `json:"requestBody"`
	Responses   map[string]docRawResponse `json:"responses"`
}

type docRawPathItem struct {
	Servers    []docRawServer `json:"servers"`
	Parameters []docRawParam  `json:"parameters"`
	Get        *docRawOp      `json:"get"`
	Head       *docRawOp      `json:"head"`
	Post       *docRawOp      `json:"post"`
	Put        *docRawOp      `json:"put"`
	Patch      *docRawOp      `json:"patch"`
	Delete     *docRawOp      `json:"delete"`
	Options    *docRawOp      `json:"options"`
}

type docRawDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Servers    []docRawServer            `json:"servers"`
	Paths      map[string]docRawPathItem `json:"paths"`
	Components struct {
		Parameters map[string]docRawParam     `json:"parameters"`
		Schemas    map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

// DistillDocs distills the public OpenAPI description into operation docs. It is separate from the gate's
// table distiller and never runs on the request path.
func DistillDocs(raw []byte) (*OperationDocs, error) {
	var doc docRawDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	sum := sha256.Sum256(raw)
	out := &OperationDocs{Version: doc.Info.Version, SHA256: hex.EncodeToString(sum[:]), Ops: map[string]OperationDoc{}}
	for path, item := range doc.Paths {
		ops := map[string]*docRawOp{
			"GET": item.Get, "HEAD": item.Head, "POST": item.Post, "PUT": item.Put,
			"PATCH": item.Patch, "DELETE": item.Delete, "OPTIONS": item.Options,
		}
		for method, op := range ops {
			if op == nil || op.OperationID == "" {
				continue
			}
			out.Ops[op.OperationID] = distillOp(&doc, method, path, &item, op)
		}
	}
	var generic any
	_ = json.Unmarshal(raw, &generic) // the typed decode above already accepted these bytes.
	for name := range collectMultiSegment(generic) {
		out.MultiSegment = append(out.MultiSegment, name)
	}
	slices.Sort(out.MultiSegment)
	if err := AdmitDocs(out); err != nil {
		return nil, err
	}
	return out, nil
}

func distillOp(doc *docRawDoc, method, path string, item *docRawPathItem, op *docRawOp) OperationDoc {
	d := OperationDoc{
		Method:  method,
		Path:    path,
		Summary: apiref.StripMarkup(op.Summary, apiref.MaxSummary),
		Params:  mergeParams(resolveParams(doc, item.Parameters), resolveParams(doc, op.Parameters)),
	}
	if server := serverURL(op.Servers, item.Servers, doc.Servers); server != docEndpoint {
		d.Server = server
	}
	if rb := op.RequestBody; rb != nil {
		fields, ok := bodyFields(doc, rb)
		switch {
		case rb.Required && ok:
			d.BodyFields = fields
			d.BodyRequired = true
		case rb.Required:
			d.BodyGap = docBodyGap
		case !ok || len(fields) > 0:
			// An optional body never adds inputs or gaps; the template omits it.
			d.BodySkipped = true
		}
	}
	d.ResponseType = responseType(op.Responses)
	d.LinkPaged = linkPaged(d.Params, op.Responses)
	return d
}

// serverURL is the first server URL of the first non-empty list, with no trailing slash, or docEndpoint when every
// list is empty.
func serverURL(lists ...[]docRawServer) string {
	for _, servers := range lists {
		if len(servers) > 0 {
			return strings.TrimRight(servers[0].URL, "/")
		}
	}
	return docEndpoint
}

func resolveParams(doc *docRawDoc, in []docRawParam) []DocParam {
	var out []DocParam
	for _, p := range in {
		if p.Ref != "" {
			name, ok := strings.CutPrefix(p.Ref, docParamRefPrefix)
			if !ok {
				continue
			}
			if p, ok = doc.Components.Parameters[name]; !ok {
				continue
			}
		}
		out = append(out, DocParam{
			Name:        text(p.Name),
			In:          text(p.In),
			Type:        typeName(schemaType(p.Schema)),
			Required:    p.Required == true,
			Description: apiref.StripMarkup(text(p.Description), apiref.MaxInputDescription),
		})
	}
	return out
}

// text returns v when it is a string and "" otherwise.
func text(v any) string {
	s, _ := v.(string)
	return s
}

// schemaType returns the "type" of a parameter schema, or nil when the schema is not an object.
func schemaType(schema any) any {
	m, _ := schema.(map[string]any)
	return m["type"]
}

func typeName(t any) string {
	if s := text(t); s != "" {
		return s
	}
	return docUnknownType
}

// mergeParams lets an operation-level parameter replace a path-level one with the same name and location.
func mergeParams(shared, own []DocParam) []DocParam {
	out := slices.Clone(shared)
	for _, p := range own {
		i := slices.IndexFunc(out, func(q DocParam) bool { return q.Name == p.Name && q.In == p.In })
		if i < 0 {
			out = append(out, p)
			continue
		}
		out[i] = p
	}
	return out
}

// bodyFields returns the required properties of a JSON object body. ok is false when the body is not one the
// template can render.
func bodyFields(doc *docRawDoc, rb *docRawBody) ([]DocParam, bool) {
	media, hasJSON := rb.Content[docJSONMedia]
	if rb.Ref != "" || !hasJSON {
		return nil, false
	}
	var schema docRawSchema
	if json.Unmarshal(media.Schema, &schema) != nil {
		return nil, false
	}
	if schema.Ref != "" {
		var ok bool
		if schema, ok = doc.schema(schema.Ref); !ok {
			return nil, false
		}
	}
	if schema.Type != "object" {
		return nil, false
	}
	names := slices.Clone(schema.Required)
	slices.Sort(names)
	fields := make([]DocParam, 0, len(names))
	for _, n := range names {
		prop := schema.Properties[n]
		fields = append(fields, DocParam{
			Name:        n,
			In:          string(apiref.LocationBody),
			Type:        bodyType(prop),
			Required:    true,
			Description: apiref.StripMarkup(prop.Description, apiref.MaxInputDescription),
		})
	}
	return fields, true
}

// schema decodes the component schema ref names, and only that one, so a malformed schema nothing references
// cannot reject the document.
func (d *docRawDoc) schema(ref string) (docRawSchema, bool) {
	var s docRawSchema
	name, ok := strings.CutPrefix(ref, docSchemaRefPrefix)
	if !ok {
		return s, false
	}
	raw, ok := d.Components.Schemas[name]
	if !ok {
		return s, false
	}
	return s, json.Unmarshal(raw, &s) == nil
}

func bodyType(p docRawProp) string {
	if len(p.OneOf)+len(p.AnyOf)+len(p.AllOf) > 0 {
		return docUnknownType
	}
	if s, _ := p.Type.(string); isScalar(s) {
		return s
	}
	return docUnknownType
}

func isScalar(t string) bool {
	switch t {
	case "string", "integer", "number", "boolean":
		return true
	}
	return false
}

// responseType is the first media type of the 200 response (empty when it has no content), else of the first
// 2xx response with content.
func responseType(resp map[string]docRawResponse) string {
	var codes []string
	for code := range resp {
		if strings.HasPrefix(code, "2") {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	if r, ok := resp[docOKStatus]; ok {
		return firstMedia(r)
	}
	for _, code := range codes {
		if mt := firstMedia(resp[code]); mt != "" {
			return mt
		}
	}
	return ""
}

func firstMedia(r docRawResponse) string {
	var types []string
	for mt := range r.Content {
		types = append(types, mt)
	}
	if len(types) == 0 {
		return ""
	}
	return slices.Min(types)
}

func linkPaged(params []DocParam, resp map[string]docRawResponse) bool {
	has := func(name string) bool {
		return slices.ContainsFunc(params, func(p DocParam) bool { return p.Name == name })
	}
	_, link := resp[docOKStatus].Headers[docLink]
	return has(docPerPage) && has(docPage) && link
}

// UnmarshalDocs parses serialized operation docs.
func UnmarshalDocs(b []byte) (*OperationDocs, error) {
	var d OperationDocs
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	return &d, nil
}

// Serialize encodes the docs for caching.
func (d *OperationDocs) Serialize() []byte {
	// OperationDocs is plain strings, bools, slices and a string-keyed map, so json.Marshal cannot fail.
	b, _ := json.Marshal(d)
	return b
}

// AdmitDocs rejects docs that name no operation.
func AdmitDocs(d *OperationDocs) error {
	if len(d.Ops) == 0 {
		return fmt.Errorf("%w: no operations", ErrDocsRejected)
	}
	return nil
}

// Reference looks up the operation q names.
func (d *OperationDocs) Reference(q apiref.Query) apiref.Result {
	id := q.Operation
	if _, ok := d.Ops[id]; !ok {
		var folded []string
		for n := range d.Ops {
			if strings.EqualFold(n, q.Operation) {
				folded = append(folded, n)
			}
		}
		switch len(folded) {
		case 0:
			return apiref.Result{
				Outcome: apiref.OutcomeNotFound,
				Reason:  apiref.Truncate(fmt.Sprintf("no operation %q in github", q.Operation), apiref.MaxReason),
			}
		case 1:
			id = folded[0]
		default:
			return apiref.Result{
				Outcome: apiref.OutcomeAmbiguous,
				Reason:  apiref.Truncate("several operations differ only by case", apiref.MaxReason),
				Choices: apiref.Choices(folded),
			}
		}
	}
	ref := d.build(id, d.Ops[id])
	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

func (d *OperationDocs) build(id string, op OperationDoc) *apiref.Reference {
	ref := &apiref.Reference{
		Connector:    "github",
		Operation:    id,
		Protocol:     docProtocol,
		Method:       op.Method,
		PathTemplate: op.Path,
		Summary:      op.Summary,
		Endpoint:     docEndpoint,
		BodyEncoding: apiref.BodyNone,
		FixedHeaders: []apiref.Param{{Key: "Accept", Value: docAccept}},
		Response:     docResponse(op.ResponseType),
		Pagination:   apiref.Pagination{Style: apiref.PaginationUnspecified},
		Limitations:  []string{docVersionLimit},
		Source: apiref.Source{
			Name: docSourceName, Document: docSourceDocument, Version: d.Version, SHA256: d.SHA256,
		},
	}
	if op.LinkPaged {
		ref.Pagination = apiref.Pagination{Style: "link-header", InputToken: docPage, PageSize: docPerPage}
		ref.Limitations = append(ref.Limitations, docLinkLimit)
	}
	if op.BodyRequired || len(op.BodyFields) > 0 {
		ref.BodyEncoding = apiref.BodyJSON
		ref.FixedHeaders = append(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: docJSONMedia})
	}
	if op.Server != "" {
		ref.Endpoint = op.Server
		ref.Gaps = append(ref.Gaps, fmt.Sprintf(docServerGap, op.Server))
	}
	if op.BodyGap != "" {
		ref.Gaps = append(ref.Gaps, op.BodyGap)
	}
	if op.BodySkipped {
		ref.Limitations = append(ref.Limitations, docBodySkipped)
	}
	docInputs(ref, op)
	return ref
}

func docResponse(mediaType string) apiref.Response {
	switch {
	case mediaType == "":
		return apiref.Response{Encoding: "none", Parse: "no response body; read the status and headers"}
	case mediaType == docJSONMedia || strings.HasSuffix(mediaType, "+json"):
		return apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}
	}
	return apiref.Response{
		Encoding: mediaType,
		Parse:    "the body is " + mediaType + " text, not JSON; read response.body as a string",
	}
}

// docInputs lists every required input and the first MaxOptionalInputs optional ones, and records a gap for
// each required input the template cannot render.
func docInputs(ref *apiref.Reference, op OperationDoc) {
	ref.Inputs = []apiref.Input{}
	var all []apiref.Input
	for _, loc := range []apiref.Location{apiref.LocationPath, apiref.LocationQuery, apiref.LocationHeader} {
		for _, p := range op.Params {
			if p.In == string(loc) {
				all = append(all, docInput(p, loc))
			}
		}
	}
	for _, p := range op.BodyFields {
		all = append(all, docInput(p, apiref.LocationBody))
	}
	if op.BodyGap != "" {
		all = append(all, apiref.Input{
			Name: "body", WireName: "body", Location: apiref.LocationBody, Required: true, Type: docUnknownType,
		})
	}
	optional := 0
	for _, in := range all {
		if !in.Required {
			if optional == apiref.MaxOptionalInputs {
				ref.InputsTruncated = true
				continue
			}
			optional++
		}
		if in.Required && !in.Renderable {
			ref.Gaps = append(ref.Gaps, fmt.Sprintf("required input %s (%s in %s) cannot be rendered",
				in.Name, in.Type, in.Location))
		}
		ref.Inputs = append(ref.Inputs, in)
	}
}

func docInput(p DocParam, loc apiref.Location) apiref.Input {
	return apiref.Input{
		Name:        p.Name,
		WireName:    p.Name,
		Location:    loc,
		Required:    p.Required,
		Type:        p.Type,
		Renderable:  isScalar(p.Type),
		Description: p.Description,
	}
}

// Hint suggests a fix for a request that matches no documented operation.
func (d *OperationDocs) Hint(v authreq.View) apiref.Hint {
	routes := make([]apiref.Route, 0, len(d.Ops))
	for id, op := range d.Ops {
		routes = append(routes, apiref.Route{Operation: id, Method: op.Method, Template: d.hintTemplate(op.Path)})
	}
	method := strings.ToUpper(strings.TrimSpace(v.Method))
	// The gate looks HEAD and OPTIONS up as GET, so the hint does too.
	if method == http.MethodHead || method == http.MethodOptions {
		method = http.MethodGet
	}
	h := apiref.Hint{Candidates: apiref.Candidates(routes, method, v.EscapedPath)}
	if ops := apiref.CandidateOperations(routes, method, v.EscapedPath); len(ops) == 1 {
		h.Operation = ops[0]
	}
	return h
}

// hintTemplate rewrites a trailing {name} whose parameter is multi-segment to {name*}, so the matcher treats it as
// the catch-all the gate does, which takes zero or more segments.
func (d *OperationDocs) hintTemplate(path string) string {
	i := strings.LastIndex(path, "/")
	last := path[i+1:]
	name, ok := strings.CutSuffix(strings.TrimPrefix(last, "{"), "}")
	if !ok || !strings.HasPrefix(last, "{") || !slices.Contains(d.MultiSegment, name) {
		return path
	}
	return path[:i+1] + "{" + name + "*}"
}
