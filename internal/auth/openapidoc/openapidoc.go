// Package openapidoc distills an OpenAPI 3 description into the compact operation docs that api_reference and the
// unmatched-request hint read, and builds references and hint routes from them. What differs per connector comes
// in a Profile. The package does no I/O and imports only the standard library and internal/apiref.
package openapidoc

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
)

// ErrDocsRejected reports operation docs that are unparseable or empty.
var ErrDocsRejected = errors.New("openapidoc: operation docs rejected")

const (
	unknownType     = "unknown"
	paramRefPrefix  = "#/components/parameters/"
	schemaRefPrefix = "#/components/schemas/"
	jsonMedia       = "application/json"
	bodySkipped     = "optional request body is not rendered"
	bodyGap         = "request body is not a JSON object the template can render"
	serverGap       = "operation is served from %s, not from the %s connector's API host %s"
	okStatus        = "200"
)

// Profile is what one connector's references differ in.
type Profile struct {
	Connector      string
	Protocol       string
	SourceName     string
	SourceDocument string
	// Endpoint is the base URL the connector calls. Distill records an operation's own server when it differs.
	Endpoint     string
	FixedHeaders []apiref.Param
	// Paged reports at distill time whether an operation pages its results. headers are the header names its 200
	// response declares, sorted. It must be set.
	Paged func(params []DocParam, headers []string) bool
	// Paging is the pagination a paged operation reports, and PagingLimit the limitation that comes with it.
	Paging      apiref.Pagination
	PagingLimit string
	// Limitations apply to every reference.
	Limitations []string
}

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
	// Paged is the profile's Paged verdict for the operation.
	Paged bool `json:"l,omitempty"`
	// Server is the operation's server URL (operation over path item over document), "" when it is the default.
	Server string `json:"sv,omitempty"`
}

// OperationDocs is the distilled documentation of every operation, keyed by operation ID.
type OperationDocs struct {
	Version string                  `json:"v"`
	SHA256  string                  `json:"h"`
	Ops     map[string]OperationDoc `json:"o"`
	// MultiSegment lists, sorted, the path parameter names a connector's gate treats as catch-alls. Only GitHub
	// sets it.
	MultiSegment []string `json:"x,omitempty"`
}

// rawParam keeps every field except $ref untyped, so one parameter with an odd value (a non-string description,
// say) degrades only that field instead of rejecting the whole document.
type rawParam struct {
	Ref         string `json:"$ref"`
	Name        any    `json:"name"`
	In          any    `json:"in"`
	Required    any    `json:"required"`
	Description any    `json:"description"`
	Schema      any    `json:"schema"`
}

type rawProp struct {
	Type        any    `json:"type"`
	Description string `json:"description"`
	OneOf       []any  `json:"oneOf"`
	AnyOf       []any  `json:"anyOf"`
	AllOf       []any  `json:"allOf"`
}

type rawSchema struct {
	Ref        string             `json:"$ref"`
	Type       any                `json:"type"`
	Required   []string           `json:"required"`
	Properties map[string]rawProp `json:"properties"`
}

// rawBody holds each media type's schema undecoded: an inline schema is decoded only when its operation's body is
// rendered, so one malformed schema cannot reject the whole document.
type rawBody struct {
	Ref      string `json:"$ref"`
	Required bool   `json:"required"`
	Content  map[string]struct {
		Schema json.RawMessage `json:"schema"`
	} `json:"content"`
}

type rawResponse struct {
	Content map[string]json.RawMessage `json:"content"`
	Headers map[string]json.RawMessage `json:"headers"`
}

type rawServer struct {
	URL string `json:"url"`
}

type rawOp struct {
	Servers     []rawServer            `json:"servers"`
	OperationID string                 `json:"operationId"`
	Summary     string                 `json:"summary"`
	Parameters  []rawParam             `json:"parameters"`
	RequestBody *rawBody               `json:"requestBody"`
	Responses   map[string]rawResponse `json:"responses"`
}

type rawPathItem struct {
	Servers    []rawServer `json:"servers"`
	Parameters []rawParam  `json:"parameters"`
	Get        *rawOp      `json:"get"`
	Head       *rawOp      `json:"head"`
	Post       *rawOp      `json:"post"`
	Put        *rawOp      `json:"put"`
	Patch      *rawOp      `json:"patch"`
	Delete     *rawOp      `json:"delete"`
	Options    *rawOp      `json:"options"`
}

type rawDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Servers    []rawServer            `json:"servers"`
	Paths      map[string]rawPathItem `json:"paths"`
	Components struct {
		Parameters map[string]rawParam        `json:"parameters"`
		Schemas    map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

// Distill distills an OpenAPI 3 description, as JSON, into operation docs. It runs when a docs cache loads: on an
// api_reference lookup, or synchronously on the denial path when an unmatched request needs a hint and the cache is
// cold.
func Distill(raw []byte, prof Profile) (*OperationDocs, error) {
	var doc rawDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	sum := sha256.Sum256(raw)
	out := &OperationDocs{Version: doc.Info.Version, SHA256: hex.EncodeToString(sum[:]), Ops: map[string]OperationDoc{}}
	for path, item := range doc.Paths {
		ops := map[string]*rawOp{
			"GET": item.Get, "HEAD": item.Head, "POST": item.Post, "PUT": item.Put,
			"PATCH": item.Patch, "DELETE": item.Delete, "OPTIONS": item.Options,
		}
		for method, op := range ops {
			if op == nil || op.OperationID == "" {
				continue
			}
			out.Ops[op.OperationID] = distillOp(&doc, &prof, method, path, &item, op)
		}
	}
	if err := Admit(out); err != nil {
		return nil, err
	}
	return out, nil
}

func distillOp(doc *rawDoc, prof *Profile, method, path string, item *rawPathItem, op *rawOp) OperationDoc {
	d := OperationDoc{
		Method:  method,
		Path:    path,
		Summary: apiref.StripMarkup(op.Summary, apiref.MaxSummary),
		Params:  mergeParams(resolveParams(doc, item.Parameters), resolveParams(doc, op.Parameters)),
	}
	if server := serverURL(prof.Endpoint, op.Servers, item.Servers, doc.Servers); server != prof.Endpoint {
		d.Server = server
	}
	if rb := op.RequestBody; rb != nil {
		fields, ok := bodyFields(doc, rb)
		switch {
		case rb.Required && ok:
			d.BodyFields = fields
			d.BodyRequired = true
		case rb.Required:
			d.BodyGap = bodyGap
		case !ok || len(fields) > 0:
			// An optional body never adds inputs or gaps; the template omits it.
			d.BodySkipped = true
		}
	}
	d.ResponseType = responseType(op.Responses)
	d.Paged = prof.Paged(d.Params, okHeaders(op.Responses))
	return d
}

// serverURL is the first server URL of the first non-empty list, with no trailing slash, or def when every list
// is empty.
func serverURL(def string, lists ...[]rawServer) string {
	for _, servers := range lists {
		if len(servers) > 0 {
			return strings.TrimRight(servers[0].URL, "/")
		}
	}
	return def
}

func resolveParams(doc *rawDoc, in []rawParam) []DocParam {
	var out []DocParam
	for _, p := range in {
		if p.Ref != "" {
			name, ok := strings.CutPrefix(p.Ref, paramRefPrefix)
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
	return unknownType
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
func bodyFields(doc *rawDoc, rb *rawBody) ([]DocParam, bool) {
	media, hasJSON := rb.Content[jsonMedia]
	if rb.Ref != "" || !hasJSON {
		return nil, false
	}
	var schema rawSchema
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
func (d *rawDoc) schema(ref string) (rawSchema, bool) {
	var s rawSchema
	name, ok := strings.CutPrefix(ref, schemaRefPrefix)
	if !ok {
		return s, false
	}
	raw, ok := d.Components.Schemas[name]
	if !ok {
		return s, false
	}
	return s, json.Unmarshal(raw, &s) == nil
}

func bodyType(p rawProp) string {
	if len(p.OneOf)+len(p.AnyOf)+len(p.AllOf) > 0 {
		return unknownType
	}
	if s, _ := p.Type.(string); isScalar(s) {
		return s
	}
	return unknownType
}

func isScalar(t string) bool {
	switch t {
	case "string", "integer", "number", "boolean":
		return true
	}
	return false
}

// responseType is the first media type of the 200 response (empty when it has no content), else of the first 2xx
// response with content.
func responseType(resp map[string]rawResponse) string {
	var codes []string
	for code := range resp {
		if strings.HasPrefix(code, "2") {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	if r, ok := resp[okStatus]; ok {
		return firstMedia(r)
	}
	for _, code := range codes {
		if mt := firstMedia(resp[code]); mt != "" {
			return mt
		}
	}
	return ""
}

func firstMedia(r rawResponse) string {
	var types []string
	for mt := range r.Content {
		types = append(types, mt)
	}
	if len(types) == 0 {
		return ""
	}
	return slices.Min(types)
}

// okHeaders lists, sorted, the header names the 200 response declares.
func okHeaders(resp map[string]rawResponse) []string {
	var names []string
	for name := range resp[okStatus].Headers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Unmarshal parses serialized operation docs.
func Unmarshal(b []byte) (*OperationDocs, error) {
	var d OperationDocs
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	return &d, nil
}

// Admit rejects docs that name no operation.
func Admit(d *OperationDocs) error {
	if len(d.Ops) == 0 {
		return fmt.Errorf("%w: no operations", ErrDocsRejected)
	}
	return nil
}

// LookupMethod is the method a gate looks a request up under: trimmed and upper-cased, with HEAD and OPTIONS read
// as GET.
func LookupMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == http.MethodHead || m == http.MethodOptions {
		return http.MethodGet
	}
	return m
}

// Serialize encodes the docs for caching.
func (d *OperationDocs) Serialize() []byte {
	// OperationDocs is plain strings, bools, slices and a string-keyed map, so json.Marshal cannot fail.
	b, _ := json.Marshal(d)
	return b
}

// Reference looks up the operation q names: exactly, then case-insensitively.
func (d *OperationDocs) Reference(q apiref.Query, prof Profile) apiref.Result {
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
				Reason: apiref.Truncate(
					fmt.Sprintf("no operation %q in %s", q.Operation, prof.Connector),
					apiref.MaxReason,
				),
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
	ref := d.build(id, d.Ops[id], &prof)
	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

// Routes lists every operation's method and path as hint routes.
func (d *OperationDocs) Routes() []apiref.Route {
	routes := make([]apiref.Route, 0, len(d.Ops))
	for id, op := range d.Ops {
		routes = append(routes, apiref.Route{Operation: id, Method: op.Method, Template: op.Path})
	}
	return routes
}

func (d *OperationDocs) build(id string, op OperationDoc, prof *Profile) *apiref.Reference {
	ref := &apiref.Reference{
		Connector:    prof.Connector,
		Operation:    id,
		Protocol:     prof.Protocol,
		Method:       op.Method,
		PathTemplate: op.Path,
		Summary:      op.Summary,
		Endpoint:     prof.Endpoint,
		BodyEncoding: apiref.BodyNone,
		FixedHeaders: slices.Clone(prof.FixedHeaders),
		Response:     response(op.ResponseType),
		Pagination:   apiref.Pagination{Style: apiref.PaginationUnspecified},
		Limitations:  slices.Clone(prof.Limitations),
		Source: apiref.Source{
			Name: prof.SourceName, Document: prof.SourceDocument, Version: d.Version, SHA256: d.SHA256,
		},
	}
	if op.Paged {
		ref.Pagination = prof.Paging
		ref.Limitations = append(ref.Limitations, prof.PagingLimit)
	}
	if op.BodyRequired || len(op.BodyFields) > 0 {
		ref.BodyEncoding = apiref.BodyJSON
		ref.FixedHeaders = append(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: jsonMedia})
	}
	if op.Server != "" {
		ref.Endpoint = op.Server
		ref.Gaps = append(ref.Gaps, fmt.Sprintf(serverGap, op.Server, prof.Connector, prof.Endpoint))
	}
	if op.BodyGap != "" {
		ref.Gaps = append(ref.Gaps, op.BodyGap)
	}
	if op.BodySkipped {
		ref.Limitations = append(ref.Limitations, bodySkipped)
	}
	inputs(ref, op)
	return ref
}

func response(mediaType string) apiref.Response {
	switch {
	case mediaType == "":
		return apiref.Response{Encoding: "none", Parse: "no response body; read the status and headers"}
	case mediaType == jsonMedia || strings.HasSuffix(mediaType, "+json"):
		return apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}
	}
	return apiref.Response{
		Encoding: mediaType,
		Parse:    "the body is " + mediaType + " text, not JSON; read response.body as a string",
	}
}

// inputs lists every required input and the first MaxOptionalInputs optional ones, and records a gap for each
// required input the template cannot render.
func inputs(ref *apiref.Reference, op OperationDoc) {
	ref.Inputs = []apiref.Input{}
	var all []apiref.Input
	for _, loc := range []apiref.Location{apiref.LocationPath, apiref.LocationQuery, apiref.LocationHeader} {
		for _, p := range op.Params {
			if p.In == string(loc) {
				all = append(all, input(p, loc))
			}
		}
	}
	for _, p := range op.BodyFields {
		all = append(all, input(p, apiref.LocationBody))
	}
	if op.BodyGap != "" {
		all = append(all, apiref.Input{
			Name: "body", WireName: "body", Location: apiref.LocationBody, Required: true, Type: unknownType,
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

func input(p DocParam, loc apiref.Location) apiref.Input {
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
