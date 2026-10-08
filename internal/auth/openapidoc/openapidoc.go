// Package openapidoc distills an OpenAPI 3 description into the compact operation docs that api_reference and the
// unmatched-request hint read, and builds references and hint routes from them. What differs per connector comes
// in a Profile. The package does no I/O and imports only the standard library and internal/apiref.
package openapidoc

import (
	"context"
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
	stringType      = "string"
	paramRefPrefix  = "#/components/parameters/"
	schemaRefPrefix = "#/components/schemas/"
	jsonMedia       = "application/json"
	bodySkipped     = "optional request body is not rendered"
	bodyGap         = "request body is not a JSON object the template can render"
	serverGap       = "operation is served from %s, not from the %s connector's API host %s"
	unspecifiedNote = "the document does not describe this operation's response format; check the Content-Type " +
		"response header before parsing"
	okStatus = "200"
)

// Profile is what one connector's references differ in.
type Profile struct {
	Connector      string
	Protocol       string
	SourceName     string
	SourceDocument string
	// Endpoint is the base URL the connector calls. Distill records an operation's own server when it differs, and
	// ignores the document's servers when Endpoint is empty.
	Endpoint     string
	FixedHeaders []apiref.Param
	// ScalarUnion renders a parameter whose schema is oneOf exactly a string and an integer as a string.
	ScalarUnion bool
	// Paged reports at distill time whether an operation pages its results. headers are the header names its 200
	// response declares, sorted. It must be set.
	Paged func(params []DocParam, headers []string) bool
	// Paging is the pagination a paged operation reports, and PagingLimit the limitation that comes with it.
	Paging      apiref.Pagination
	PagingLimit string
	// Limitations apply to every reference.
	Limitations []string
	// UnspecifiedResponse reports a selected success response that declares no content as unspecified, with a
	// limitation, instead of as having no body. It suits a document that often omits response content.
	UnspecifiedResponse bool
	// Refuse reports an input the connector rejects whatever the permission level. A refused input is left out of
	// the inputs and the template, and a required one is a gap. Nil refuses nothing.
	Refuse func(loc apiref.Location, name string) bool
	// Keep reports whether an operation is distilled. Nil keeps every operation.
	Keep func(method, path, operationID string) bool
	// SkipBodies records every required request body as a gap and every optional one as skipped, without decoding
	// a schema.
	SkipBodies bool
	// MaxTextBytes, when above zero, cuts each summary and description to that many bytes before its markup is
	// stripped (apiref.StripMarkupCut). Zero strips the whole text.
	MaxTextBytes int
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
	// Alt lists other concrete forms of Path that a hint should also match.
	Alt []string `json:"ap,omitempty"`
	// Gaps are blocking gaps a connector's distiller recorded for the operation.
	Gaps []string `json:"gp,omitempty"`
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

// rawParam keeps every field except $ref as raw JSON, so one parameter with an odd value (a non-string
// description, say) degrades only that field instead of rejecting the whole document, and a wide schema costs its
// bytes rather than a tree of Go maps. Each field is converted where it is read.
type rawParam struct {
	Ref         string          `json:"$ref"`
	Name        json.RawMessage `json:"name"`
	In          json.RawMessage `json:"in"`
	Required    json.RawMessage `json:"required"`
	Description json.RawMessage `json:"description"`
	Schema      json.RawMessage `json:"schema"`
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

// distiller is one distillation: the decoded document, the profile, and each component parameter converted once
// and shared by every operation that references it.
type distiller struct {
	doc        *rawDoc
	prof       *Profile
	components map[string]DocParam
}

// Distill distills an OpenAPI 3 description, as JSON, into operation docs. It runs when a docs cache loads: on an
// api_reference lookup, or synchronously on the denial path when an unmatched request needs a hint and the cache is
// cold.
func Distill(raw []byte, prof Profile) (*OperationDocs, error) {
	return DistillContext(context.Background(), raw, prof)
}

// DistillContext is Distill that checks ctx before each path item. The one decode of the document is not
// interruptible.
func DistillContext(ctx context.Context, raw []byte, prof Profile) (*OperationDocs, error) {
	var doc rawDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	sum := sha256.Sum256(raw)
	out := &OperationDocs{Version: doc.Info.Version, SHA256: hex.EncodeToString(sum[:]), Ops: map[string]OperationDoc{}}
	d := &distiller{doc: &doc, prof: &prof, components: map[string]DocParam{}}
	for path, item := range doc.Paths {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("openapidoc: distill: %w", err)
		}
		ops := map[string]*rawOp{
			"GET": item.Get, "HEAD": item.Head, "POST": item.Post, "PUT": item.Put,
			"PATCH": item.Patch, "DELETE": item.Delete, "OPTIONS": item.Options,
		}
		for method, op := range ops {
			if op == nil || op.OperationID == "" {
				continue
			}
			if prof.Keep != nil && !prof.Keep(method, path, op.OperationID) {
				continue
			}
			out.Ops[op.OperationID] = d.op(method, path, &item, op)
		}
	}
	if err := Admit(out); err != nil {
		return nil, err
	}
	return out, nil
}

// text strips markup from a summary or description, cutting it first when the profile bounds text.
func (p *Profile) text(s string, maxRunes int) string {
	if p.MaxTextBytes > 0 {
		return apiref.StripMarkupCut(s, p.MaxTextBytes, maxRunes)
	}
	return apiref.StripMarkup(s, maxRunes)
}

func (d *distiller) op(method, path string, item *rawPathItem, op *rawOp) OperationDoc {
	out := OperationDoc{
		Method:  method,
		Path:    path,
		Summary: d.prof.text(op.Summary, apiref.MaxSummary),
		Params:  mergeParams(d.params(item.Parameters), d.params(op.Parameters)),
	}
	if d.prof.Endpoint != "" {
		if server := serverURL(d.prof.Endpoint, op.Servers, item.Servers, d.doc.Servers); server != d.prof.Endpoint {
			out.Server = server
		}
	}
	if rb := op.RequestBody; rb != nil {
		d.body(&out, rb)
	}
	out.ResponseType = responseType(op.Responses)
	out.Paged = d.prof.Paged(out.Params, okHeaders(op.Responses))
	return out
}

// body records a request body on out: its required fields, a gap, or a skipped optional body. Under SkipBodies no
// schema is decoded.
func (d *distiller) body(out *OperationDoc, rb *rawBody) {
	if d.prof.SkipBodies {
		if rb.Required {
			out.BodyGap = bodyGap
			return
		}
		out.BodySkipped = true
		return
	}
	fields, ok := d.bodyFields(rb)
	switch {
	case rb.Required && ok:
		out.BodyFields = fields
		out.BodyRequired = true
	case rb.Required:
		out.BodyGap = bodyGap
	case !ok || len(fields) > 0:
		// An optional body never adds inputs or gaps; the template omits it.
		out.BodySkipped = true
	}
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

// params converts a parameter list. A reference to a component parameter is converted once per distillation; a
// reference that is not to a component parameter, or names none, is dropped.
func (d *distiller) params(in []rawParam) []DocParam {
	var out []DocParam
	for _, p := range in {
		if p.Ref == "" {
			out = append(out, d.param(p))
			continue
		}
		name, ok := strings.CutPrefix(p.Ref, paramRefPrefix)
		if !ok {
			continue
		}
		conv, done := d.components[name]
		if !done {
			comp, found := d.doc.Components.Parameters[name]
			if !found {
				continue
			}
			conv = d.param(comp)
			d.components[name] = conv
		}
		out = append(out, conv)
	}
	return out
}

// param converts one parameter: a non-string name, location, description or type is empty, and only JSON true
// makes it required.
func (d *distiller) param(p rawParam) DocParam {
	return DocParam{
		Name:        text(p.Name),
		In:          text(p.In),
		Type:        paramType(p.Schema, d.prof.ScalarUnion),
		Required:    string(p.Required) == "true",
		Description: d.prof.text(text(p.Description), apiref.MaxInputDescription),
	}
}

// text returns raw as a string when it is a JSON string and "" otherwise.
func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// schemaMembers decodes a schema's members by exact key, the last of repeated keys winning, or nil when it is not
// an object. It never decodes into a struct, which would also bind a key spelled Type.
func schemaMembers(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// paramType is the parameter schema's type, "string" for a oneOf of exactly a string and an integer when union is
// set, and "unknown" otherwise.
func paramType(schema json.RawMessage, union bool) string {
	m := schemaMembers(schema)
	if s := text(m["type"]); s != "" {
		return s
	}
	if union && isScalarUnion(m) {
		return stringType
	}
	return unknownType
}

// isScalarUnion reports a schema that is oneOf exactly two alternatives typed string and integer.
func isScalarUnion(m map[string]json.RawMessage) bool {
	var alts []json.RawMessage
	if json.Unmarshal(m["oneOf"], &alts) != nil {
		return false
	}
	types := make([]string, 0, len(alts))
	for _, alt := range alts {
		types = append(types, text(schemaMembers(alt)["type"]))
	}
	slices.Sort(types)
	return slices.Equal(types, []string{"integer", stringType})
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
func (d *distiller) bodyFields(rb *rawBody) ([]DocParam, bool) {
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
		if schema, ok = d.doc.schema(schema.Ref); !ok {
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
			Description: d.prof.text(prop.Description, apiref.MaxInputDescription),
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
	case stringType, "integer", "number", "boolean":
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

// firstMedia is application/json when the response lists it, otherwise the alphabetically first media type.
func firstMedia(r rawResponse) string {
	if _, ok := r.Content[jsonMedia]; ok {
		return jsonMedia
	}
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

// Routes lists every operation's method and path, and each alternate form of the path, as hint routes.
func (d *OperationDocs) Routes() []apiref.Route {
	routes := make([]apiref.Route, 0, len(d.Ops))
	for id, op := range d.Ops {
		routes = append(routes, apiref.Route{Operation: id, Method: op.Method, Template: op.Path})
		for _, alt := range op.Alt {
			routes = append(routes, apiref.Route{Operation: id, Method: op.Method, Template: alt})
		}
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
	if op.ResponseType == "" && prof.UnspecifiedResponse {
		ref.Response = apiref.Response{
			Encoding: "unspecified",
			Parse:    "the document does not describe the response; read Content-Type before parsing response.body",
		}
		ref.Limitations = append(ref.Limitations, unspecifiedNote)
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
	ref.Gaps = append(ref.Gaps, op.Gaps...)
	if op.BodySkipped {
		ref.Limitations = append(ref.Limitations, bodySkipped)
	}
	inputs(ref, op, prof)
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
// required input the template cannot render or the profile refuses.
func inputs(ref *apiref.Reference, op OperationDoc, prof *Profile) {
	ref.Inputs = []apiref.Input{}
	optional := 0
	for _, in := range allInputs(op) {
		if prof.refuses(in) {
			if in.Required {
				ref.Gaps = append(ref.Gaps, fmt.Sprintf("required input %s is a credential the %s connector refuses",
					in.Name, prof.Connector))
			}
			continue
		}
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

// allInputs lists the operation's inputs: path, query and header parameters, then body fields, then a placeholder
// for a required body the template cannot render.
func allInputs(op OperationDoc) []apiref.Input {
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
	return all
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

// refuses reports an input the profile's Refuse rejects.
func (p *Profile) refuses(in apiref.Input) bool {
	return p.Refuse != nil && p.Refuse(in.Location, in.Name)
}
