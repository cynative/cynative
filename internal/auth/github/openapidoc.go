package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	docBodyGap         = "request body is not a JSON object the template can render"
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
	// BodyGap is non-empty when a required body is not a JSON object the template can render.
	BodyGap string `json:"g,omitempty"`
	// ResponseType is the first media type of the 200 (else first 2xx) response; "" when it has no content.
	ResponseType string `json:"rt,omitempty"`
	LinkPaged    bool   `json:"l,omitempty"`
}

// OperationDocs is the distilled documentation of every operation, keyed by operation ID.
type OperationDocs struct {
	Version string                  `json:"v"`
	SHA256  string                  `json:"h"`
	Ops     map[string]OperationDoc `json:"o"`
}

type docRawParam struct {
	Ref         string `json:"$ref"`
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Schema      struct {
		Type any `json:"type"`
	} `json:"schema"`
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

type docRawBody struct {
	Ref      string `json:"$ref"`
	Required bool   `json:"required"`
	Content  map[string]struct {
		Schema docRawSchema `json:"schema"`
	} `json:"content"`
}

type docRawResponse struct {
	Content map[string]json.RawMessage `json:"content"`
	Headers map[string]json.RawMessage `json:"headers"`
}

type docRawOp struct {
	OperationID string                    `json:"operationId"`
	Summary     string                    `json:"summary"`
	Parameters  []docRawParam             `json:"parameters"`
	RequestBody *docRawBody               `json:"requestBody"`
	Responses   map[string]docRawResponse `json:"responses"`
}

type docRawPathItem struct {
	Parameters []docRawParam `json:"parameters"`
	Get        *docRawOp     `json:"get"`
	Head       *docRawOp     `json:"head"`
	Post       *docRawOp     `json:"post"`
	Put        *docRawOp     `json:"put"`
	Patch      *docRawOp     `json:"patch"`
	Delete     *docRawOp     `json:"delete"`
	Options    *docRawOp     `json:"options"`
}

type docRawDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]docRawPathItem `json:"paths"`
	Components struct {
		Parameters map[string]docRawParam  `json:"parameters"`
		Schemas    map[string]docRawSchema `json:"schemas"`
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
			out.Ops[op.OperationID] = distillOp(&doc, method, path, item.Parameters, op)
		}
	}
	if err := AdmitDocs(out); err != nil {
		return nil, err
	}
	return out, nil
}

func distillOp(doc *docRawDoc, method, path string, shared []docRawParam, op *docRawOp) OperationDoc {
	d := OperationDoc{
		Method:  method,
		Path:    path,
		Summary: apiref.StripMarkup(op.Summary, apiref.MaxSummary),
		Params:  resolveParams(doc, slices.Concat(shared, op.Parameters)),
	}
	d.BodyFields, d.BodyGap = distillBody(doc, op.RequestBody)
	d.ResponseType = responseType(op.Responses)
	d.LinkPaged = linkPaged(d.Params, op.Responses)
	return d
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
			Name:        p.Name,
			In:          p.In,
			Type:        typeName(p.Schema.Type),
			Required:    p.Required,
			Description: apiref.StripMarkup(p.Description, apiref.MaxInputDescription),
		})
	}
	return out
}

func typeName(t any) string {
	if s, _ := t.(string); s != "" {
		return s
	}
	return docUnknownType
}

// distillBody returns the required body properties, or a gap when the body is not a JSON object.
func distillBody(doc *docRawDoc, rb *docRawBody) ([]DocParam, string) {
	if rb == nil {
		return nil, ""
	}
	media, hasJSON := rb.Content[docJSONMedia]
	switch {
	case rb.Ref != "":
		return nil, docBodyGap
	case !hasJSON && rb.Required:
		return nil, docBodyGap
	case !hasJSON:
		return nil, ""
	}
	schema := media.Schema
	if schema.Ref != "" {
		name, ok := strings.CutPrefix(schema.Ref, docSchemaRefPrefix)
		if !ok {
			return nil, docBodyGap
		}
		if schema, ok = doc.Components.Schemas[name]; !ok {
			return nil, docBodyGap
		}
	}
	if schema.Type != "object" {
		return nil, docBodyGap
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
	return fields, ""
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

// responseType is the first media type of the 200 response, else of the first 2xx response with content.
func responseType(resp map[string]docRawResponse) string {
	var codes []string
	for code := range resp {
		if strings.HasPrefix(code, "2") {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	for _, code := range append([]string{docOKStatus}, codes...) {
		var types []string
		for mt := range resp[code].Content {
			types = append(types, mt)
		}
		if len(types) > 0 {
			return slices.Min(types)
		}
	}
	return ""
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
				Choices: docChoices(folded),
			}
		}
	}
	ref := d.build(id, d.Ops[id])
	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

// docChoices sorts, truncates and bounds a choice list.
func docChoices(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	if len(out) > apiref.MaxChoices {
		out = out[:apiref.MaxChoices]
	}
	for i, c := range out {
		out[i] = apiref.Truncate(c, apiref.MaxChoice)
	}
	return out
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
	if len(op.BodyFields) > 0 {
		ref.BodyEncoding = apiref.BodyJSON
		ref.FixedHeaders = append(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: docJSONMedia})
	}
	if op.BodyGap != "" {
		ref.Gaps = append(ref.Gaps, op.BodyGap)
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
		routes = append(routes, apiref.Route{Operation: id, Method: op.Method, Template: op.Path})
	}
	h := apiref.Hint{Candidates: apiref.Candidates(routes, v.Method, v.EscapedPath)}
	if ops := apiref.CandidateOperations(routes, v.Method, v.EscapedPath); len(ops) == 1 {
		h.Operation = ops[0]
	}
	return h
}
