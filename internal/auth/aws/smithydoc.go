package aws

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

const (
	headerContentType = "Content-Type"
	formContentType   = "application/x-www-form-urlencoded; charset=utf-8"
	jsonContentType   = "application/json"
	awsJSON10Type     = "application/x-amz-json-1.0"
	awsJSON11Type     = "application/x-amz-json-1.1"
	defaultListItem   = "member"
	regionalLimit     = "endpoint is the standard regional form; other partitions, FIPS and dual-stack " +
		"endpoints are not covered"
	normalizeListJS = "x == null ? [] : [].concat(x)"
	xmlLeafGuidance = "Parse with xml.parse(response.body) inside code_execution. Every leaf is a string " +
		"(compare IsTruncated === 'true', never its truthiness)."
	typeUnknown = "unknown"
	typeList    = "list"
	encodingXML = "xml"
)

const (
	traitDocumentation = "smithy.api#documentation"
	traitRequired      = "smithy.api#required"
	traitHTTPLabel     = "smithy.api#httpLabel"
	traitHTTPQuery     = "smithy.api#httpQuery"
	traitHTTPHeader    = "smithy.api#httpHeader"
	traitHTTPPayload   = "smithy.api#httpPayload"
	traitXMLName       = "smithy.api#xmlName"
	traitXMLFlattened  = "smithy.api#xmlFlattened"
	traitJSONName      = "smithy.api#jsonName"
	traitStreaming     = "smithy.api#streaming"
	traitPaginated     = "smithy.api#paginated"
	traitHTTP          = "smithy.api#http"
	traitRuleSet       = "smithy.rules#endpointRuleSet"
)

// Traits that bind a member to something other than the body, and the scalar types the renderer can fill.
//
//nolint:gochecknoglobals // immutable lookup tables.
var (
	specialInputTraits = []string{"smithy.api#httpQueryParams", "smithy.api#httpPrefixHeaders", traitHTTPPayload}
	boundOutputTraits  = []string{traitHTTPHeader, "smithy.api#httpResponseCode", "smithy.api#httpPrefixHeaders"}
	scalarTypes        = []string{"string", "enum", "integer", "long", "short", "byte", "boolean", "float", "double"}
)

// docTarget is a Smithy shape reference.
type docTarget struct {
	Target string `json:"target"`
}

// docMember is one structure or list member.
type docMember struct {
	Target string                     `json:"target"`
	Traits map[string]json.RawMessage `json:"traits"`
}

// docShape is the Smithy shape subset documentation reads.
type docShape struct {
	Type    string                     `json:"type"`
	Version string                     `json:"version"`
	Traits  map[string]json.RawMessage `json:"traits"`
	Input   docTarget                  `json:"input"`
	Output  docTarget                  `json:"output"`
	Members map[string]docMember       `json:"members"`
	Member  docMember                  `json:"member"`
}

// docPaginated is the smithy.api#paginated trait.
type docPaginated struct {
	InputToken  string `json:"inputToken"`
	OutputToken string `json:"outputToken"`
	Items       string `json:"items"`
	PageSize    string `json:"pageSize"`
}

// DocModel is a Smithy model parsed for documentation.
type DocModel struct {
	shapes  map[string]docShape
	ops     map[string]string // operation short name to shape id.
	svcName string            // service shape short name, the X-Amz-Target prefix.
	svc     docShape
	sm      ServiceModel
	urls    []string
}

// ParseDocModel parses raw Smithy 2.0 JSON-AST bytes for documentation.
func ParseDocModel(raw []byte) (*DocModel, error) {
	var doc smithyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrSmithyUnavailable, err)
	}
	if !strings.HasPrefix(doc.Smithy, "2.") {
		return nil, fmt.Errorf("%w: unsupported smithy version %q", ErrSmithyUnavailable, doc.Smithy)
	}
	m := &DocModel{shapes: make(map[string]docShape, len(doc.Shapes)), ops: make(map[string]string)}
	sawSvc := false
	for id, rawShape := range doc.Shapes {
		var sh docShape
		if err := json.Unmarshal(rawShape, &sh); err != nil {
			return nil, fmt.Errorf("%w: shape %q: %w", ErrSmithyUnavailable, id, err)
		}
		m.shapes[id] = sh
		switch sh.Type {
		case "operation":
			m.ops[shortName(id)] = id
		case serviceShapeType:
			if err := m.setService(id, sh, rawShape); err != nil {
				return nil, err
			}
			sawSvc = true
		}
	}
	if !sawSvc {
		return nil, fmt.Errorf("%w: no service shape found", ErrSmithyUnavailable)
	}
	if m.sm.EndpointPrefix == "" {
		return nil, fmt.Errorf("%w: service shape has no endpoint prefix", ErrSmithyUnavailable)
	}
	return m, nil
}

// setService records the service shape: its identity, protocol and literal endpoint URLs.
func (m *DocModel) setService(id string, sh docShape, rawShape json.RawMessage) error {
	var base smithyShape
	_ = json.Unmarshal(rawShape, &base) // the same bytes already decoded into docShape.
	if err := decodeService(base, &m.sm); err != nil {
		return err
	}
	m.svc = sh
	m.svcName = shortName(id)
	var node any
	_ = json.Unmarshal(sh.Traits[traitRuleSet], &node) // absent trait leaves node nil, which has no urls.
	collectURLs(node, &m.urls)
	return nil
}

// Protocol reports the service protocol.
func (m *DocModel) Protocol() Protocol { return m.sm.Protocol }

// HasOperation reports whether the model defines the operation.
func (m *DocModel) HasOperation(name string) bool {
	_, ok := m.ops[name]
	return ok
}

// OperationNames lists the operation names, sorted.
func (m *DocModel) OperationNames() []string {
	names := make([]string, 0, len(m.ops))
	for n := range m.ops {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ProtocolName is the Smithy protocol name a reference reports.
func ProtocolName(p Protocol) string {
	switch p {
	case ProtocolRestXML:
		return "restXml"
	case ProtocolRestJSON1:
		return "restJson1"
	case ProtocolAWSJSON10:
		return "awsJson1_0"
	case ProtocolAWSJSON11:
		return "awsJson1_1"
	case ProtocolAWSQuery:
		return "awsQuery"
	case ProtocolEC2Query:
		return "ec2Query"
	case ProtocolUnknown:
	}
	return "unknown"
}

// DocSupported reports whether references are generated for the protocol.
func DocSupported(p Protocol) bool {
	switch p {
	case ProtocolRestXML, ProtocolRestJSON1, ProtocolAWSJSON10, ProtocolAWSJSON11, ProtocolAWSQuery:
		return true
	case ProtocolUnknown, ProtocolEC2Query:
	}
	return false
}

func (m *DocModel) isREST() bool {
	return m.sm.Protocol == ProtocolRestXML || m.sm.Protocol == ProtocolRestJSON1
}

// Reference describes one operation. Source.SHA256 and Source.Document are left for the caller. It must only be
// called for a supported protocol and an existing operation.
func (m *DocModel) Reference(service, dir, name string) *apiref.Reference {
	op := m.shapes[m.ops[name]]
	ref := &apiref.Reference{
		Connector:  "aws",
		Service:    service,
		Model:      dir,
		Operation:  name,
		Protocol:   ProtocolName(m.sm.Protocol),
		APIVersion: m.svc.Version,
		Summary:    apiref.StripMarkup(traitName(op.Traits[traitDocumentation]), apiref.MaxSummary),
		AuthField:  "aws_auth",
		AuthArgs:   map[string]string{"service": m.sm.SigningName},
		Source:     apiref.Source{Name: "aws/api-models-aws", Version: m.svc.Version},
	}
	m.endpoint(ref)
	m.request(ref, op, name)
	m.response(ref, op, name)
	ref.Pagination = m.pagination(op)
	return ref
}

// endpoint prefers the literal global endpoint in the ruleset and otherwise falls back to the regional form.
func (m *DocModel) endpoint(ref *apiref.Reference) {
	global := "https://" + m.sm.EndpointPrefix + ".amazonaws.com"
	if slices.Contains(m.urls, global) {
		ref.Endpoint = global
		return
	}
	ref.Endpoint = "https://" + m.sm.EndpointPrefix + ".<region>.amazonaws.com"
	ref.Limitations = append(ref.Limitations, regionalLimit)
}

// request fills the method, path, fixed parts and inputs.
func (m *DocModel) request(ref *apiref.Reference, op docShape, name string) {
	ref.BodyEncoding = apiref.BodyNone
	switch m.sm.Protocol {
	case ProtocolRestXML, ProtocolRestJSON1:
		var h smithyHTTP
		_ = json.Unmarshal(op.Traits[traitHTTP], &h) // a malformed trait leaves the method and path empty.
		ref.Method = h.Method
		ref.PathTemplate, ref.FixedQuery = splitURI(h.URI)
	case ProtocolAWSQuery:
		ref.Method, ref.PathTemplate = "POST", "/"
		ref.BodyEncoding = apiref.BodyForm
		ref.FixedForm = []apiref.Param{{Key: "Action", Value: name}, {Key: "Version", Value: m.svc.Version}}
		ref.FixedHeaders = []apiref.Param{{Key: headerContentType, Value: formContentType}}
	case ProtocolAWSJSON10, ProtocolAWSJSON11:
		ref.Method, ref.PathTemplate = "POST", "/"
		ref.BodyEncoding = apiref.BodyJSON
		ctype := awsJSON10Type
		if m.sm.Protocol == ProtocolAWSJSON11 {
			ctype = awsJSON11Type
		}
		ref.FixedHeaders = []apiref.Param{
			{Key: "X-Amz-Target", Value: m.svcName + "." + name},
			{Key: headerContentType, Value: ctype},
		}
	case ProtocolUnknown, ProtocolEC2Query:
	}
	m.inputs(ref, m.shapes[op.Input.Target])
	if m.sm.Protocol == ProtocolRestJSON1 && hasRequiredBody(ref.Inputs) {
		ref.BodyEncoding = apiref.BodyJSON
		ref.FixedHeaders = append(ref.FixedHeaders, apiref.Param{Key: headerContentType, Value: jsonContentType})
	}
}

func hasRequiredBody(inputs []apiref.Input) bool {
	return slices.ContainsFunc(inputs, func(in apiref.Input) bool {
		return in.Required && in.Location == apiref.LocationBody
	})
}

// splitURI separates the literal path from its fixed query pairs, dropping the SDK-only x-id marker.
func splitURI(uri string) (string, []apiref.Param) {
	path, query, _ := strings.Cut(uri, "?")
	var params []apiref.Param
	for pair := range strings.SplitSeq(query, "&") {
		key, value, _ := strings.Cut(pair, "=")
		if key == "" || key == "x-id" {
			continue
		}
		params = append(params, apiref.Param{Key: key, Value: value})
	}
	return path, params
}

// inputs lists every required input and the first MaxOptionalInputs optional ones, and records a gap for each
// required input the renderer cannot place.
func (m *DocModel) inputs(ref *apiref.Reference, in docShape) {
	ref.Inputs = []apiref.Input{}
	optional := 0
	for _, name := range sortedMembers(in.Members) {
		input := m.input(name, in.Members[name])
		if !input.Required {
			if optional == apiref.MaxOptionalInputs {
				ref.InputsTruncated = true
				continue
			}
			optional++
		}
		if input.Required && !input.Renderable {
			ref.Gaps = append(ref.Gaps, fmt.Sprintf("required input %s (%s in %s) cannot be rendered",
				input.Name, input.Type, input.Location))
		}
		ref.Inputs = append(ref.Inputs, input)
	}
}

func sortedMembers(members map[string]docMember) []string {
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// input describes one input member.
func (m *DocModel) input(name string, mem docMember) apiref.Input {
	loc, wire, special := m.locate(name, mem.Traits)
	typ := m.typeOf(mem.Target)
	return apiref.Input{
		Name:     name,
		WireName: wire,
		Location: loc,
		Required: has(mem.Traits, traitRequired),
		Type:     typ,
		Renderable: !special && slices.Contains(scalarTypes, typ) &&
			(m.sm.Protocol != ProtocolRestXML || loc != apiref.LocationBody),
		Description: apiref.StripMarkup(traitName(mem.Traits[traitDocumentation]), apiref.MaxInputDescription),
	}
}

// locate reports where an input travels, its wire name, and whether it is bound in a way the renderer cannot
// fill from a scalar.
func (m *DocModel) locate(name string, tr map[string]json.RawMessage) (apiref.Location, string, bool) {
	if !m.isREST() {
		return apiref.LocationBody, m.bodyWire(name, tr), false
	}
	special := slices.ContainsFunc(specialInputTraits, func(t string) bool { return has(tr, t) })
	switch q, h := traitName(tr[traitHTTPQuery]), traitName(tr[traitHTTPHeader]); {
	case has(tr, traitHTTPLabel):
		return apiref.LocationPath, name, special
	case q != "":
		return apiref.LocationQuery, q, special
	case h != "":
		return apiref.LocationHeader, h, special
	}
	return apiref.LocationBody, m.bodyWire(name, tr), special
}

// bodyWire is the member's wire name in the body: jsonName for restJson1, xmlName for XML protocols.
func (m *DocModel) bodyWire(name string, tr map[string]json.RawMessage) string {
	var key string
	switch m.sm.Protocol {
	case ProtocolRestJSON1:
		key = traitJSONName
	case ProtocolRestXML, ProtocolAWSQuery:
		key = traitXMLName
	case ProtocolUnknown, ProtocolAWSJSON10, ProtocolAWSJSON11, ProtocolEC2Query:
	}
	if wire := traitName(tr[key]); wire != "" {
		return wire
	}
	return name
}

// typeOf names a member's type: the prelude type for smithy.api targets, else the target shape's type.
func (m *DocModel) typeOf(target string) string {
	if prelude, ok := strings.CutPrefix(target, "smithy.api#"); ok {
		return strings.ToLower(strings.TrimPrefix(prelude, "Primitive"))
	}
	if sh, ok := m.shapes[target]; ok {
		return sh.Type
	}
	return typeUnknown
}

// response fills the response encoding and parse guidance, and a gap when the body is a raw payload.
func (m *DocModel) response(ref *apiref.Reference, op docShape, name string) {
	out := m.shapes[op.Output.Target]
	body := m.bodyMembers(out)
	if raw := m.rawPayload(out, body); raw != "" {
		ref.Response = apiref.Response{
			Encoding: "raw",
			Parse:    "the body is the raw payload of member " + raw + "; no parse guidance is generated",
		}
		ref.Gaps = append(ref.Gaps, "response body is a raw payload")
		return
	}
	switch {
	case len(body) == 0 && m.sm.Protocol == ProtocolAWSQuery:
		ref.Response = apiref.Response{
			Encoding: encodingXML,
			Parse:    name + "Response envelope with ResponseMetadata and no result fields. " + xmlLeafGuidance,
		}
	case len(body) == 0:
		ref.Response = apiref.Response{Encoding: "none", Parse: "no modeled body fields; read the status and headers"}
	case m.sm.Protocol == ProtocolRestXML || m.sm.Protocol == ProtocolAWSQuery:
		ref.Response = apiref.Response{Encoding: encodingXML, Parse: m.xmlParse(op, out, body, name)}
	default:
		ref.Response = apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}
	}
}

// bodyMembers lists the output members that travel in the body, sorted.
func (m *DocModel) bodyMembers(out docShape) []string {
	var body []string
	for _, name := range sortedMembers(out.Members) {
		bound := m.isREST() && slices.ContainsFunc(boundOutputTraits, func(t string) bool {
			return has(out.Members[name].Traits, t)
		})
		if !bound {
			body = append(body, name)
		}
	}
	return body
}

// rawPayload names the first body member that is an unparsed payload, or "" when there is none.
func (m *DocModel) rawPayload(out docShape, body []string) string {
	for _, name := range body {
		mem := out.Members[name]
		if has(mem.Traits, traitHTTPPayload) || has(m.shapes[mem.Target].Traits, traitStreaming) {
			return name
		}
	}
	return ""
}

// xmlParse describes where the result element sits and how each list inside it parses.
func (m *DocModel) xmlParse(op, out docShape, body []string, name string) string {
	root := name + "Response." + name + "Result"
	if m.sm.Protocol == ProtocolRestXML {
		root = traitName(out.Traits[traitXMLName])
		if root == "" {
			root = shortName(op.Output.Target)
		}
	}
	var b strings.Builder
	b.WriteString(xmlLeafGuidance + " Result element: " + root + ".")
	for _, member := range body {
		mem := out.Members[member]
		list := m.shapes[mem.Target]
		if list.Type != typeList {
			continue
		}
		path := traitName(mem.Traits[traitXMLName])
		if path == "" {
			path = member
		}
		if !has(mem.Traits, traitXMLFlattened) && !has(list.Traits, traitXMLFlattened) {
			item := traitName(list.Member.Traits[traitXMLName])
			if item == "" {
				item = defaultListItem
			}
			path += "." + item
		}
		b.WriteString(" List " + member + ": " + path + "; a single entry parses as an object and an absent " +
			"list as undefined, normalize with " + normalizeListJS + ".")
	}
	return b.String()
}

// pagination merges the operation's paginated trait over the service's.
func (m *DocModel) pagination(op docShape) apiref.Pagination {
	opTrait, ok := op.Traits[traitPaginated]
	if !ok {
		return apiref.Pagination{Style: apiref.PaginationUnspecified}
	}
	var merged docPaginated
	_ = json.Unmarshal(m.svc.Traits[traitPaginated], &merged) // an absent service trait leaves every field empty.
	var over docPaginated
	_ = json.Unmarshal(opTrait, &over) // a malformed trait leaves the inherited values.
	for dst, src := range map[*string]string{
		&merged.InputToken: over.InputToken, &merged.OutputToken: over.OutputToken,
		&merged.Items: over.Items, &merged.PageSize: over.PageSize,
	} {
		if src != "" {
			*dst = src
		}
	}
	return apiref.Pagination{
		Style: "token", InputToken: merged.InputToken, OutputToken: merged.OutputToken,
		Items: merged.Items, PageSize: merged.PageSize,
	}
}
