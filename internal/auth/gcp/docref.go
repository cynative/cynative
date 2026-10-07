package gcp

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

const (
	docConnector  = "gcp"
	docProtocol   = "rest-json"
	docSourceName = "Google API Discovery"
	docAuthField  = "gcp_auth"
	// docMaxEndpointForms bounds the locational host forms a reference names.
	docMaxEndpointForms = 3
	docSegment          = "a path segment"
	docJSONMedia        = "application/json"
	docBodyGap          = "request body is not a JSON object the template can render"
	docProseRequired    = "required per the field documentation: "
	docStandardParams   = "the standard query parameters every Google API accepts, such as fields, alt, " +
		"prettyPrint and quotaUser, are not listed"
	docPageToken  = "pageToken"
	docPagingNote = "pagination is inferred from the pageToken parameter and the nextPageToken response field; " +
		"send each response's nextPageToken as pageToken until a response has none"
	docBothSizes = "the method declares both pageSize and maxResults; read their descriptions before choosing " +
		"a page size"
	docHTTPBodyNote = "the response is a google.api.HttpBody: an arbitrary payload, not a JSON object"
	docMediaNote    = "alt=media returns the raw bytes instead of JSON"
)

var (
	// docLabel matches a {label} in a rendered path.
	docLabel = regexp.MustCompile(`\{([^{}]+)\}`)
	// docReserved matches a {+param} reserved expansion in a Discovery path.
	docReserved = regexp.MustCompile(`\{\+([^{}]+)\}`)
)

// buildReference describes one method of a distilled document.
func buildReference(doc *APIDoc, id string) *apiref.Reference {
	m := doc.Methods[id]
	path, inputs, gaps := renderPath(doc, m)
	ref := &apiref.Reference{
		Connector:    docConnector,
		Model:        doc.Version,
		Operation:    id,
		Protocol:     docProtocol,
		Method:       m.HTTPMethod,
		PathTemplate: path,
		APIVersion:   doc.Version,
		Summary:      m.Summary,
		Endpoint:     strings.TrimSuffix(doc.RootURL, "/"),
		Inputs:       inputs,
		BodyEncoding: apiref.BodyNone,
		AuthField:    docAuthField,
		AuthArgs:     map[string]string{"service": serviceShortName(doc.RootURL, doc.Name)},
		Pagination:   apiref.Pagination{Style: apiref.PaginationUnspecified},
		Limitations:  []string{docStandardParams},
		Source: apiref.Source{
			Name: docSourceName, Document: doc.Name + " " + doc.Version, Version: doc.Revision, SHA256: doc.SHA256,
		},
	}
	ref.Gaps = append(ref.Gaps, gaps...)
	addInputs(ref, queryAndBody(doc, m, id))
	addPagination(ref, m)
	addResponse(ref, m)
	if len(doc.Endpoints) > 0 {
		forms := doc.Endpoints[:min(len(doc.Endpoints), docMaxEndpointForms)]
		ref.Limitations = append(ref.Limitations, "the API also serves locational endpoints ("+
			strings.Join(forms, ", ")+"); the template uses the global endpoint, and gcp_auth.location, if supplied, "+
			"must match the host")
	}
	if !versionSelected(doc, m) {
		ref.Gaps = append(ref.Gaps, "version "+doc.Version+
			" is not selected by the request path; the request may reach a different API version")
	}
	return ref
}

// versionSelected reports whether the request path names the document's version: as a whole segment of servicePath,
// or as the first segment of the method's own path with any custom verb split off ("v1:evaluateDataset"). A match
// anywhere else in the path, such as compute preview's routers/{router}/preview, does not count.
func versionSelected(doc *APIDoc, m DocMethod) bool {
	if slices.Contains(strings.Split(doc.ServicePath, "/"), doc.Version) {
		return true
	}
	rel := m.FlatPath
	if rel == "" {
		rel = m.Path
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(rel, "/"), "/")
	first, _, _ = strings.Cut(first, ":")
	return first == doc.Version
}

// renderPath renders the request path the gate matches, servicePath plus flatPath (or path), and lists every
// {label} in it as a required path input. A {+param} with no flatPath stays one unrenderable label and a gap.
func renderPath(doc *APIDoc, m DocMethod) (string, []apiref.Input, []string) {
	path := "/" + effectiveTemplate(MethodDescriptor{ServicePath: doc.ServicePath, FlatPath: m.FlatPath, Path: m.Path})
	params := map[string]DocParam{}
	for _, p := range m.Params {
		if p.Location == string(apiref.LocationPath) {
			params[p.Name] = p
		}
	}
	var gaps []string
	unrendered := map[string]bool{}
	for _, r := range docReserved.FindAllStringSubmatch(path, -1) {
		gaps = append(gaps, "reserved-expansion path parameter "+r[1]+" has no flat path to render")
		unrendered[r[1]] = true
	}
	path = docReserved.ReplaceAllString(path, "{$1}")
	described, aligned := alignLabels(m.Path, m.FlatPath, params)
	inputs := []apiref.Input{}
	for _, l := range docLabel.FindAllStringSubmatch(path, -1) {
		label := l[1]
		in := apiref.Input{
			Name: label, WireName: label, Location: apiref.LocationPath, Required: true, Type: "string",
			Renderable: !unrendered[label], Description: docSegment,
		}
		if p, ok := params[label]; ok {
			in.Type, in.Description = p.Type, p.Description
		} else if aligned {
			in.Description = described[label]
		}
		inputs = append(inputs, in)
	}
	return path, inputs, gaps
}

// alignLabels attributes each flatPath label to the path parameter it is part of, aligning path with flatPath
// segment by segment: a literal must equal its counterpart, a {param} takes one segment, and a {+param} takes the
// run of segments up to the next literal of path, or to the end. It reports false when the two do not align.
func alignLabels(path, flat string, params map[string]DocParam) (map[string]string, bool) {
	p, f := verbSegments(path), verbSegments(flat)
	described := map[string]string{}
	j := 0
	for i, seg := range p {
		name, reserved := strings.CutPrefix(strings.Trim(seg, "{}"), "+")
		switch {
		case reserved && isPlaceholder(seg):
			end := runEnd(p[i+1:], f, j)
			if end <= j {
				return nil, false
			}
			describeRun(described, f[j:end], segmentOf(name, params[name].Pattern))
			j = end
		case isPlaceholder(seg):
			if j >= len(f) || !isPlaceholder(f[j]) {
				return nil, false
			}
			described[strings.Trim(f[j], "{}")] = params[name].Description
			j++
		default:
			if j >= len(f) || f[j] != seg {
				return nil, false
			}
			j++
		}
	}
	return described, j == len(f)
}

// describeRun gives every label in a run of flat segments the same description.
func describeRun(described map[string]string, run []string, desc string) {
	for _, seg := range run {
		for _, l := range docLabel.FindAllStringSubmatch(seg, -1) {
			described[l[1]] = desc
		}
	}
}

// runEnd is where a {+param}'s run of flat segments, starting at j, ends: at the next literal of the rest of path,
// found after j, or at the end. It returns j when that literal is missing, and len(f) when flatPath is already used
// up, which leaves the run empty and fails the alignment.
func runEnd(rest, f []string, j int) int {
	i := slices.IndexFunc(rest, func(s string) bool { return !isPlaceholder(s) })
	if i < 0 || j >= len(f) {
		return len(f)
	}
	k := slices.Index(f[j+1:], rest[i])
	if k < 0 {
		return j
	}
	return j + 1 + k
}

// segmentOf describes a flatPath label that is one segment of a reserved-expansion parameter.
func segmentOf(param, pattern string) string {
	desc := "one segment of " + param
	if form := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$"); form != "" {
		desc += ", which has the form " + form
	}
	return apiref.Truncate(desc, apiref.MaxInputDescription)
}

// verbSegments splits a Discovery path into segments, with a custom verb on the last segment as a segment of its
// own: "{+name}:cancel" becomes "{+name}" and ":cancel".
func verbSegments(path string) []string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	last := segs[len(segs)-1]
	if i := strings.Index(last, ":"); i > 0 {
		segs = append(segs[:len(segs)-1], last[:i], last[i:])
	}
	return segs
}

// queryAndBody lists the method's query parameters, then its request body: the writable top-level properties of
// a JSON object schema, or a body gap when the schema is missing, inline or not an object.
func queryAndBody(doc *APIDoc, m DocMethod, id string) bodyInputs {
	out := bodyInputs{encoding: apiref.BodyNone}
	for _, p := range m.Params {
		if p.Location != string(apiref.LocationQuery) {
			continue
		}
		desc := p.Description
		if p.Repeated {
			desc = apiref.Truncate("(repeatable) "+desc, apiref.MaxInputDescription)
		}
		out.inputs = append(out.inputs, docInput(p.Name, apiref.LocationQuery, p.Required, p.Type, desc))
	}
	if !m.Body {
		return out
	}
	s, ok := doc.Schemas[m.Request]
	if !ok || !s.Object {
		out.bodyGap = true
		return out
	}
	out.encoding = apiref.BodyJSON
	for _, p := range s.Props {
		if p.ReadOnly {
			continue
		}
		required := slices.Contains(p.RequiredBy, id)
		desc := p.Description
		if !required && p.Prose {
			required = true
			desc = apiref.Truncate(docProseRequired+desc, apiref.MaxInputDescription)
		}
		out.inputs = append(out.inputs, docInput(p.Name, apiref.LocationBody, required, p.Type, desc))
	}
	return out
}

// bodyInputs is what queryAndBody found after the path.
type bodyInputs struct {
	inputs   []apiref.Input
	encoding apiref.BodyEncoding
	bodyGap  bool
}

func docInput(name string, loc apiref.Location, required bool, typ, desc string) apiref.Input {
	return apiref.Input{
		Name: name, WireName: name, Location: loc, Required: required, Type: typ,
		Renderable: isDocScalar(typ), Description: desc,
	}
}

// isDocScalar reports a type the template renders as one value. Discovery writes int64 and uint64 as strings.
func isDocScalar(t string) bool {
	switch t {
	case "string", "integer", "number", "boolean":
		return true
	}
	return false
}

// addInputs appends every required input and the first apiref.MaxOptionalInputs optional ones, records a gap for
// each required input the template cannot render, and sets the body encoding.
func addInputs(ref *apiref.Reference, b bodyInputs) {
	ref.BodyEncoding = b.encoding
	if b.encoding == apiref.BodyJSON {
		ref.FixedHeaders = append(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: docJSONMedia})
	}
	if b.bodyGap {
		ref.Gaps = append(ref.Gaps, docBodyGap)
	}
	optional := 0
	for _, in := range b.inputs {
		switch {
		case !in.Required && optional == apiref.MaxOptionalInputs:
			ref.InputsTruncated = true
			continue
		case !in.Required:
			optional++
		case !in.Renderable:
			ref.Gaps = append(ref.Gaps, fmt.Sprintf("required input %s (%s in %s) cannot be rendered",
				in.Name, in.Type, in.Location))
		}
		ref.Inputs = append(ref.Inputs, in)
	}
	// The body gap already says why; the placeholder only marks the body in the template.
	if b.bodyGap {
		ref.Inputs = append(ref.Inputs, apiref.Input{
			Name: "body", WireName: "body", Location: apiref.LocationBody, Required: true, Type: unknownDocType,
		})
	}
}

// addPagination infers page-token pagination when the method takes a pageToken query parameter and its response
// has a nextPageToken property. The page size is pageSize or maxResults, whichever the method declares.
func addPagination(ref *apiref.Reference, m DocMethod) {
	query := map[string]bool{}
	for _, p := range m.Params {
		if p.Location == string(apiref.LocationQuery) {
			query[p.Name] = true
		}
	}
	if !query[docPageToken] || !m.NextPageToken {
		return
	}
	ref.Pagination = apiref.Pagination{Style: "page-token", InputToken: docPageToken, OutputToken: "nextPageToken"}
	ref.Limitations = append(ref.Limitations, docPagingNote)
	switch {
	case query["pageSize"] && query["maxResults"]:
		ref.Limitations = append(ref.Limitations, docBothSizes)
	case query["pageSize"]:
		ref.Pagination.PageSize = "pageSize"
	case query["maxResults"]:
		ref.Pagination.PageSize = "maxResults"
	}
}

// addResponse describes the response: JSON for a modeled response, the raw payload for a google.api.HttpBody, and
// no modeled fields when the method names no response schema.
func addResponse(ref *apiref.Reference, m DocMethod) {
	switch {
	case m.Response == "":
		ref.Response = apiref.Response{Encoding: "none", Parse: "no modeled body fields; read the status and headers"}
	case m.HTTPBody:
		ref.Response = apiref.Response{
			Encoding: "raw",
			Parse:    "the body is an arbitrary payload; its content type is in the Content-Type response header",
		}
		ref.Limitations = append(ref.Limitations, docHTTPBodyNote)
	default:
		ref.Response = apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}
	}
	if m.MediaDownload {
		ref.Limitations = append(ref.Limitations, docMediaNote)
	}
}
