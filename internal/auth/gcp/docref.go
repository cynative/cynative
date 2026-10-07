package gcp

import (
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
		Source: apiref.Source{
			Name: docSourceName, Document: doc.Name + " " + doc.Version, Version: doc.Revision, SHA256: doc.SHA256,
		},
	}
	ref.Gaps = append(ref.Gaps, gaps...)
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
