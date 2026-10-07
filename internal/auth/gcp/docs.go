package gcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

// maxDocumentBytes caps one Discovery download for api_reference. The largest document in the directory measured
// on 2026-10-05 was compute alpha at 7,566,442 bytes.
const maxDocumentBytes = 32 << 20

var (
	// ErrDocumentTooLarge reports a Discovery download over maxDocumentBytes.
	ErrDocumentTooLarge = errors.New("gcp_hardening: discovery document exceeds the size cap")
	// ErrDocsRejected reports a Discovery document api_reference cannot use.
	ErrDocsRejected = errors.New("gcp_hardening: discovery document rejected")
)

// Description prefixes the distiller reads, and the type and location markers it writes.
const (
	outputOnlyPrefix    = "Output only"
	outputOnlyBracket   = "[Output Only]"
	proseRequiredMark   = "Required."
	unknownDocType      = "unknown"
	objectDocType       = "object"
	locationPlaceholder = "<location>"
)

// APIDoc is one Discovery REST document distilled for api_reference: the facts a reference and its template need,
// and nothing the gate reads.
type APIDoc struct {
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	Revision    string               `json:"revision,omitempty"`
	RootURL     string               `json:"root"`
	ServicePath string               `json:"sp,omitempty"`
	Endpoints   []string             `json:"ep,omitempty"`
	SHA256      string               `json:"sha"`
	Methods     map[string]DocMethod `json:"m"`
	Schemas     map[string]DocSchema `json:"s,omitempty"`
}

// DocMethod is one Discovery method.
type DocMethod struct {
	HTTPMethod string     `json:"h"`
	Path       string     `json:"p"`
	FlatPath   string     `json:"f,omitempty"`
	Summary    string     `json:"d,omitempty"`
	Params     []DocParam `json:"a,omitempty"`
	// Body is set when the method takes a request body; Request names its schema, empty for an inline one.
	Body    bool   `json:"b,omitempty"`
	Request string `json:"rq,omitempty"`
	// Response names the response schema; HTTPBody marks the google.api.HttpBody shape and NextPageToken a
	// nextPageToken property.
	Response      string `json:"rs,omitempty"`
	HTTPBody      bool   `json:"hb,omitempty"`
	NextPageToken bool   `json:"np,omitempty"`
	MediaDownload bool   `json:"md,omitempty"`
}

// DocParam is one path or query parameter.
type DocParam struct {
	Name        string `json:"n"`
	Location    string `json:"l"`
	Type        string `json:"t"`
	Required    bool   `json:"r,omitempty"`
	Repeated    bool   `json:"x,omitempty"`
	Description string `json:"d,omitempty"`
	Pattern     string `json:"pt,omitempty"`
}

// DocSchema is a request schema's top level.
type DocSchema struct {
	Object bool      `json:"o,omitempty"`
	Props  []DocProp `json:"p,omitempty"`
}

// DocProp is one top-level property of a request schema. RequiredBy lists the method ids its
// annotations.required names; Prose marks a description that starts with "Required.".
type DocProp struct {
	Name        string   `json:"n"`
	Type        string   `json:"t"`
	Description string   `json:"d,omitempty"`
	RequiredBy  []string `json:"r,omitempty"`
	Prose       bool     `json:"pr,omitempty"`
	ReadOnly    bool     `json:"ro,omitempty"`
}

type discoveryRef struct {
	Ref string `json:"$ref"`
}

type discoveryParam struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	Required    bool   `json:"required"`
	Repeated    bool   `json:"repeated"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
}

type discoveryMethod struct {
	ID                    string                    `json:"id"`
	HTTPMethod            string                    `json:"httpMethod"`
	Path                  string                    `json:"path"`
	FlatPath              string                    `json:"flatPath"`
	Description           string                    `json:"description"`
	Parameters            map[string]discoveryParam `json:"parameters"`
	Request               *discoveryRef             `json:"request"`
	Response              *discoveryRef             `json:"response"`
	SupportsMediaDownload bool                      `json:"supportsMediaDownload"`
}

type discoveryResource struct {
	Methods   map[string]discoveryMethod   `json:"methods"`
	Resources map[string]discoveryResource `json:"resources"`
}

type discoveryProp struct {
	Type        string `json:"type"`
	Ref         string `json:"$ref"`
	Description string `json:"description"`
	ReadOnly    bool   `json:"readOnly"`
	Annotations struct {
		Required []string `json:"required"`
	} `json:"annotations"`
}

type discoverySchema struct {
	Type       string                   `json:"type"`
	Properties map[string]discoveryProp `json:"properties"`
}

type discoveryDoc struct {
	discoveryResource

	Name        string                     `json:"name"`
	Version     string                     `json:"version"`
	Revision    string                     `json:"revision"`
	RootURL     string                     `json:"rootUrl"`
	ServicePath string                     `json:"servicePath"`
	Endpoints   []discoveryEndpoint        `json:"endpoints"`
	Schemas     map[string]discoverySchema `json:"schemas"`
}

// discoveryEndpoint is one locational or regional host a Discovery document lists.
type discoveryEndpoint struct {
	Location    string `json:"location"`
	EndpointURL string `json:"endpointUrl"`
}

// DistillDoc distills one Discovery REST document. It runs when a document cache loads, on an api_reference
// lookup only.
func DistillDoc(raw []byte) (*APIDoc, error) {
	var doc discoveryDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	sum := sha256.Sum256(raw)
	out := &APIDoc{
		Name: doc.Name, Version: doc.Version, Revision: doc.Revision, RootURL: doc.RootURL,
		ServicePath: doc.ServicePath, Endpoints: endpointForms(doc), SHA256: hex.EncodeToString(sum[:]),
		Methods: map[string]DocMethod{}, Schemas: map[string]DocSchema{},
	}
	distillResource(&doc, doc.discoveryResource, out)
	return out, nil
}

// endpointForms lists the document's endpoints[] hosts with the location replaced by <location>, deduplicated
// and sorted.
func endpointForms(doc discoveryDoc) []string {
	var forms []string
	for _, e := range doc.Endpoints {
		u := strings.TrimSuffix(e.EndpointURL, "/")
		if e.Location != "" {
			u = placeLocation(u, e.Location)
		}
		forms = append(forms, u)
	}
	slices.Sort(forms)
	return slices.Compact(forms)
}

// placeLocation replaces the location in a host only where it is a whole label or a dash-bounded part of one
// (logging.in.rep, in-discoveryengine, us-east1-aiplatform, synth-eu), so a location that is also a substring of
// the service name ("in" in "logging") stays in the name.
func placeLocation(u, loc string) string {
	scheme, host, _ := strings.Cut(u, "://")
	labels := strings.Split(host, ".")
	for i, l := range labels {
		switch {
		case l == loc:
			labels[i] = locationPlaceholder
		case strings.HasPrefix(l, loc+"-"):
			labels[i] = locationPlaceholder + strings.TrimPrefix(l, loc)
		case strings.HasSuffix(l, "-"+loc):
			labels[i] = strings.TrimSuffix(l, loc) + locationPlaceholder
		}
	}
	return scheme + "://" + strings.Join(labels, ".")
}

func distillResource(doc *discoveryDoc, r discoveryResource, out *APIDoc) {
	for _, m := range r.Methods {
		out.Methods[m.ID] = distillMethod(doc, m, out)
	}
	for _, sub := range r.Resources {
		distillResource(doc, sub, out)
	}
}

func distillMethod(doc *discoveryDoc, m discoveryMethod, out *APIDoc) DocMethod {
	dm := DocMethod{
		HTTPMethod:    strings.ToUpper(m.HTTPMethod),
		Path:          m.Path,
		FlatPath:      m.FlatPath,
		Summary:       apiref.StripMarkup(m.Description, apiref.MaxSummary),
		MediaDownload: m.SupportsMediaDownload,
	}
	for name, p := range m.Parameters {
		dm.Params = append(dm.Params, DocParam{
			Name: name, Location: p.Location, Type: docType(p.Type, ""), Required: p.Required, Repeated: p.Repeated,
			Description: apiref.StripMarkup(p.Description, apiref.MaxInputDescription), Pattern: p.Pattern,
		})
	}
	slices.SortFunc(dm.Params, func(a, b DocParam) int { return strings.Compare(a.Name, b.Name) })
	if m.Request != nil {
		dm.Body = true
		dm.Request = m.Request.Ref
		_, done := out.Schemas[m.Request.Ref]
		if s, ok := doc.Schemas[m.Request.Ref]; ok && !done {
			out.Schemas[m.Request.Ref] = distillSchema(s)
		}
	}
	if m.Response != nil {
		dm.Response = m.Response.Ref
		props := doc.Schemas[m.Response.Ref].Properties
		_, contentType := props["contentType"]
		_, data := props["data"]
		dm.HTTPBody = contentType && data
		_, dm.NextPageToken = props["nextPageToken"]
	}
	return dm
}

// distillSchema keeps a request schema's top-level properties.
func distillSchema(s discoverySchema) DocSchema {
	out := DocSchema{Object: s.Type == objectDocType}
	for name, p := range s.Properties {
		desc := strings.TrimSpace(p.Description)
		out.Props = append(out.Props, DocProp{
			Name:        name,
			Type:        docType(p.Type, p.Ref),
			Description: apiref.StripMarkup(desc, apiref.MaxInputDescription),
			RequiredBy:  slices.Clone(p.Annotations.Required),
			Prose:       strings.HasPrefix(desc, proseRequiredMark),
			ReadOnly: p.ReadOnly || strings.HasPrefix(desc, outputOnlyPrefix) ||
				strings.HasPrefix(desc, outputOnlyBracket),
		})
	}
	slices.SortFunc(out.Props, func(a, b DocProp) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// docType is a Discovery type as a reference reports it: a $ref is an object, and a missing type is unknown.
func docType(t, ref string) string {
	switch {
	case ref != "":
		return objectDocType
	case t == "":
		return unknownDocType
	}
	return t
}

// Serialize encodes the distilled document for caching.
func (d *APIDoc) Serialize() []byte {
	// APIDoc is plain strings, bools, slices and string-keyed maps, so json.Marshal cannot fail.
	b, _ := json.Marshal(d)
	return b
}

// UnmarshalDoc parses a cached distilled document.
func UnmarshalDoc(b []byte) (*APIDoc, error) {
	var d APIDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocsRejected, err)
	}
	return &d, nil
}

// admitDoc accepts only a document that names the directory entry it was fetched for, so two entries can never
// serve each other's bytes.
func admitDoc(name, version string) func(*APIDoc) error {
	return func(d *APIDoc) error {
		if d.Name != name || d.Version != version {
			return fmt.Errorf("%w: document is %s %s, want %s %s", ErrDocsRejected, d.Name, d.Version, name, version)
		}
		return nil
	}
}

// readCapped reads r to the end, failing once it passes limit bytes.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrDocumentTooLarge, limit)
	}
	return buf.Bytes(), nil
}
