package gcp

import (
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

const (
	docConnector  = "gcp"
	docProtocol   = "rest-json"
	docSourceName = "Google API Discovery"
	docAuthField  = "gcp_auth"
)

// buildReference describes one method of a distilled document.
func buildReference(doc *APIDoc, id string) *apiref.Reference {
	m := doc.Methods[id]
	path := "/" + effectiveTemplate(MethodDescriptor{ServicePath: doc.ServicePath, FlatPath: m.FlatPath, Path: m.Path})
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
		Inputs:       []apiref.Input{},
		BodyEncoding: apiref.BodyNone,
		AuthField:    docAuthField,
		AuthArgs:     map[string]string{"service": serviceShortName(doc.RootURL, doc.Name)},
		Pagination:   apiref.Pagination{Style: apiref.PaginationUnspecified},
		Source: apiref.Source{
			Name: docSourceName, Document: doc.Name + " " + doc.Version, Version: doc.Revision, SHA256: doc.SHA256,
		},
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
