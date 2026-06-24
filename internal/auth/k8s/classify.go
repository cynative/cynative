package k8s

import (
	"net/url"
	"strconv"
	"strings"
)

// RequestInfo is the structured authorization view of a Kubernetes API request,
// mirroring the subset of kube-apiserver's RequestInfo we need to authorize.
type RequestInfo struct {
	IsResourceRequest bool
	Verb              string
	APIGroup          string
	APIVersion        string
	Namespace         string
	Resource          string
	Subresource       string
	Name              string
	Path              string
}

const (
	verbWatch = "watch"
	verbProxy = "proxy"

	verbGet    = "get"
	verbDelete = "delete"

	resourceNamespaces = "namespaces"

	// minAPIsSegments is the minimum number of path segments for an /apis/<group>/<version>/...
	// resource request (apis + group + version + at-least-one-resource = 4).
	minAPIsSegments = 4
	// minAPISegments is the minimum number of path segments for an /api/<version>/...
	// resource request (api + version + at-least-one-resource = 3).
	minAPISegments = 3

	// indexName is the segment index of a resource's name within its path slice.
	indexName = 1
	// indexSubresource is the segment index of a subresource within its path slice.
	indexSubresource = 2
	// minSegmentsForName is the minimum slice length that includes a name segment.
	minSegmentsForName = 2
	// minSegmentsForSubresource is the minimum slice length that includes a subresource segment.
	minSegmentsForSubresource = 3
)

// Classify maps an HTTP method, URL path, and query to a RequestInfo,
// reproducing kube-apiserver's RequestInfoFactory rules: method→verb, then
// nameless GET→list (watch when the watch query is truthy), nameless
// DELETE→deletecollection; the subresource is the 3rd post-namespace segment
// except under the proxy verb; /api & /apis discovery roots and unprefixed
// paths are non-resource URLs whose verb is the lowercased HTTP method.
func Classify(method, path string, query url.Values) RequestInfo {
	httpVerb := strings.ToLower(method)
	parts := splitPath(path)

	if len(parts) < minAPISegments || (parts[0] != "api" && parts[0] != "apis") {
		return RequestInfo{IsResourceRequest: false, Verb: httpVerb, Path: path}
	}

	ri := RequestInfo{IsResourceRequest: true, Path: path}

	if parts[0] == "api" {
		ri.APIVersion = parts[1]
		parts = parts[2:]
	} else {
		if len(parts) < minAPIsSegments {
			return RequestInfo{IsResourceRequest: false, Verb: httpVerb, Path: path}
		}

		ri.APIGroup = parts[1]
		ri.APIVersion = parts[2]
		parts = parts[3:]
	}

	if len(parts) > 0 && (parts[0] == verbProxy || parts[0] == verbWatch) {
		ri.Verb = parts[0]
		parts = parts[1:]
	}

	parts = consumeNamespace(&ri, parts)
	consumeResource(&ri, parts)
	applyVerb(&ri, httpVerb, query)

	return ri
}

// splitPath trims slashes and splits a URL path into non-empty segments.
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}

	return strings.Split(p, "/")
}

// consumeNamespace strips a leading namespaces/<ns> scope, handling the
// /namespaces and /namespaces/<ns> resource-request forms. It returns the
// remaining path segments.
func consumeNamespace(ri *RequestInfo, parts []string) []string {
	if len(parts) == 0 || parts[0] != resourceNamespaces {
		return parts
	}

	if len(parts) == 1 {
		ri.Resource = resourceNamespaces

		return nil
	}

	if len(parts) < minSegmentsForSubresource {
		ri.Resource = resourceNamespaces
		ri.Name = parts[indexName]

		return nil
	}

	ri.Namespace = parts[indexName]

	return parts[minSegmentsForName:]
}

// consumeResource fills resource/name/subresource from the remaining segments,
// skipping the subresource under the proxy verb (its tail is opaque).
func consumeResource(ri *RequestInfo, parts []string) {
	if ri.Resource != "" || len(parts) == 0 {
		return
	}

	ri.Resource = parts[0]
	if len(parts) >= minSegmentsForName {
		ri.Name = parts[indexName]
	}

	if len(parts) >= minSegmentsForSubresource && ri.Verb != verbProxy {
		ri.Subresource = parts[indexSubresource]
	}
}

// applyVerb sets the verb from the HTTP method unless a special verb
// (proxy/watch) was already set, then reclassifies nameless get→list (watch on
// a truthy watch query) and nameless delete→deletecollection.
func applyVerb(ri *RequestInfo, httpVerb string, query url.Values) {
	if ri.Verb != "" {
		return
	}

	switch httpVerb {
	case "post":
		ri.Verb = "create"
	case verbGet, "head":
		ri.Verb = verbGet
	case "put":
		ri.Verb = "update"
	case "patch":
		ri.Verb = "patch"
	case verbDelete:
		ri.Verb = verbDelete
	default:
		ri.Verb = httpVerb
	}

	if ri.Name == "" {
		switch ri.Verb {
		case verbGet:
			ri.Verb = "list"
		case verbDelete:
			ri.Verb = "deletecollection"
		}
	}

	if ri.Verb == "list" && isWatch(query) {
		ri.Verb = verbWatch
	}
}

// isWatch reports whether the watch query parameter is present and parses to a
// truthy boolean (matching kube-apiserver's [strconv.ParseBool] handling); an
// absent/empty/false/0 value is not a watch.
func isWatch(query url.Values) bool {
	if query == nil {
		return false
	}

	b, err := strconv.ParseBool(query.Get("watch"))

	return err == nil && b
}
