package github

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

const (
	docEndpoint       = "https://api.github.com"
	docProtocol       = "rest-json"
	docSourceName     = "github/rest-api-description"
	docSourceDocument = "descriptions/api.github.com/api.github.com.json"
	docAccept         = "application/vnd.github+json"
	docVersionLimit   = "the connector strips X-GitHub-Api-Version, so the server's default API version applies"
	docLinkLimit      = `pagination is inferred from per_page/page parameters and a declared Link header; ` +
		`follow rel="next" in the Link response header`
	docPerPage = "per_page"
	docPage    = "page"
	docLink    = "Link"
)

// DistillDocs distills the public OpenAPI description into operation docs, with the parameter names the gate
// treats as catch-alls. It is separate from the gate's table distiller; it runs when the docs cache loads, which a
// cold unmatched-request hint does synchronously on the denial path.
func DistillDocs(raw []byte) (*openapidoc.OperationDocs, error) {
	d, err := openapidoc.Distill(raw, docProfile())
	if err != nil {
		return nil, err
	}
	var generic any
	_ = json.Unmarshal(raw, &generic) // Distill already decoded these bytes as JSON.
	for name := range collectMultiSegment(generic) {
		d.MultiSegment = append(d.MultiSegment, name)
	}
	slices.Sort(d.MultiSegment)
	return d, nil
}

// Reference looks up the operation q names in GitHub's docs.
func Reference(d *openapidoc.OperationDocs, q apiref.Query) apiref.Result {
	return d.Reference(q, docProfile())
}

// Hint suggests a fix for a request that matches no documented operation.
func Hint(d *openapidoc.OperationDocs, v authreq.View) apiref.Hint {
	routes := d.Routes()
	for i := range routes {
		routes[i].Template = hintTemplate(d.MultiSegment, routes[i].Template)
	}
	// The gate looks HEAD and OPTIONS up as GET, so the hint does too.
	method := openapidoc.LookupMethod(v.Method)
	h := apiref.Hint{Candidates: apiref.Candidates(routes, method, v.EscapedPath)}
	if ops := apiref.CandidateOperations(routes, method, v.EscapedPath); len(ops) == 1 {
		h.Operation = ops[0]
	}
	return h
}

func docProfile() openapidoc.Profile {
	return openapidoc.Profile{
		Connector:      "github",
		Protocol:       docProtocol,
		SourceName:     docSourceName,
		SourceDocument: docSourceDocument,
		Endpoint:       docEndpoint,
		FixedHeaders:   []apiref.Param{{Key: "Accept", Value: docAccept}},
		Paged:          linkPaged,
		Paging:         apiref.Pagination{Style: "link-header", InputToken: docPage, PageSize: docPerPage},
		PagingLimit:    docLinkLimit,
		Limitations:    []string{docVersionLimit},
	}
}

// linkPaged reports an operation with both per_page and page parameters whose 200 response declares a Link header.
func linkPaged(params []openapidoc.DocParam, headers []string) bool {
	has := func(name string) bool {
		return slices.ContainsFunc(params, func(p openapidoc.DocParam) bool { return p.Name == name })
	}
	return has(docPerPage) && has(docPage) && slices.Contains(headers, docLink)
}

// hintTemplate marks each multi-segment {name} the way the gate matches it: a
// last one becomes {name*} (zero or more segments) and any other {name+} (one or
// more). The hint matcher handles one greedy label per template, which covers
// every template GitHub publishes; hints are advisory, so a template with two
// only loses a hint.
func hintTemplate(multiSegment []string, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		name, ok := strings.CutSuffix(strings.TrimPrefix(s, "{"), "}")
		if !ok || !strings.HasPrefix(s, "{") || !slices.Contains(multiSegment, name) {
			continue
		}
		if i == len(segs)-1 {
			segs[i] = "{" + name + "*}"
		} else {
			segs[i] = "{" + name + "+}"
		}
	}

	return strings.Join(segs, "/")
}
