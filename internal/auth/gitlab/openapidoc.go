package gitlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

const (
	docProtocol       = "rest-json"
	docSourceName     = "gitlab-org/gitlab"
	docSourceDocument = "doc/api/openapi/openapi_v3.yaml"
	docPage           = "page"
	docPerPage        = "per_page"
	docOffsetLimit    = "pagination is inferred from the page and per_page query parameters; follow the " +
		`X-Next-Page response header (or rel="next" in the Link header)`
	docMasterLimit = "the document describes GitLab's master branch; a self-managed instance may run an older " +
		"version that lacks this operation"
	docDriftLimit = "the docs and the gitlab gate's table can be read from different downloads of the document"
)

// DistillDocs distills GitLab's OpenAPI v3 YAML into operation docs for api_reference and the unmatched-request
// hint. It is separate from the gate's table distiller. It runs when the docs cache loads, which a cold
// unmatched-request hint does synchronously on the denial path. The docs hash the YAML bytes as fetched.
func DistillDocs(raw []byte) (*openapidoc.OperationDocs, error) {
	js, err := yamlToJSON(raw)
	if err != nil {
		return nil, err
	}
	d, err := openapidoc.Distill(js, docProfile("", nil))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	d.SHA256 = hex.EncodeToString(sum[:])
	return d, nil
}

// Reference looks q up in GitLab's docs. endpoint is the served API base URL, supplied at lookup because the
// cache stores no host, and refuse reports an input the connector rejects whatever the permission level.
func Reference(
	d *openapidoc.OperationDocs, q apiref.Query, endpoint string, refuse func(apiref.Location, string) bool,
) apiref.Result {
	return d.Reference(q, docProfile(endpoint, refuse))
}

// docProfile is the gitlab connector's reference profile. Distill runs it with no endpoint, so the document's
// https://{hostname} server is ignored. The document often omits response content (162 GETs declare a 200 with
// none), so a contentless response is reported as unspecified rather than as no body.
func docProfile(endpoint string, refuse func(apiref.Location, string) bool) openapidoc.Profile {
	return openapidoc.Profile{
		Connector:      "gitlab",
		Protocol:       docProtocol,
		SourceName:     docSourceName,
		SourceDocument: docSourceDocument,
		Endpoint:       endpoint,
		ScalarUnion:    true,
		Paged:          offsetPaged,
		Paging:         apiref.Pagination{Style: "offset", InputToken: docPage, PageSize: docPerPage},
		PagingLimit:    docOffsetLimit,
		Limitations:    []string{docMasterLimit, docDriftLimit},
		Refuse:         refuse,

		UnspecifiedResponse: true,
	}
}

// offsetPaged reports an operation with both page and per_page query parameters. Keyset pagination is never
// inferred.
func offsetPaged(params []openapidoc.DocParam, _ []string) bool {
	inQuery := func(name string) bool {
		return slices.ContainsFunc(params, func(p openapidoc.DocParam) bool {
			return p.Name == name && p.In == string(apiref.LocationQuery)
		})
	}
	return inQuery(docPage) && inQuery(docPerPage)
}

// yamlToJSON re-encodes a YAML document as JSON for the shared OpenAPI decoder. YAML allows mapping keys that are
// not strings (an unquoted response code decodes as an int) and JSON does not, so every key becomes its string
// form first.
func yamlToJSON(raw []byte) ([]byte, error) {
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("%w: parse openapi: %w", openapidoc.ErrDocsRejected, err)
	}
	js, err := json.Marshal(stringKeys(tree))
	if err != nil {
		return nil, fmt.Errorf("%w: re-encode openapi: %w", openapidoc.ErrDocsRejected, err)
	}
	return js, nil
}

// stringKeys returns v with every mapping key in it converted to its string form.
func stringKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = stringKeys(e)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(k)] = stringKeys(e)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = stringKeys(e)
		}
		return t
	}
	return v
}
