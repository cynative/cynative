package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Action is the derived RBAC Action. Full is the canonical
// "{Namespace}/{ResourceType}/{Verb}" form the catalog and role evaluator key on.
type Action struct {
	Namespace    string
	ResourceType string
	Verb         string
	Full         string
}

// postReadAllowList is the explicit, catalog-verified set of genuine query-style
// POST reads. A POST never otherwise synthesizes a /read. Keyed by the full
// "{namespace}/{resourceTypePath}/{verbToken}" (case-insensitive); the value is
// the resolved RBAC verb. For the Resource Graph collection POSTs the token is
// the collection name itself, so the key repeats it.
//
//nolint:gochecknoglobals // stateless lookup table, the documented exception.
var postReadAllowList = map[string]string{
	"microsoft.resourcegraph/resources/resources":                         "read",
	"microsoft.resourcegraph/resourcechanges/resourcechanges":             "read",
	"microsoft.resourcegraph/resourcechangedetails/resourcechangedetails": "read",
	"microsoft.resourcegraph/resourceshistory/resourceshistory":           "read",
	"microsoft.operationalinsights/workspaces/query":                      "read",
	"microsoft.network/networkwatchers/topology":                          "read",
	"microsoft.network/networkwatchers/nexthop":                           "read",
}

// pollSegments are the GET async-poll shapes that degrade to a scope-level read.
//
//nolint:gochecknoglobals // stateless lookup set, the documented exception.
var pollSegments = map[string]bool{"operations": true, "operationstatuses": true, "operationresults": true}

// typeNameStride is the index step between resource-type segments in an ARM path:
// even positions (0, 2, 4, …) are resource-type components, odd positions are
// resource names.
const typeNameStride = 2

// DeriveAction resolves req to exactly one candidate RBAC Action, deny-on-ambiguity.
// Pure modulo the injected Catalog port. The service is never read from the claim —
// the namespace comes from the URL path (the last /providers/ segment).
func DeriveAction(ctx context.Context, req *http.Request, cat Catalog) (Action, error) {
	method := strings.ToUpper(req.Method)
	segs := splitPath(req.URL.Path)

	// Reject any non-canonical path segment before classification: both the
	// provider-less template alignment and the poll even/odd parity rely on
	// segment positions, and req.URL.Path reaches us verbatim (no upstream
	// path.Clean), so an empty, ".", or ".." segment, or a percent-encoded
	// slash (%2F), could otherwise skew parity or diverge decoded/wire form.
	if nonCanonicalPath(req.URL.EscapedPath(), segs) {
		return Action{}, fmt.Errorf("%w: non-canonical path %q", ErrActionUnresolved, req.URL.EscapedPath())
	}

	namespace, rest, ok := resolveNamespace(segs)
	if !ok {
		return providerLessAction(method, segs)
	}

	if a, isPoll := pollAction(method, namespace, rest); isPoll {
		return a, nil
	}

	typePath, token, err := resolveResourceType(ctx, cat, method, namespace, rest)
	if err != nil {
		return Action{}, err
	}

	return verbAction(ctx, cat, method, namespace, typePath, token)
}

// resolveNamespace returns the segment after the LAST /providers/ and the
// segments that follow it. ok=false signals a provider-less root.
func resolveNamespace(segs []string) (string, []string, bool) {
	last := -1
	for i, s := range segs {
		if strings.EqualFold(s, "providers") {
			last = i
		}
	}
	if last < 0 || last+1 >= len(segs) {
		return "", nil, false
	}
	return segs[last+1], segs[last+2:], true
}

// providerLessRoute is one provider-less ARM GET route: a path-segment template
// (literals + "{}" single-segment wildcards) and the resource-type path of the
// Microsoft.Resources read it requires.
type providerLessRoute struct {
	template []string
	resource string
}

// providerLessRoutes is the exact set of GET routes addressed by the bare ARM
// hierarchy (no /providers/{namespace}/ segment). Every entry emits a
// Microsoft.Resources read; everything else fails closed. Template literals are
// lowercase (matchTemplate compares case-insensitively); resource is the
// canonical-cased Action resource-type path.
//
//nolint:gochecknoglobals // stateless provider-less ARM route table, the documented exception.
var providerLessRoutes = []providerLessRoute{
	{[]string{"subscriptions"}, "subscriptions"},
	{[]string{"subscriptions", "{}"}, "subscriptions"},
	{[]string{"subscriptions", "{}", "resourcegroups"}, "subscriptions/resourceGroups"},
	{[]string{"subscriptions", "{}", "resourcegroups", "{}"}, "subscriptions/resourceGroups"},
	{[]string{"subscriptions", "{}", "locations"}, "subscriptions/locations"},
	{[]string{"subscriptions", "{}", "providers"}, "subscriptions/providers"},
	{[]string{"subscriptions", "{}", "tagnames"}, "subscriptions/tagNames"},
	{[]string{"subscriptions", "{}", "resources"}, "subscriptions/resources"},
	{[]string{"subscriptions", "{}", "resourcegroups", "{}", "resources"}, "subscriptions/resourceGroups/resources"},
	{[]string{"tenants"}, "tenants"},
	{[]string{"providers"}, "providers"},
}

// providerLessAction matches the request path against the exact provider-less GET
// route table, emitting the documented Microsoft.Resources read. Non-GET, no
// match, or a length/segment mismatch fails closed. managementGroups is reached
// only via the provider-ful /providers/Microsoft.Management/managementGroups path,
// so it is intentionally absent here.
func providerLessAction(method string, segs []string) (Action, error) {
	if method != http.MethodGet {
		return Action{}, fmt.Errorf("%w: provider-less %s (only GET reads are mapped)", ErrActionUnresolved, method)
	}
	for _, r := range providerLessRoutes {
		if matchTemplate(r.template, segs) {
			return mk("Microsoft.Resources", r.resource, "read"), nil
		}
	}
	return Action{}, fmt.Errorf("%w: no provider-less route matches %v", ErrActionUnresolved, segs)
}

// matchTemplate reports whether segs matches a route template: equal length, each
// literal segment equal case-insensitively, "{}" matching any segment. Empty
// segments are already rejected by DeriveAction, so "{}" never binds an empty one.
func matchTemplate(template, segs []string) bool {
	if len(template) != len(segs) {
		return false
	}
	for i, t := range template {
		if t == "{}" {
			continue
		}
		if !strings.EqualFold(t, segs[i]) {
			return false
		}
	}
	return true
}

// pollAction recognizes an async-operation poll/list ONLY at a structurally valid
// position: a marker word (operations/operationStatuses/operationResults) at an
// EVEN index i in rest (the resource-type slot), where the shape is either the
// namespace-root bare list (i==0 and n==1) or a poll with exactly one trailing
// operation id (i==len(rest)-2). A bare marker at i>0 is a resource name, not a
// poll. GET only; anything else falls through to resolveResourceType. The
// empty-segment guard in DeriveAction runs first, so parity cannot be skewed.
func pollAction(method, namespace string, rest []string) (Action, bool) {
	if method != http.MethodGet {
		return Action{}, false
	}
	for i := 0; i < len(rest); i += typeNameStride {
		if pollSegments[strings.ToLower(rest[i])] && isPollShape(i, len(rest)) {
			return mk(namespace, strings.ToLower(rest[i]), "read"), true
		}
	}
	return Action{}, false
}

// isPollShape reports whether a marker at even index i in a rest slice of length n
// is a valid poll/list: a poll with exactly one trailing id (i==n-2, at any even
// i) or a namespace-root bare list (i==0 and n==1). A bare marker at i>0 is not
// a poll.
func isPollShape(i, n int) bool {
	if i == n-2 {
		return true
	}
	return i == 0 && n == 1
}

// resolveResourceType walks the alternating type/name segments after the
// namespace, validating each candidate type path against the catalog's
// ResourceTypes (exact, case-insensitive, NO stemming). Segments at even
// positions (0, 2, 4, …) are resource-type components; odd positions are
// resource names (skipped when building the type path). It returns the longest
// matched type path plus the trailing token (last even-position segment, for
// POST verb derivation). Unregistered type-position segments trailing the match
// fail closed: a POST tolerates exactly one (its action-verb token); every other
// method must consume all type-position segments, else the request targets an
// unregistered sub-path and is denied.
func resolveResourceType(
	ctx context.Context, cat Catalog, method, namespace string, rest []string,
) (string, string, error) {
	types, terr := cat.ResourceTypes(ctx, namespace)
	if terr != nil {
		return "", "", fmt.Errorf("%w: resource types for %q: %w", ErrCatalogUnavailable, namespace, terr)
	}
	known := make(map[string]bool, len(types))
	for _, t := range types {
		known[strings.ToLower(t)] = true
	}

	// Walk only the type-position slots (even indices: 0, 2, 4, …), building a
	// cumulative type path and recording the longest catalog match plus the last
	// type-position index seen.
	var typeParts []string
	matched := ""
	lastTypeToken := ""
	matchedIdx, lastEvenIdx := -1, -1
	for i := 0; i < len(rest); i += typeNameStride {
		typeParts = append(typeParts, rest[i])
		cand := strings.Join(typeParts, "/")
		lastTypeToken = rest[i]
		lastEvenIdx = i
		if known[strings.ToLower(cand)] {
			matched, matchedIdx = cand, i
		}
	}
	if matched == "" {
		return "", "", fmt.Errorf(
			"%w: %q not a resource type of %q",
			ErrActionUnresolved,
			strings.Join(rest, "/"),
			namespace,
		)
	}

	// Reject unregistered type-position segments trailing the longest match.
	maxTrailing := 0
	if method == http.MethodPost {
		maxTrailing = 1 // the action-verb token legitimately trails the type path.
	}
	if trailing := (lastEvenIdx - matchedIdx) / typeNameStride; trailing > maxTrailing {
		return "", "", fmt.Errorf("%w: %q has unregistered segment(s) trailing %q",
			ErrActionUnresolved, strings.Join(rest, "/"), matched)
	}

	// token is the last even-position segment seen (drives POST verb derivation).
	return matched, lastTypeToken, nil
}

// verbAction maps the HTTP method to the RBAC verb and applies the POST rules
// (allow-list / ambiguity-deny). A POST never synthesizes a /read.
func verbAction(
	ctx context.Context, cat Catalog, method, namespace, typePath, token string,
) (Action, error) {
	switch method {
	case http.MethodGet:
		return mk(namespace, typePath, "read"), nil
	case http.MethodPut, http.MethodPatch:
		return mk(namespace, typePath, "write"), nil
	case http.MethodDelete:
		return mk(namespace, typePath, "delete"), nil
	case http.MethodPost:
		return postAction(ctx, cat, namespace, typePath, token)
	default:
		return Action{}, fmt.Errorf("%w: unsupported method %q", ErrActionUnresolved, method)
	}
}

// postAction resolves a POST: an explicit allow-listed read, else an instance
// {verb}/action. Ambiguity (catalog has >1 distinct verb for the token) denies.
func postAction(ctx context.Context, cat Catalog, namespace, typePath, token string) (Action, error) {
	verbs, _, err := cat.LookupOperation(ctx, namespace, typePath, token)
	if err != nil {
		return Action{}, fmt.Errorf("%w: lookup %q: %w", ErrCatalogUnavailable, token, err)
	}
	if dv := distinct(verbs); len(dv) > 1 {
		return Action{}, fmt.Errorf("%w: POST %s/%s/%s (catalog has %v)",
			ErrActionAmbiguous, namespace, typePath, token, dv)
	}

	key := strings.ToLower(namespace + "/" + typePath + "/" + token)
	if verb, ok := postReadAllowList[key]; ok {
		return mk(namespace, typePath, verb), nil
	}
	// {trailingVerb}/action: the type path with the token stripped is the parent
	// resource type, the token is the action verb.
	parent := strings.TrimSuffix(typePath, "/"+token)
	return Action{
		Namespace:    namespace,
		ResourceType: parent,
		Verb:         token + "/action",
		Full:         namespace + "/" + parent + "/" + token + "/action",
	}, nil
}

func mk(namespace, resourceType, verb string) Action {
	return Action{
		Namespace:    namespace,
		ResourceType: resourceType,
		Verb:         verb,
		Full:         namespace + "/" + resourceType + "/" + verb,
	}
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// nonCanonicalPath reports whether the request path must be rejected before
// classification because its segmentation cannot be trusted: an empty, ".", or
// ".." segment (which would skew the segment-position parity that both the poll
// rule and the provider-less route table depend on), or a percent-encoded slash
// (%2F), which makes the decoded url.Path the classifier splits diverge from the
// EscapedPath wire form. Legitimate ARM control-plane paths contain none of these.
func nonCanonicalPath(escapedPath string, segs []string) bool {
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return true
		}
	}
	return strings.Contains(strings.ToLower(escapedPath), "%2f")
}

// distinct returns the case-insensitively unique verbs, first-seen order preserved.
func distinct(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		k := strings.ToLower(s)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}
