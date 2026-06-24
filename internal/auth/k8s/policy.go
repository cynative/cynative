package k8s

import "slices"

// PolicyRule is a single RBAC rule extracted from a ClusterRole. Resources may
// be a bare resource ("pods") or a slash-joined subresource ("pods/log").
type PolicyRule struct {
	APIGroups []string
	Resources []string
	// ResourceNames, when non-empty, restricts the rule to objects with these exact names (no wildcard).
	ResourceNames []string
	Verbs         []string
}

// ViewPolicy is an allow-only set of PolicyRules (the cluster's configured read-only ClusterRole, default `view`).
type ViewPolicy struct {
	rules []PolicyRule
}

// BuildViewPolicy wraps parsed rules into a ViewPolicy matcher.
func BuildViewPolicy(rules []PolicyRule) *ViewPolicy {
	return &ViewPolicy{rules: rules}
}

// Allows reports whether ri (a resource request) is permitted by any rule,
// using RBAC matching: group, (resource or resource/subresource), and verb must
// each match a rule entry or its "*" wildcard. A nil ViewPolicy denies all.
func (vp *ViewPolicy) Allows(ri RequestInfo) bool {
	if vp == nil || !ri.IsResourceRequest {
		return false
	}

	target := ri.Resource
	if ri.Subresource != "" {
		target = ri.Resource + "/" + ri.Subresource
	}

	for _, r := range vp.rules {
		if matchItem(r.Verbs, ri.Verb) &&
			matchItem(r.APIGroups, ri.APIGroup) &&
			matchItem(r.Resources, target) &&
			resourceNameMatches(r.ResourceNames, ri.Name) {
			return true
		}
	}

	return false
}

// matchItem reports whether want is in set or set contains the "*" wildcard.
func matchItem(set []string, want string) bool {
	for _, s := range set {
		if s == "*" || s == want {
			return true
		}
	}

	return false
}

// resourceNameMatches reports whether a rule restricted to specific resource
// names applies to the request's resource name. An empty restriction matches
// any name; a non-empty restriction matches only an exact, non-empty name (no
// wildcard), so a name-restricted rule never authorizes a nameless request.
func resourceNameMatches(names []string, requestName string) bool {
	if len(names) == 0 {
		return true
	}

	if requestName == "" {
		return false
	}

	return slices.Contains(names, requestName)
}
