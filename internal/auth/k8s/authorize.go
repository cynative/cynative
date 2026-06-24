package k8s

import (
	"fmt"
	"strings"
)

// safeNonResourcePaths are exact non-resource URLs allowed under a read-only
// posture (the API is unusable without discovery/health/version).
var safeNonResourcePaths = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table
	"/":        true,
	"/version": true,
	"/healthz": true,
	"/livez":   true,
	"/readyz":  true,
	"/api":     true,
	"/apis":    true,
}

// safeNonResourcePrefixes are non-resource URL prefixes allowed under GET or HEAD
// (discovery sub-trees and OpenAPI schemas).
var safeNonResourcePrefixes = []string{ //nolint:gochecknoglobals // immutable lookup table
	"/openapi", "/api/", "/apis/", "/version/", "/healthz/", "/livez/", "/readyz/",
}

// Authorize returns nil when ri is permitted under the read-only posture, or an
// ErrForbidden-wrapped error otherwise. Resource requests must match the
// ViewPolicy; non-resource requests must be a safe read-only URL.
func Authorize(ri RequestInfo, vp *ViewPolicy) error {
	if !ri.IsResourceRequest {
		if allowedNonResource(ri.Verb, ri.Path) {
			return nil
		}

		return fmt.Errorf("%w: non-resource %s %s", ErrForbidden, ri.Verb, ri.Path)
	}

	if vp.Allows(ri) {
		return nil
	}

	target := ri.Resource
	if ri.Subresource != "" {
		target += "/" + ri.Subresource
	}

	return fmt.Errorf("%w: %s %s (group %q)", ErrForbidden, ri.Verb, target, ri.APIGroup)
}

// allowedNonResource reports whether a read-only non-resource GET/HEAD to path
// is permitted.
func allowedNonResource(verb, path string) bool {
	if verb != "get" && verb != "head" {
		return false
	}

	if safeNonResourcePaths[path] {
		return true
	}

	for _, prefix := range safeNonResourcePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}
