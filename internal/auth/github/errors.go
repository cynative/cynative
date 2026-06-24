// Package github classifies GitHub API requests by category and access level so
// the auth provider can enforce a configurable exposure ceiling. It performs no
// I/O beyond an injected OpenAPI fetcher.
package github

import "errors"

var (
	// ErrUnclassifiable indicates the request could not be classified (unknown
	// route, unrecognized method); callers must fail closed.
	ErrUnclassifiable = errors.New("github_hardening: cannot classify request")
	// ErrGraphQLUnsupported indicates a request to the GraphQL endpoint, which is
	// not supported; callers deny it and steer the model to the REST API.
	ErrGraphQLUnsupported = errors.New("github_hardening: GraphQL is not supported; use the REST API")
	// ErrExposureExceeded indicates the request exceeds the configured exposure
	// ceiling for its category.
	ErrExposureExceeded = errors.New("github_hardening: request exceeds configured exposure")
	// ErrTableNotReady indicates no category table could be resolved, so
	// classification-dependent requests are denied.
	ErrTableNotReady = errors.New("github_hardening: category table not ready")
	// ErrUnknownKey indicates a configured permissions key names no real GitHub
	// category (likely a typo); the connector fails closed.
	ErrUnknownKey = errors.New("github_hardening: unknown permissions key")
	// ErrTableRejected indicates a category table failed structural or admission
	// checks and must not become active policy (callers fall back / fail closed).
	ErrTableRejected = errors.New("github_hardening: category table rejected")
)
