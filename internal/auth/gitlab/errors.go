// Package gitlab classifies GitLab API requests to their category and required
// access level so the auth provider can enforce a per-category exposure ceiling.
// It performs no I/O.
package gitlab

import "errors"

var (
	// ErrUnclassifiable indicates the request could not be classified as a read or
	// a write; callers must fail closed.
	ErrUnclassifiable = errors.New("gitlab_hardening: cannot classify request as read or write")
	// ErrGraphQLUnsupported indicates a request to the GraphQL endpoint, which is
	// not supported; callers deny it and steer the model to the REST API.
	ErrGraphQLUnsupported = errors.New("gitlab_hardening: GraphQL is not supported; use the REST API")
	// ErrTableRejected indicates a category table failed structural or admission
	// checks and must not become active policy (callers fall back / fail closed).
	ErrTableRejected = errors.New("gitlab_hardening: category table rejected")
	// ErrUnknownKey indicates a configured permissions key names no real GitLab
	// category (likely a typo); the connector fails closed.
	ErrUnknownKey = errors.New("gitlab_hardening: unknown permissions key")
	// ErrExposureExceeded indicates the request exceeds the configured exposure
	// ceiling for its category.
	ErrExposureExceeded = errors.New("gitlab_hardening: request exceeds configured exposure")
	// ErrTableNotReady indicates no category table could be resolved, so
	// classification-dependent requests are denied.
	ErrTableNotReady = errors.New("gitlab_hardening: category table not ready")
)
