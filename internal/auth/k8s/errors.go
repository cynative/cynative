// Package k8s provides a read-only Kubernetes API request-authorization core:
// a faithful kube-apiserver RequestInfo classifier and an RBAC matcher that
// authorizes requests against a cluster's configured read-only ClusterRole (default `view`), failing
// closed. It has no network or cloud-SDK dependency; the parent auth providers
// fetch the configured ClusterRole and feed it in.
package k8s

import "errors"

// ErrForbidden is returned when a classified request is not permitted by the
// configured read-only ClusterRole policy (default-deny).
var ErrForbidden = errors.New("k8s_hardening: request not permitted by the configured ClusterRole policy")

// ErrUnclassifiable is returned when an HTTP request cannot be mapped to a
// Kubernetes RequestInfo (fail closed).
var ErrUnclassifiable = errors.New("k8s_hardening: could not classify Kubernetes API request")
