package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// clusterRolesBasePath is the API path prefix for cluster-scoped RBAC ClusterRole
// objects. The specific role name is appended as an escaped path segment by
// clusterRolePath.
const clusterRolesBasePath = "/apis/rbac.authorization.k8s.io/v1/clusterroles"

// clusterRolePath builds the Kubernetes API path for the named ClusterRole,
// escaping the name as a single URL path segment. [url.PathEscape] escapes '/' and
// '%' (path-injection defense) while preserving ':' so built-in system: roles
// (e.g. system:aggregate-to-view) and custom roles work unchanged.
func clusterRolePath(role string) string {
	return clusterRolesBasePath + "/" + url.PathEscape(role)
}

// ErrClusterAccessDenied marks a ClusterRole fetch that failed because the
// authenticated identity is not authorized on the cluster (k8s API 401/403),
// as distinct from a transport or hardening-resolution failure.
var ErrClusterAccessDenied = errors.New("k8s_hardening: not authorized on this cluster")

// clusterRoleStatusError carries the HTTP status of a non-200/401/403 ClusterRole
// fetch so isTransientProbeErr classifies a 429/5xx as transient (it implements
// HTTPStatusCode, mirroring githubStatusError) — without this, an eager probeKube
// against a cluster returning 5xx would not be retried. The 401/403 cases stay the
// definitive ErrClusterAccessDenied-wrapped errors below (never transient).
type clusterRoleStatusError struct {
	clusterRole string
	code        int
}

func (e *clusterRoleStatusError) Error() string {
	return fmt.Sprintf("k8s_hardening: clusterrole %q fetch status %d", e.clusterRole, e.code)
}

func (e *clusterRoleStatusError) HTTPStatusCode() int { return e.code }

// clusterRoleFetchStatusError maps an HTTP status from the ClusterRole fetch to an
// error: nil for 200; an ErrClusterAccessDenied-wrapped, status-specific message for
// 401/403; a generic *clusterRoleStatusError (carrying the status) otherwise. Pure:
// no I/O. The 401 vs 403 wording is deliberately distinct so the message does not
// overstate the cause — 401 is an authentication failure (token rejected / identity
// unknown to the cluster), 403 is authenticated-but-not-authorized to read the role.
func clusterRoleFetchStatusError(clusterRole string, status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf(
			"%w: reading clusterrole %q returned k8s API 401 Unauthorized; the identity is not "+
				"authenticated to this cluster (for EKS, it is likely not mapped in the cluster's "+
				"access entries / aws-auth)",
			ErrClusterAccessDenied, clusterRole)
	case http.StatusForbidden:
		return fmt.Errorf(
			"%w: reading clusterrole %q returned k8s API 403 Forbidden; the identity is "+
				"authenticated but not authorized to read it",
			ErrClusterAccessDenied, clusterRole)
	default:
		return &clusterRoleStatusError{clusterRole: clusterRole, code: status}
	}
}
