package gcp

import iamv1 "google.golang.org/api/iam/v1"

// permissionNames projects the Name of each testable permission. Pure; the gated
// counterpart of QueryTestablePermissions's inner page-accumulation loop, extracted
// so the shell paging function stays under the thin-shell complexity budget.
func permissionNames(perms []*iamv1.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.Name)
	}
	return out
}
