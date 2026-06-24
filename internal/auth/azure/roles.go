package azure

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

func matchesRole(rd *armauthorization.RoleDefinition, want string) bool {
	if rd.Name != nil && strings.EqualFold(*rd.Name, want) {
		return true
	}
	if rd.Properties.RoleName != nil && strings.EqualFold(*rd.Properties.RoleName, want) {
		return true
	}
	return false
}

// flattenPermissions merges a role definition's permission blocks into one
// RolePermissions. It unions Actions and NotActions across blocks rather than
// computing per-block (Actions - NotActions); the two differ only when a
// NotActions entry in one block intersects an Actions grant in another. Built-in
// Azure roles use a single block, and the union form errs toward deny
// (fail-closed), so the simplification is safe for the allow-list use case.
func flattenPermissions(rd *armauthorization.RoleDefinition) RolePermissions {
	var out RolePermissions
	for _, p := range rd.Properties.Permissions {
		if p == nil {
			continue
		}
		out.Actions = append(out.Actions, derefAll(p.Actions)...)
		out.NotActions = append(out.NotActions, derefAll(p.NotActions)...)
	}
	return out
}

func derefAll(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// selectRolePermissions scans one page of role definitions for the first that
// matches want, returning its flattened permissions. It skips nil entries and
// entries with nil Properties — the same guard the live pager applied inline —
// so matchesRole/flattenPermissions never dereference a nil Properties.
func selectRolePermissions(values []*armauthorization.RoleDefinition, want string) (RolePermissions, bool) {
	for _, rd := range values {
		if rd == nil || rd.Properties == nil {
			continue
		}
		if matchesRole(rd, want) {
			return flattenPermissions(rd), true
		}
	}
	return RolePermissions{}, false
}
