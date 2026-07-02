package gcp

import (
	"fmt"
	"strings"
)

// RoleRefKind classifies a configured IAM role reference.
type RoleRefKind int

const (
	// RoleRefPredefined is a predefined role: roles/<id>.
	RoleRefPredefined RoleRefKind = iota
	// RoleRefProjectCustom is a project custom role: projects/<p>/roles/<r>.
	RoleRefProjectCustom
	// RoleRefOrgCustom is an organization custom role: organizations/<o>/roles/<r>.
	RoleRefOrgCustom
)

const (
	predefinedParts = 2 // roles/<id>.
	customParts     = 4 // {projects|organizations}/<id>/roles/<id>.

	rolesSegment         = "roles"
	projectsSegment      = "projects"
	organizationsSegment = "organizations"
)

// ParseRoleReference classifies and structurally validates a configured role
// reference. It accepts the three IAM role-name forms and rejects anything else
// (ErrInvalidRoleRef). Identifier charset is left to the IAM API: a structurally
// valid but nonexistent role fails closed at fetch time (ErrRoleFetchFailed).
// This is the single source of truth for role-reference shape;
// internal/config's validateGCPRole delegates to it.
func ParseRoleReference(role string) (RoleRefKind, error) {
	parts := strings.Split(role, "/")
	switch {
	case len(parts) == predefinedParts && parts[0] == rolesSegment && parts[1] != "":
		return RoleRefPredefined, nil
	case len(parts) == customParts &&
		parts[0] == projectsSegment && parts[1] != "" && parts[2] == rolesSegment && parts[3] != "":
		return RoleRefProjectCustom, nil
	case len(parts) == customParts &&
		parts[0] == organizationsSegment && parts[1] != "" && parts[2] == rolesSegment && parts[3] != "":
		return RoleRefOrgCustom, nil
	default:
		return RoleRefPredefined, fmt.Errorf("%w: %q", ErrInvalidRoleRef, role)
	}
}
