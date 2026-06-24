package gcp

import (
	"context"
	"fmt"
)

//go:generate go tool moq -out iam_roles_mock_test.go . iamRolesClient

// RoleDefinition is the subset of an IAM role the gate needs: the granted
// permissions plus the launch-stage / soft-delete signals used to fail closed on
// a disabled role.
type RoleDefinition struct {
	IncludedPermissions []string
	Stage               string // IAM Role.Stage enum value (e.g. GA, BETA, DISABLED); "" when unset.
	Deleted             bool   // IAM Role.Deleted soft-delete flag.
}

// iamRolesClient is the IAM subset Layer 1+2 depends on: role definition fetch
// and testable-permission enumeration. Real *iam.Service impl in roles_shell.go.
// The public IAMRolesClient in roles_shell.go intentionally mirrors this interface.
//
//nolint:iface // private core port; IAMRolesClient is the public mirror in roles_shell.go.
type iamRolesClient interface {
	GetRole(ctx context.Context, roleName string) (RoleDefinition, error)
	QueryTestablePermissions(ctx context.Context, fullResourceName string) ([]string, error)
}

type roleEvaluator struct {
	granted map[string]bool // the allow-list role's includedPermissions.
}

func newRoleEvaluator(granted map[string]bool) *roleEvaluator {
	return &roleEvaluator{granted: granted}
}

// AllowedAll reports whether every perm is granted by the role. Empty perms
// (permissionless) → allowed. Caller-independent. Pure.
func (e *roleEvaluator) AllowedAll(perms []string) bool {
	for _, p := range perms {
		if !e.granted[p] {
			return false
		}
	}
	return true
}

// FetchRolePermissions fetches the allow-list role's includedPermissions as a
// set. Fails closed (ErrRoleFetchFailed) on the fetch error.
func FetchRolePermissions(ctx context.Context, client iamRolesClient, role string) (map[string]bool, error) {
	def, err := client.GetRole(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrRoleFetchFailed, role, err)
	}
	if def.Deleted || def.Stage == "DISABLED" {
		return nil, fmt.Errorf("%w: %q (stage=%q deleted=%t)", ErrRoleDisabled, role, def.Stage, def.Deleted)
	}
	granted := make(map[string]bool, len(def.IncludedPermissions))
	for _, p := range def.IncludedPermissions {
		granted[p] = true
	}
	return granted, nil
}
