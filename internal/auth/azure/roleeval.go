package azure

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

//go:generate go tool moq -out roles_mock_test.go . roleClient

// roleClient fetches the configured role definition's static permissions by name
// or GUID. Real impl (roleDefinitions.get) in roles_shell.go.
type roleClient interface {
	RolePermissions(ctx context.Context, roleNameOrID string) (RolePermissions, error)
}

// RolePermissions is one role definition's control-plane permission set.
// Cynative is control-plane only: data-plane requests are denied at Layer 3
// (host pinning, see network.go), so DataActions/NotDataActions are out of scope
// and not modeled here.
type RolePermissions struct {
	Actions    []string
	NotActions []string
}

// RoleEvaluator authorizes a single control-plane Action against the configured
// role definition. Implemented by roleEvaluator.
type RoleEvaluator interface {
	Allowed(a Action) bool
}

type roleEvaluator struct {
	role RolePermissions
}

// NewRoleEvaluator builds the evaluator over the configured role definition's
// control-plane permissions. Membership is an Azure-RBAC-style set-subtraction
// (Actions minus NotActions); multi-block role definitions are pre-flattened in
// flattenPermissions, which unions blocks and errs toward deny.
func NewRoleEvaluator(role RolePermissions) RoleEvaluator {
	return &roleEvaluator{role: role}
}

// Allowed reports whether a.Full is a member of the role definition: it matches
// an Actions pattern and no NotActions pattern. Pure, caller-independent.
func (e *roleEvaluator) Allowed(a Action) bool {
	return matchAny(e.role.Actions, a.Full) && !matchAny(e.role.NotActions, a.Full)
}

func matchAny(patterns []string, action string) bool {
	for _, p := range patterns {
		if matchPattern(p, action) {
			return true
		}
	}
	return false
}

// matchPattern reports whether an Azure RBAC Action pattern matches action.
// "*" compiles to a full-string-anchored, case-insensitive regex ".*" (spanning
// "/"); all other characters are literal. Pure.
func matchPattern(pattern, action string) bool {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString("$")
	// The pattern is always valid: only ".*" and regexp.QuoteMeta output are
	// combined, so regexp.MustCompile cannot panic here.
	return regexp.MustCompile(b.String()).MatchString(action)
}

// FetchRolePermissions fetches the configured role definition's permissions,
// failing closed on the fetch error (ErrRoleFetchFailed).
func FetchRolePermissions(ctx context.Context, rc roleClient, roleDefinition string) (RolePermissions, error) {
	perms, err := rc.RolePermissions(ctx, roleDefinition)
	if err != nil {
		return RolePermissions{}, fmt.Errorf("%w: %q: %w", ErrRoleFetchFailed, roleDefinition, err)
	}
	return perms, nil
}
