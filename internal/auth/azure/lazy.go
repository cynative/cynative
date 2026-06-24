package azure

import (
	"context"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// LazyDeps carries everything LazyResolve needs for deferred Azure init.
// Construction of these deps in the shell is cheap (no Azure I/O); LazyResolve
// is what makes the actual Azure calls.
type LazyDeps struct {
	RoleDefinition string
	Catalog        Catalog
	Roles          roleClient
	Identity       identityProber
}

// LazyResult is what LazyResolve hands back on success. Azure has no scoped
// token source (no downscoping primitive), so only the Layer-2 action provider
// is returned.
type LazyResult struct {
	ActionProvider *Provider
}

// LazyResolve performs the one-time deferred Azure init: identity probe →
// role-definition permissions fetch → role evaluator → composed provider. A
// failure returns the inner step error; the provider's lazyInit wrapper exposes
// it to the model as "azure_hardening: not_ready: …". There is no
// credential-downscoping step (Azure has none); the operator token retains full
// RBAC and Layer 2 is the sole gate.
func LazyResolve(ctx context.Context, deps LazyDeps) (*LazyResult, error) {
	if _, err := deps.Identity.Probe(ctx); err != nil {
		return nil, cloudauth.NotReady("azure_hardening", "identity", err)
	}

	perms, err := FetchRolePermissions(ctx, deps.Roles, deps.RoleDefinition)
	if err != nil {
		return nil, cloudauth.NotReady("azure_hardening", "roles", err)
	}

	eval := NewRoleEvaluator(perms)
	actionProvider := NewProvider(deps.Catalog, eval, deps.RoleDefinition)

	return &LazyResult{ActionProvider: actionProvider}, nil
}
