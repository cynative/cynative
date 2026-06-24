package gcp

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// projectResourcePrefix is the Resource Manager full-resource-name prefix for a
// project. QueryTestablePermissions (Layer 2 catalog) needs the caller's
// project as a full resource name.
const projectResourcePrefix = "//cloudresourcemanager.googleapis.com/projects/"

// LazyDeps carries everything LazyResolve needs for deferred GCP init.
// Construction of these deps in the shell is cheap (no GCP I/O); LazyResolve is
// what makes the actual GCP calls.
type LazyDeps struct {
	Role       string
	Catalog    Catalog
	Dataset    datasetLookuper // iam-dataset GCP tier (nil → derive-only).
	Roles      iamRolesClient
	Identity   identityProber
	RootSource oauth2.TokenSource // operator ADC token source, injected raw.
}

// LazyResult is what LazyResolve hands back on success.
type LazyResult struct {
	ActionProvider *Provider          // Layer 2 composed provider.
	TokenSource    oauth2.TokenSource // raw operator ADC source (no downscoping).
}

// LazyResolve performs the one-time deferred GCP init: identity → role-union
// fetch → permission-catalog fetch → Layer-2 action provider. The injected
// token is the raw ADC source; read-only and host gating are enforced by
// Layer-2 action authorization and Layer-3 host pinning. A failure returns the
// inner step error; the provider's lazyInit wrapper exposes it to the model as
// "gcp_hardening: not_ready: …".
func LazyResolve(ctx context.Context, deps LazyDeps) (*LazyResult, error) {
	_, projectID, err := deps.Identity.Probe(ctx)
	if err != nil {
		return nil, cloudauth.NotReady("gcp_hardening", "identity", err)
	}
	if projectID == "" {
		return nil, ErrProjectUnresolved
	}

	granted, err := FetchRolePermissions(ctx, deps.Roles, deps.Role)
	if err != nil {
		return nil, cloudauth.NotReady("gcp_hardening", "roles", err)
	}

	testable, err := deps.Roles.QueryTestablePermissions(ctx, projectResourcePrefix+projectID)
	if err != nil {
		return nil, cloudauth.NotReady("gcp_hardening", "permission catalog", err)
	}

	actionProvider := NewProvider(
		deps.Catalog,
		NewPermissionResolver(NewPermissionCatalog(testable), defaultPrefixMap(), deps.Dataset),
		newRoleEvaluator(granted),
		deps.Role,
	)

	return &LazyResult{ActionProvider: actionProvider, TokenSource: deps.RootSource}, nil
}
