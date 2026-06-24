package aws

import (
	"context"
	"strings"
)

// ActionSource records which tier resolved an operation's action set.
type ActionSource int

const (
	// SourceNone means no tier could resolve an action set (caller denies).
	SourceNone ActionSource = iota
	// SourceServiceRef means the authoritative Service Reference API answered.
	SourceServiceRef
	// SourceIAMDataset means the iam-dataset fallback answered.
	SourceIAMDataset
	// SourceDerived means the namespace:op last-resort derivation answered.
	SourceDerived
	// SourcePermissionless means the operation requires no IAM permission, so
	// there is no action to authorize and the caller must allow it unconditionally.
	SourcePermissionless
)

// serviceRefGetter is the Service Reference registry port (tier 1). Returns nil
// on a miss so the resolver falls through to the next tier (fail-closed).
type serviceRefGetter interface {
	Get(ctx context.Context, service string) *ServiceRefModel
}

// iamDatasetLookuper is the iam-dataset registry port (tier 2): it resolves an
// operation to its required IAM action set.
type iamDatasetLookuper interface {
	Lookup(ctx context.Context, service string, sdkNames []string, op string) []string
	LookupSDKID(ctx context.Context, sdkID, op string) []string
}

// ActionResolver maps an operation to its required IAM action set via the
// 3-tier chain: Service Reference → iam-dataset → namespace:op.
type ActionResolver struct {
	serviceRef serviceRefGetter
	iamDataset iamDatasetLookuper
}

// NewActionResolver constructs the resolver from its two data ports.
func NewActionResolver(sr serviceRefGetter, ds iamDatasetLookuper) *ActionResolver {
	return &ActionResolver{serviceRef: sr, iamDataset: ds}
}

// permissionlessOps is the pinned set of AWS operations that require no IAM
// permission, so there is no action to authorize against the scoping policy.
// Mirrors gcp.permissionlessMethods (internal/auth/gcp/permissions.go). Keyed
// "<arnNamespace>:<op>" with a lowercased namespace. Network-free and
// deterministic, so the entry stays allowed even when the iam-dataset is
// unavailable.
//
// Entry criterion: AWS documents the operation as requiring no permission AND it
// is a harmless read (no credentials, no data, no mutation) AND cynative actually
// needs it. Only sts:GetCallerIdentity qualifies — agents call it to discover the
// active identity. The iann0036/iam-dataset also marks sts:GetSessionToken and
// dynamodb:DescribeEndpoints permissionless, but both are deliberately EXCLUDED:
// GetSessionToken issues temporary credentials with the caller's permissions, so
// an unconditional allow would let a credential-minting call bypass the read-only
// policy gate (notably when cred_scope is disabled); DescribeEndpoints is not
// needed by any cynative workflow. Each appears as a real IAM action in AWS's
// Service Reference, so when left out it resolves to that action and is policy-
// checked like anything else. Revisit only for a no-permission harmless read
// cynative actually needs.
var permissionlessOps = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"sts:GetCallerIdentity": true,
}

// Resolve returns the action set for op in the candidate model and the tier
// that produced it. A pinned permissionless operation (permissionlessOps)
// short-circuits to SourcePermissionless (no action to authorize). For a
// namespace-shadowed model the resolution is delegated to resolveShadowed;
// otherwise the standard 3-tier chain (resolveStandard) is used.
func (r *ActionResolver) Resolve(ctx context.Context, model *ServiceModel, op string) ([]string, ActionSource) {
	keys := dedupeNonEmpty(model.ARNNamespace, model.Dir, model.EndpointPrefix)
	for _, key := range keys {
		if permissionlessOps[strings.ToLower(key)+":"+op] {
			return nil, SourcePermissionless
		}
	}
	if model.NamespaceShadowed {
		return r.resolveShadowed(ctx, model, op)
	}
	return r.resolveStandard(ctx, model, op)
}

// resolveStandard is the default 3-tier chain for a service that owns its IAM
// namespace: Service Reference (over [arnNamespace, dir, endpointPrefix]) →
// iam-dataset → namespace:op derivation.
func (r *ActionResolver) resolveStandard(ctx context.Context, model *ServiceModel, op string) ([]string, ActionSource) {
	keys := dedupeNonEmpty(model.ARNNamespace, model.Dir, model.EndpointPrefix)
	var sdkNames []string
	for _, key := range keys {
		m := r.serviceRef.Get(ctx, key)
		if m == nil {
			continue
		}
		srop, ok := m.Operations[op]
		if !ok {
			continue
		}
		sdkNames = srop.SDKNames
		if acts := srop.AuthorizedActions; len(acts) > 0 {
			return acts, SourceServiceRef
		}
	}
	for _, key := range keys {
		if acts := r.iamDataset.Lookup(ctx, key, sdkNames, op); len(acts) > 0 {
			return acts, SourceIAMDataset
		}
	}
	if model.ARNNamespace != "" {
		return []string{model.ARNNamespace + ":" + op}, SourceDerived
	}
	return nil, SourceNone
}

// resolveShadowed resolves a namespace-shadowed model (its ARN namespace belongs
// to a foreign primary service). It consults Service Reference only under the
// model's OWN keys (dir/endpointPrefix, never the shared arnNamespace), then the
// iam-dataset by the model's own SDK id, and fails closed on miss — the
// namespace key is foreign, so there is no trustworthy fallback and the
// derivation tier is not used.
func (r *ActionResolver) resolveShadowed(ctx context.Context, model *ServiceModel, op string) ([]string, ActionSource) {
	for _, key := range dedupeNonEmpty(model.Dir, model.EndpointPrefix) {
		m := r.serviceRef.Get(ctx, key)
		if m == nil {
			continue
		}
		if srop, ok := m.Operations[op]; ok && len(srop.AuthorizedActions) > 0 {
			return srop.AuthorizedActions, SourceServiceRef
		}
	}
	if acts := r.iamDataset.LookupSDKID(ctx, model.SDKID, op); len(acts) > 0 {
		return acts, SourceIAMDataset
	}
	return nil, SourceNone
}

// dedupeNonEmpty returns the non-empty inputs with first-seen order preserved.
func dedupeNonEmpty(in ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
