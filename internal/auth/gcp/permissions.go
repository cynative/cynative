package gcp

import (
	"context"
	"maps"
	"slices"
	"strings"
)

// PermissionSource records how a method's required permission set was resolved.
type PermissionSource int

const (
	// SourceNone means the permission could not be resolved — caller fails closed.
	SourceNone PermissionSource = iota
	// SourceResolved means a non-empty required set was produced (a pinned method
	// override, derive-then-validate, the iam-dataset tier, or — for writes — the
	// union of the latter two).
	SourceResolved
	// SourcePermissionless means no IAM permission is required (allow-with-empty-perms).
	SourcePermissionless
)

// PermissionResolver resolves a Discovery method id to its required IAM
// permission(s). Fail-closed: an empty required set → SourceNone (deny).
type PermissionResolver interface {
	Resolve(ctx context.Context, methodID string) ([]string, PermissionSource)
}

// datasetLookuper resolves a method id to its high-confidence iam-dataset
// permission set. Returns nil on miss/unavailable. Real impl: IAMDatasetRegistry
// (iamdataset.go); a nil lookuper means "no dataset tier".
type datasetLookuper interface {
	Lookup(ctx context.Context, methodID string) []string
}

// permissionlessMethods is the pinned allow-with-empty-perms set.
var permissionlessMethods = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"oauth2.tokeninfo":       true,
	"discovery.apis.getRest": true,
	"discovery.apis.list":    true,
}

// readMethodVerbs identifies read method-id verbs. The iam-dataset tier is
// unioned for writes (its secondary perms — multi-perm/actAs — are real
// requirements there) but only consulted as a FALLBACK for reads (derivation is
// precise for reads and avoids the dataset's over-listing; see Resolve).
var readMethodVerbs = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"get": true, "list": true, "aggregatedList": true, "search": true, "getIamPolicy": true,
}

// isReadMethod reports whether methodID's verb (last dot-segment) is a read.
func isReadMethod(methodID string) bool {
	i := strings.LastIndex(methodID, ".")
	return i >= 0 && readMethodVerbs[methodID[i+1:]]
}

// verbSkew maps a Discovery method-id verb to its IAM permission verb where the
// two differ. Verbs absent here map to themselves (identity), which is correct
// for the vast majority (delete→delete, update→update, custom verbs like
// start→start). SECURITY INVARIANT (TestVerbSkewNoMutatingToRead): no entry maps
// a non-read method verb to a read IAM perm verb, so a write method can never
// derive a read permission and slip past a read-only allow-list.
var verbSkew = map[string]string{ //nolint:gochecknoglobals // immutable pinned set.
	"insert":         "create",
	"patch":          "update",
	"aggregatedList": "list",
}

// defaultPrefixMap reconciles API-name → IAM-permission-prefix divergence. It is
// a DIVERGENCE-ONLY override: only APIs whose Discovery name differs from their
// IAM permission prefix need an entry; all other APIs use identity passthrough
// (api name == perm prefix), made safe by catalog validation in derivePrimary.
//
// TRAP: a GCP API whose Discovery name diverges from its IAM permission prefix
// and is absent from BOTH this override map and the iam-dataset tier will derive
// an invalid permission, fail catalog validation, and be DENIED. This is
// fail-safe (deny, never allow), but if such an API must be supported, add an
// override entry here.
func defaultPrefixMap() map[string]string {
	return map[string]string{
		"cloudresourcemanager": "resourcemanager",
	}
}

// methodPermissionOverrides pins discovery methods whose true required IAM
// permission neither derive-then-validate nor the iam-dataset tier can resolve:
//   - projects.list / folders.list derive the CORRECT resourcemanager.<res>.list,
//     but that permission is parent-scoped (org/folder) and therefore absent from
//     the project-scoped queryTestablePermissions catalog, so derive-then-validate
//     fails. projects.list has only a low-confidence restcrawlv1 dataset entry
//     (excluded); folders.list has a high-confidence dataset entry, but pinning it
//     keeps folder listing independent of the external iam-dataset.
//   - the *.search methods filter results to what the caller can .get, so they
//     require resourcemanager.<resource>.get — NOT a ".search" permission, which
//     does not exist. Their search verb derives a non-existent permission and
//     they have no high-confidence dataset entry.
//
// Values encode the v3 method semantics and are sourced from Google's Discovery
// descriptions + the live IAM API (the catalog strips per-method permission data,
// so they cannot be validated at runtime). The pin is returned unconditionally,
// independent of which API version wins the catalog merge.
//
// INVARIANT: every value must be a READ permission (preserving the read-only gate
// posture; pinned by TestOverridesAreReadOnly) and must never be a strict subset
// of the method's true required permission set (a subset could under-require and
// false-allow). Re-verify against Google's Discovery before adding or editing.
var methodPermissionOverrides = map[string][]string{ //nolint:gochecknoglobals // immutable pinned set.
	"cloudresourcemanager.projects.list":        {"resourcemanager.projects.list"},
	"cloudresourcemanager.projects.search":      {"resourcemanager.projects.get"},
	"cloudresourcemanager.folders.list":         {"resourcemanager.folders.list"},
	"cloudresourcemanager.folders.search":       {"resourcemanager.folders.get"},
	"cloudresourcemanager.organizations.search": {"resourcemanager.organizations.get"},
}

// NewPermissionCatalog builds the queryTestablePermissions-validation catalog
// from a fetched permission slice (the cached snapshot): a set of valid IAM
// permission strings used by derivePrimary to reject wrong guesses.
func NewPermissionCatalog(perms []string) map[string]bool {
	set := make(map[string]bool, len(perms))
	for _, p := range perms {
		set[p] = true
	}
	return set
}

type permResolver struct {
	cat       map[string]bool
	prefixMap map[string]string
	dataset   datasetLookuper
}

// NewPermissionResolver constructs the resolver with a validation catalog, a
// divergence-only prefix map, and an iam-dataset lookuper (nil disables the
// dataset tier; derive-then-validate still runs).
func NewPermissionResolver(
	cat map[string]bool, prefixMap map[string]string, dataset datasetLookuper,
) PermissionResolver {
	return &permResolver{cat: cat, prefixMap: prefixMap, dataset: dataset}
}

// Resolve returns the required IAM permission(s) for methodID and the source.
// Fail-closed: empty result → SourceNone (deny). Permissionless methods
// short-circuit. The HTTP method is irrelevant — the method-id verb (chosen by
// the classifier) determines read/write nature.
func (r *permResolver) Resolve(ctx context.Context, methodID string) ([]string, PermissionSource) {
	if permissionlessMethods[methodID] || strings.HasSuffix(methodID, ".testIamPermissions") {
		return nil, SourcePermissionless
	}

	if perms, ok := methodPermissionOverrides[methodID]; ok {
		return slices.Clone(perms), SourceResolved
	}

	read := isReadMethod(methodID)
	derived, haveDerived := r.derivePrimary(methodID)

	set := map[string]struct{}{}
	if haveDerived {
		set[derived] = struct{}{}
	}
	// Dataset tier. Writes UNION the dataset's secondary permissions (multi-perm /
	// iam.serviceAccounts.actAs are real security requirements; over-require →
	// fail-closed). Reads consult the dataset only as a FALLBACK when derivation
	// produced nothing — derivation is precise for reads and avoids the dataset's
	// over-listing, while the fallback recovers reads derivation can't resolve
	// (e.g. divergent APIs absent from the prefix map). A read whose derivation
	// succeeded uses the derived primary alone.
	if r.dataset != nil && (!read || !haveDerived) {
		for _, perm := range r.dataset.Lookup(ctx, methodID) {
			set[perm] = struct{}{}
		}
	}

	if len(set) == 0 {
		return nil, SourceNone
	}
	return slices.Sorted(maps.Keys(set)), SourceResolved
}

// derivePrimary derives <permPrefix>.<resource…>.<permVerb> and validates it
// against the queryTestablePermissions catalog. permPrefix is prefixMap[api] or,
// for unmapped APIs, the api name itself (identity passthrough — safe because
// the catalog rejects wrong guesses, including a divergent API that lacks an
// override). Returns ("", false) when the method id is too short or the derived
// permission is absent from the catalog.
func (r *permResolver) derivePrimary(methodID string) (string, bool) {
	parts := strings.Split(methodID, ".")
	if len(parts) < 3 { //nolint:mnd // minimum is <api>.<resource>.<verb>.
		return "", false
	}
	permPrefix, ok := r.prefixMap[parts[0]]
	if !ok {
		permPrefix = parts[0] // identity passthrough.
	}
	permVerb := parts[len(parts)-1]
	if mapped, skewed := verbSkew[permVerb]; skewed {
		permVerb = mapped
	}
	permParts := make([]string, 0, len(parts))
	permParts = append(permParts, permPrefix)
	permParts = append(permParts, parts[1:len(parts)-1]...)
	permParts = append(permParts, permVerb)
	perm := strings.Join(permParts, ".")
	if !r.cat[perm] {
		return "", false
	}
	return perm, true
}
