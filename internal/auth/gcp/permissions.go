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

// datasetLookuper resolves a method id to its iam-dataset permission set, in two
// tiers: Lookup answers from the write tier (high-confidence methodologies
// only), LookupRead from the read tier (which additionally admits the
// parameter-table scrape). Both return nil on miss or when the dataset is
// unavailable. Real impl: IAMDatasetRegistry (iamdataset.go); a nil lookuper
// means "no dataset tier".
type datasetLookuper interface {
	Lookup(ctx context.Context, methodID string) []string
	LookupRead(ctx context.Context, methodID string) []string
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

// mutatingReadMethods are Discovery method ids whose verb reads as a read but
// whose operation Google authorizes as a mutation. The read-tier fallback is
// skipped for these ENTIRELY, whichever tier holds the answer, because no
// scraped answer may authorize a mutation; if the true permission is
// established, pin it in methodPermissionOverrides instead.
//
// container's aggregated usable-subnetworks listing requires
// container.clusters.create despite its .list name and HTTP GET, confirmed
// against live GKE enforcement in #233. It has no dataset entry today, so this
// entry is a tripwire against one appearing upstream, not a live suppression.
var mutatingReadMethods = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"container.projects.aggregated.usableSubnetworks.list": true,
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
//   - projects.list is special: its Discovery id is shared by BOTH the v1
//     unfiltered list (GET /v1/projects), which Google authorizes by
//     resourcemanager.projects.get — its doc reads "Lists Projects that the caller
//     has the resourcemanager.projects.get permission on" — AND the v3 parent-
//     scoped list (GET /v3/projects?parent=…), which requires
//     resourcemanager.projects.list. The multi-version catalog merge makes both
//     versions routable under the one id (see mergeServiceDocs), so the override
//     requires the UNION {projects.get, projects.list}: neither version can then
//     under-require, so a .list-only ceiling role cannot authorize the unfiltered
//     v1 enumeration that exposes .get-level data, while roles/viewer (the default,
//     granting both) is unaffected. The .list permission is itself parent-scoped
//     (org/folder) and absent from the project-scoped queryTestablePermissions
//     catalog, so derive-then-validate cannot resolve it either.
//   - folders.list derives the CORRECT resourcemanager.folders.list, but that
//     permission is parent-scoped and absent from the project-scoped catalog, so
//     derive-then-validate fails. It has a high-confidence dataset entry, but
//     pinning it keeps folder listing independent of the external iam-dataset.
//   - the *.search methods filter results to what the caller can .get, so they
//     require resourcemanager.<resource>.get — NOT a ".search" permission, which
//     does not exist. Their search verb derives a non-existent permission and
//     they have no high-confidence dataset entry.
//   - the container (GKE) control-plane reads name the LEAF resource in the
//     permission (container.clusters.*, container.operations.*) while the Discovery
//     id nests that resource under projects.{locations,zones}, so derivation builds
//     e.g. container.projects.locations.clusters.get and the catalog rejects it. The
//     node-pool reads diverge further: they authorize on the PARENT cluster's
//     container.clusters.get, and no container.nodePools.* permission exists at all.
//     The dataset holds the right answers but only under a low-confidence
//     methodology, so every container read was denied — including the endpoint
//     lookup the gke connector's own documented workflow depends on. Both the
//     locations and the legacy zones route are pinned; they are separate ids.
//   - the container methods with CUSTOM verbs — getServerConfig (and its legacy
//     getServerconfig spelling), checkAutopilotCompatibility, and the two
//     fetch*UpgradeInfo pairs — are plain GETs whose verb is absent from
//     readMethodVerbs, so without a pin they take the WRITE path and union the
//     dataset, which holds nothing high-confidence for them. The override
//     short-circuits before that split, so the pin alone decides. Server config
//     requires container.clusters.list; the rest require container.clusters.get.
//
// Values are sourced from Google's Discovery descriptions + the live IAM API (the
// catalog strips per-method permission data, so they cannot be validated at
// runtime) and cover every API version sharing the id (see projects.list). Every
// container value is the permission named in that method's own REST-reference
// authorization sentence, and holds for both published Discovery versions (v1 and
// v1beta1). Most were additionally confirmed against live GKE enforcement, which
// names the required permission in its 403: cluster and node-pool get/list,
// operations.list, and both server-config spellings, on both routes. Two groups
// rest on the documentation alone — operations.get, because GKE rejects a
// synthetic operation id with a 400 before it authorizes, and the
// compatibility/upgrade reads, which were not probed.
//
// FIELD-LEVEL CAVEAT: Google gates the credential fields of a cluster get/list
// behind a CONDITIONAL container.clusters.getCredentials, which roles/viewer does
// not grant. This gate authorizes per method, not per response field, so a
// credential-bearing response is possible when the ambient ADC principal is
// broader than the configured ceiling. That is a property of the gate's
// granularity rather than of these entries — the pinned value is exactly the
// method's documented requirement — and it is why response redaction runs on
// every response. See docs/connectors/gcp.md.
//
// Deliberately absent, each a deny that must stay one: container's
// aggregated.usableSubnetworks.list requires container.clusters.create (confirmed
// live) despite its .list name and HTTP GET, so it is a write and pinning it would
// break the read-only invariant below; and the v1beta1-only projects.locations.list
// documents no permission.
//
// INVARIANT: every value must be a READ permission (preserving the read-only gate
// posture; pinned by TestOverridesAreReadOnly) and must never be a strict subset
// of the method's true required permission set (a subset could under-require and
// false-allow). Re-verify against Google's Discovery before adding or editing.
// The two container permissions each several container method ids map onto. Named
// because a node-pool or server-config pin resolves to a CLUSTER permission, which
// reads as a typo at the call site until you know that is the documented mapping.
const (
	permContainerClustersGet  = "container.clusters.get"
	permContainerClustersList = "container.clusters.list"
)

var methodPermissionOverrides = map[string][]string{ //nolint:gochecknoglobals // immutable pinned set.
	"cloudresourcemanager.projects.list":        {"resourcemanager.projects.get", "resourcemanager.projects.list"},
	"cloudresourcemanager.projects.search":      {"resourcemanager.projects.get"},
	"cloudresourcemanager.folders.list":         {"resourcemanager.folders.list"},
	"cloudresourcemanager.folders.search":       {"resourcemanager.folders.get"},
	"cloudresourcemanager.organizations.search": {"resourcemanager.organizations.get"},

	"container.projects.locations.clusters.get":            {permContainerClustersGet},
	"container.projects.locations.clusters.list":           {permContainerClustersList},
	"container.projects.locations.clusters.nodePools.get":  {permContainerClustersGet},
	"container.projects.locations.clusters.nodePools.list": {permContainerClustersGet},
	"container.projects.locations.operations.get":          {"container.operations.get"},
	"container.projects.locations.operations.list":         {"container.operations.list"},
	"container.projects.zones.clusters.get":                {permContainerClustersGet},
	"container.projects.zones.clusters.list":               {permContainerClustersList},
	"container.projects.zones.clusters.nodePools.get":      {permContainerClustersGet},
	"container.projects.zones.clusters.nodePools.list":     {permContainerClustersGet},
	"container.projects.zones.operations.get":              {"container.operations.get"},
	"container.projects.zones.operations.list":             {"container.operations.list"},
	"container.projects.locations.getServerConfig":         {permContainerClustersList},
	"container.projects.zones.getServerconfig":             {permContainerClustersList},

	"container.projects.locations.clusters.checkAutopilotCompatibility":        {permContainerClustersGet},
	"container.projects.locations.clusters.fetchClusterUpgradeInfo":            {permContainerClustersGet},
	"container.projects.zones.clusters.fetchClusterUpgradeInfo":                {permContainerClustersGet},
	"container.projects.locations.clusters.nodePools.fetchNodePoolUpgradeInfo": {permContainerClustersGet},
	"container.projects.zones.clusters.nodePools.fetchNodePoolUpgradeInfo":     {permContainerClustersGet},
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
	overrides map[string][]string
}

// NewPermissionResolver constructs the resolver with a validation catalog, a
// divergence-only prefix map, and an iam-dataset lookuper (nil disables the
// dataset tier; derive-then-validate still runs). The pinned override map is
// carried as a field rather than read from the package global inside Resolve, so
// tests can exercise the fail-closed guard without mutating shared state.
func NewPermissionResolver(
	cat map[string]bool, prefixMap map[string]string, dataset datasetLookuper,
) PermissionResolver {
	return &permResolver{
		cat:       cat,
		prefixMap: prefixMap,
		dataset:   dataset,
		overrides: methodPermissionOverrides,
	}
}

// Resolve returns the required IAM permission(s) for methodID and the source.
// Fail-closed: empty result → SourceNone (deny). Permissionless methods
// short-circuit. The HTTP method is irrelevant — the method-id verb (chosen by
// the classifier) determines read/write nature.
func (r *permResolver) Resolve(ctx context.Context, methodID string) ([]string, PermissionSource) {
	if permissionlessMethods[methodID] || strings.HasSuffix(methodID, ".testIamPermissions") {
		return nil, SourcePermissionless
	}

	if perms, ok := r.overrides[methodID]; ok {
		// An empty pin denies. SourceResolved with no permissions would reach
		// roleEvaluator.AllowedAll(nil), which is vacuously true — i.e. the method
		// would be authorized under every role. Fail closed instead.
		if len(perms) == 0 {
			return nil, SourceNone
		}
		return slices.Clone(perms), SourceResolved
	}

	read := isReadMethod(methodID)
	derived, haveDerived := r.derivePrimary(methodID)

	set := map[string]struct{}{}
	if haveDerived {
		set[derived] = struct{}{}
	}
	if r.dataset != nil {
		for _, perm := range r.datasetPerms(ctx, methodID, read, haveDerived) {
			set[perm] = struct{}{}
		}
	}

	if len(set) == 0 {
		return nil, SourceNone
	}
	return slices.Sorted(maps.Keys(set)), SourceResolved
}

// datasetPerms returns the dataset's contribution to methodID's required set.
//
// A WRITE unions the write tier in: its secondary permissions (multi-permission
// operations, iam.serviceAccounts.actAs) are real requirements, and
// over-requiring fails closed. A READ consults the read tier only as a FALLBACK
// when derivation produced nothing, because derivation is precise for reads and
// avoids the dataset's over-listing; a read whose derivation succeeded uses the
// derived primary alone.
func (r *permResolver) datasetPerms(ctx context.Context, methodID string, read, haveDerived bool) []string {
	if !read {
		return r.dataset.Lookup(ctx, methodID)
	}
	if haveDerived || mutatingReadMethods[methodID] {
		return nil
	}
	return r.dataset.LookupRead(ctx, methodID)
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
