package gcp

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
)

// fakeDataset is the test datasetLookuper. write is what Lookup returns (the
// write tier); read is what LookupRead returns (the read tier, a superset).
type fakeDataset struct {
	write map[string][]string
	read  map[string][]string
}

func (f fakeDataset) Lookup(_ context.Context, methodID string) []string { return f.write[methodID] }

func (f fakeDataset) LookupRead(_ context.Context, methodID string) []string {
	return f.read[methodID]
}

// emptyDataset always returns nil from both tiers.
type emptyDataset struct{}

func (emptyDataset) Lookup(_ context.Context, _ string) []string { return nil }

func (emptyDataset) LookupRead(_ context.Context, _ string) []string { return nil }

// readPermVerbs backs the verbSkew invariant test. readMethodVerbs is the
// production var (permissions.go); this file only adds the perm-verb set.
var readPermVerbs = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"get": true, "list": true, "getIamPolicy": true,
}

func TestPermissionResolverResolve(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{
		"compute.instances.list":         true,
		"compute.instances.get":          true,
		"compute.instances.create":       true,
		"compute.instances.delete":       true,
		"compute.instances.start":        true,
		"compute.instances.getIamPolicy": true,
		"resourcemanager.projects.get":   true,
	}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	tests := []struct {
		name       string
		methodID   string
		wantSource PermissionSource
		wantPerms  []string
	}{
		{"permissionless tokeninfo", "oauth2.tokeninfo", SourcePermissionless, nil},
		{"permissionless testIamPermissions", "compute.instances.testIamPermissions", SourcePermissionless, nil},
		{"read list", "compute.instances.list", SourceResolved, []string{"compute.instances.list"}},
		{"read get", "compute.instances.get", SourceResolved, []string{"compute.instances.get"}},
		{"write insert→create", "compute.instances.insert", SourceResolved, []string{"compute.instances.create"}},
		{"write delete", "compute.instances.delete", SourceResolved, []string{"compute.instances.delete"}},
		{"custom verb start (literal)", "compute.instances.start", SourceResolved, []string{"compute.instances.start"}},
		{"getIamPolicy", "compute.instances.getIamPolicy", SourceResolved, []string{"compute.instances.getIamPolicy"}},
		{
			"prefix divergence cloudresourcemanager",
			"cloudresourcemanager.projects.get",
			SourceResolved,
			[]string{"resourcemanager.projects.get"},
		},
		{"derived absent from catalog → none", "compute.disks.delete", SourceNone, nil},
		{"too few parts → none", "compute.instances", SourceNone, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			perms, src := r.Resolve(context.Background(), tc.methodID)
			if src != tc.wantSource {
				t.Fatalf("Resolve(%q) source = %v, want %v (perms=%v)", tc.methodID, src, tc.wantSource, perms)
			}
			if tc.wantSource == SourceResolved {
				if len(perms) != len(tc.wantPerms) || perms[0] != tc.wantPerms[0] {
					t.Errorf("Resolve(%q) perms = %v, want %v", tc.methodID, perms, tc.wantPerms)
				}
			}
		})
	}
}

// Identity passthrough: an unmapped API derives <api>.<resource…>.<verb>; valid
// only when the catalog confirms it.
func TestPermissionResolverIdentityPassthrough(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	perms, src := r.Resolve(context.Background(), "pubsub.projects.topics.publish")
	if src != SourceNone {
		t.Fatalf("identity passthrough miss: src=%v perms=%v", src, perms)
	}

	cat2 := map[string]bool{"pubsub.projects.topics.publish": true}
	r2 := NewPermissionResolver(cat2, defaultPrefixMap(), emptyDataset{})
	perms2, src2 := r2.Resolve(context.Background(), "pubsub.projects.topics.publish")
	if src2 != SourceResolved || len(perms2) != 1 || perms2[0] != "pubsub.projects.topics.publish" {
		t.Fatalf("identity passthrough hit: src=%v perms=%v", src2, perms2)
	}
}

// Union: the dataset contributes a secondary permission the derivation misses,
// and the result is deduped + sorted.
func TestPermissionResolverUnionWithDataset(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"compute.instances.create": true}
	m := map[string][]string{
		"compute.instances.insert": {"compute.instances.create", "iam.serviceAccounts.actAs"},
	}
	ds := fakeDataset{write: m, read: m}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(context.Background(), "compute.instances.insert")
	if src != SourceResolved {
		t.Fatalf("union: src=%v", src)
	}
	want := []string{"compute.instances.create", "iam.serviceAccounts.actAs"}
	if len(perms) != len(want) || perms[0] != want[0] || perms[1] != want[1] {
		t.Errorf("union perms = %v, want %v", perms, want)
	}
}

// Read skips dataset: a read whose derivation SUCCEEDS resolves to the derived
// primary ONLY — the dataset (with its over-listed secondary) is not consulted,
// so a common read is not false-denied. (A read whose derivation fails instead
// falls back to the dataset; see TestPermissionResolverReadDatasetFallback.)
// This exercises the read+derive-success branch of the Resolve dataset gate.
func TestPermissionResolverReadSkipsDataset(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"compute.instances.get": true}
	m := map[string][]string{
		"compute.instances.get": {"compute.instances.get", "compute.instances.list"},
	}
	ds := fakeDataset{write: m, read: m}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(context.Background(), "compute.instances.get")
	if src != SourceResolved {
		t.Fatalf("read skips dataset: src=%v", src)
	}
	// Dataset extra (compute.instances.list) must NOT be unioned in for a read.
	if len(perms) != 1 || perms[0] != "compute.instances.get" {
		t.Errorf("read skips dataset: perms = %v, want [compute.instances.get]", perms)
	}
}

// TestPermissionResolverReadDatasetFallback: a read whose derivation can't
// resolve (divergent API — derived perm absent from the catalog) falls back to
// the dataset, recovering coverage. (Reads that DO derive skip the dataset; see
// TestPermissionResolverReadSkipsDataset.)
func TestPermissionResolverReadDatasetFallback(t *testing.T) {
	t.Parallel()

	// Catalog lacks the derived "sqladmin.instances.get" (divergent: the real IAM
	// prefix is cloudsql, not in defaultPrefixMap); the dataset supplies the real
	// permission, so the read still resolves via the fallback.
	cat := map[string]bool{}
	m := map[string][]string{
		"sqladmin.instances.get": {"cloudsql.instances.get"},
	}
	ds := fakeDataset{write: m, read: m}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(context.Background(), "sqladmin.instances.get")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "cloudsql.instances.get" {
		t.Fatalf("read dataset fallback: src=%v perms=%v", src, perms)
	}
}

// Dataset-only: derivation produces nothing (empty catalog), dataset carries it;
// and a method neither keyed nor in the catalog resolves to none.
func TestPermissionResolverDatasetOnly(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{}
	m := map[string][]string{"weird.thing.frobnicate": {"weird.thing.frobnicate"}}
	ds := fakeDataset{write: m, read: m}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(context.Background(), "weird.thing.frobnicate")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "weird.thing.frobnicate" {
		t.Fatalf("dataset-only hit: src=%v perms=%v", src, perms)
	}

	perms2, src2 := r.Resolve(context.Background(), "weird.thing.unkeyed")
	if src2 != SourceNone {
		t.Fatalf("dataset-only miss: src=%v perms=%v", src2, perms2)
	}
}

// Nil dataset: derivation-only, no panic.
func TestPermissionResolverNilDataset(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"compute.instances.list": true}
	r := NewPermissionResolver(cat, defaultPrefixMap(), nil)

	perms, src := r.Resolve(context.Background(), "compute.instances.list")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "compute.instances.list" {
		t.Fatalf("nil dataset: src=%v perms=%v", src, perms)
	}
}

// A11: a crafted wrong-service method id derives a real-looking permission that
// the catalog (scoped to the true resource) rejects → denied. Pins that identity
// passthrough cannot fabricate a valid cross-service permission.
func TestPermissionResolverA11WrongServiceDenied(t *testing.T) {
	t.Parallel()

	// Catalog knows resourcemanager.projects.get but NOT compute.projects.get.
	cat := map[string]bool{"resourcemanager.projects.get": true}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	// methodID compute.projects.get → identity prefix compute → "compute.projects.get",
	// absent from the catalog → SourceNone (the cat.Has gate is the A11 guard).
	perms, src := r.Resolve(context.Background(), "compute.projects.get")
	if src != SourceNone {
		t.Fatalf("A11 wrong-service: want SourceNone, got src=%v perms=%v", src, perms)
	}
}

// SECURITY INVARIANT: verbSkew never maps a non-read method verb to a read perm
// verb (else a write method could derive a read permission and pass roles/viewer).
func TestVerbSkewNoMutatingToRead(t *testing.T) {
	t.Parallel()

	for methodVerb, permVerb := range verbSkew {
		if !readMethodVerbs[methodVerb] && readPermVerbs[permVerb] {
			t.Errorf("verbSkew[%q]=%q maps a non-read method verb to a read perm verb", methodVerb, permVerb)
		}
	}
}

func TestNewPermissionCatalog(t *testing.T) {
	t.Parallel()
	cat := NewPermissionCatalog([]string{"compute.instances.list", "storage.buckets.list"})
	if !cat["compute.instances.list"] {
		t.Error("seeded perm should be present")
	}
	if cat["iam.roles.create"] {
		t.Error("absent perm should be false")
	}
	empty := NewPermissionCatalog(nil)
	if empty["compute.instances.list"] {
		t.Error("empty catalog should return false")
	}
}

// wantOverrides is the authoritative expected content of methodPermissionOverrides.
// TestPermissionResolverOverrides asserts SET EQUALITY against the production map, so a
// new pin cannot be added without a reviewed row here — the map is a client-side
// authorization ceiling and every entry is hand-sourced from Google's first-party docs.
var wantOverrides = map[string][]string{ //nolint:gochecknoglobals // immutable test fixture.
	// projects.list requires the UNION: its id is shared by the v1 unfiltered
	// list (true perm .get) and the v3 parent-scoped list (true perm .list).
	"cloudresourcemanager.projects.list":        {"resourcemanager.projects.get", "resourcemanager.projects.list"},
	"cloudresourcemanager.projects.search":      {"resourcemanager.projects.get"},
	"cloudresourcemanager.folders.list":         {"resourcemanager.folders.list"},
	"cloudresourcemanager.folders.search":       {"resourcemanager.folders.get"},
	"cloudresourcemanager.organizations.search": {"resourcemanager.organizations.get"},

	// Container (GKE) control-plane reads. The permission names the LEAF resource
	// (clusters/operations) while the Discovery id nests it under projects.{locations,
	// zones}, and node-pool reads authorize on the PARENT cluster — neither shape is
	// derivable, so all twelve are pinned. Both the locations and the legacy zones
	// route are pinned because they are separate Discovery ids.
	"container.projects.locations.clusters.get":            {"container.clusters.get"},
	"container.projects.locations.clusters.list":           {"container.clusters.list"},
	"container.projects.locations.clusters.nodePools.get":  {"container.clusters.get"},
	"container.projects.locations.clusters.nodePools.list": {"container.clusters.get"},
	"container.projects.locations.operations.get":          {"container.operations.get"},
	"container.projects.locations.operations.list":         {"container.operations.list"},
	"container.projects.zones.clusters.get":                {"container.clusters.get"},
	"container.projects.zones.clusters.list":               {"container.clusters.list"},
	"container.projects.zones.clusters.nodePools.get":      {"container.clusters.get"},
	"container.projects.zones.clusters.nodePools.list":     {"container.clusters.get"},
	"container.projects.zones.operations.get":              {"container.operations.get"},
	"container.projects.zones.operations.list":             {"container.operations.list"},

	// These carry CUSTOM method verbs, so isReadMethod is false and they would
	// otherwise take the write path. The override short-circuits before that split,
	// which is what makes a read permission the right value here. Every one is a
	// plain GET.
	"container.projects.locations.getServerConfig":                             {"container.clusters.list"},
	"container.projects.zones.getServerconfig":                                 {"container.clusters.list"},
	"container.projects.locations.clusters.checkAutopilotCompatibility":        {"container.clusters.get"},
	"container.projects.locations.clusters.fetchClusterUpgradeInfo":            {"container.clusters.get"},
	"container.projects.zones.clusters.fetchClusterUpgradeInfo":                {"container.clusters.get"},
	"container.projects.locations.clusters.nodePools.fetchNodePoolUpgradeInfo": {"container.clusters.get"},
	"container.projects.zones.clusters.nodePools.fetchNodePoolUpgradeInfo":     {"container.clusters.get"},
}

// TestPermissionResolverOverrides pins the methodPermissionOverrides entries: the
// override is consulted first and is independent of the catalog/dataset tiers (here
// the catalog rejects everything and the dataset is empty), so each pinned discovery
// method resolves to its hand-pinned permission with SourceResolved. The set-equality
// assertion makes wantOverrides authoritative: an unreviewed production entry fails here.
func TestPermissionResolverOverrides(t *testing.T) {
	t.Parallel()

	if !maps.EqualFunc(methodPermissionOverrides, wantOverrides, slices.Equal) {
		t.Fatalf("methodPermissionOverrides = %v, want %v", methodPermissionOverrides, wantOverrides)
	}

	cat := map[string]bool{}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	for methodID, want := range wantOverrides {
		t.Run(methodID, func(t *testing.T) {
			t.Parallel()
			perms, src := r.Resolve(context.Background(), methodID)
			if src != SourceResolved {
				t.Fatalf("Resolve(%q) source = %v, want SourceResolved (perms=%v)", methodID, src, perms)
			}
			if !slices.Equal(perms, want) {
				t.Errorf("Resolve(%q) perms = %v, want %v", methodID, perms, want)
			}
		})
	}
}

// TestPermissionResolverOverrideBeatsDerivation proves the override wins over a
// catalog that WOULD validate the derived permission. For cloudresourcemanager.
// projects.search the catalog validates the (in reality non-existent) derived
// resourcemanager.projects.search, yet Resolve must return the pinned .get.
func TestPermissionResolverOverrideBeatsDerivation(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"resourcemanager.projects.search": true}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	perms, src := r.Resolve(context.Background(), "cloudresourcemanager.projects.search")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "resourcemanager.projects.get" {
		t.Fatalf("override must win over derivation: src=%v perms=%v", src, perms)
	}
}

// TestPermissionResolverOverrideBeatsDataset proves the override wins over a
// populated dataset that WOULD answer. The catalog is empty so derivation fails
// (haveDerived=false), and a read consults the dataset only when derivation fails;
// see datasetPerms. The dataset returns a different permission, yet Resolve must
// return the pinned .get because the override short-circuits before the dataset
// is ever reached.
func TestPermissionResolverOverrideBeatsDataset(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{}
	m := map[string][]string{
		"cloudresourcemanager.projects.search": {"resourcemanager.something.else"},
	}
	ds := fakeDataset{write: m, read: m}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(context.Background(), "cloudresourcemanager.projects.search")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "resourcemanager.projects.get" {
		t.Fatalf("override must win over the dataset: src=%v perms=%v", src, perms)
	}
}

// TestPermissionResolverOverrideReturnsIndependentSlice proves Resolve returns a
// fresh slice (slices.Clone), so a caller mutating the result cannot corrupt the
// pinned map. Compares against a literal want, NOT methodPermissionOverrides[id]
// (a missing clone would corrupt both identically and a map-based assert could pass).
func TestPermissionResolverOverrideReturnsIndependentSlice(t *testing.T) {
	t.Parallel()

	r := NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{})
	want := []string{"resourcemanager.projects.get", "resourcemanager.projects.list"}

	perms, _ := r.Resolve(context.Background(), "cloudresourcemanager.projects.list")
	perms[0] = "mutated"

	perms2, _ := r.Resolve(context.Background(), "cloudresourcemanager.projects.list")
	if !slices.Equal(perms2, want) {
		t.Fatalf("override slice not independent: second Resolve = %v, want %v", perms2, want)
	}
}

// TestOverridesAreReadOnly is the read-only-posture invariant: every override
// value is an IAM PERMISSION string and its verb (last dot-segment) must be a read
// PERM verb (readPermVerbs = {get,list,getIamPolicy}). It deliberately does NOT use
// readMethodVerbs, which also contains search/aggregatedList — valid as method
// verbs but never as permission verbs — so a future ".search"/".aggregatedList" or
// write-shaped override value fails closed here.
//
// It also pins the SHAPE of each value list — non-empty, sorted, duplicate-free —
// because Resolve returns the pinned slice verbatim: an empty list would deny (the
// guard in Resolve), and an unsorted or duplicated one would make the resolver's
// output depend on hand-editing order rather than on the permission set.
func TestOverridesAreReadOnly(t *testing.T) {
	t.Parallel()

	for methodID, perms := range methodPermissionOverrides {
		if len(perms) == 0 {
			t.Errorf("override %q has no permissions; an empty pin denies and is never intended", methodID)
		}
		if !slices.IsSorted(perms) {
			t.Errorf("override %q -> %v is not sorted", methodID, perms)
		}
		// Sortedness is asserted above, so any duplicate is adjacent.
		for i := 1; i < len(perms); i++ {
			if perms[i] == perms[i-1] {
				t.Errorf("override %q -> %v contains duplicates", methodID, perms)

				break
			}
		}
		for _, p := range perms {
			i := strings.LastIndex(p, ".")
			if i < 0 || !readPermVerbs[p[i+1:]] {
				t.Errorf("override %q -> %q is not a read permission (verb not in readPermVerbs)", methodID, p)
			}
		}
	}
}

// TestPermissionResolverDoesNotCollapseIntermediateSegments pins that derivation is
// EXACT: it never drops the intermediate segments of a method id to reach a shorter,
// catalog-valid permission. Collapsing would look attractive (it is what the container
// pins encode by hand) but the catalog proves only that a permission string EXISTS, not
// that it binds to this method — measured across the full GCP read surface, a collapse
// rule resolves 38 known methods to the WRONG permission, which in an authorization gate
// is a silent under-require. A method whose true permission is not derivable must stay
// unresolved and be pinned deliberately.
func TestPermissionResolverDoesNotCollapseIntermediateSegments(t *testing.T) {
	t.Parallel()

	// The collapsed candidate is the ONLY entry in the catalog, so a collapsing
	// derivation would resolve here and a exact one cannot.
	cat := map[string]bool{"svc.children.get": true}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	perms, src := r.Resolve(context.Background(), "svc.parents.children.get")
	if src != SourceNone {
		t.Fatalf("derivation must not collapse intermediate segments: src=%v perms=%v", src, perms)
	}
}

// TestPermissionResolverUsableSubnetworksStaysUnresolved pins a deliberate NON-entry.
// container.projects.aggregated.usableSubnetworks.list reads like a read (".list" verb,
// HTTP GET) but Google classifies it ADMIN_WRITE requiring container.clusters.create, so
// it must never be swept into the container read pins alongside its neighbours.
func TestPermissionResolverUsableSubnetworksStaysUnresolved(t *testing.T) {
	t.Parallel()

	r := NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), emptyDataset{})

	perms, src := r.Resolve(context.Background(), "container.projects.aggregated.usableSubnetworks.list")
	if src != SourceNone {
		t.Fatalf("usableSubnetworks.list must stay unresolved: src=%v perms=%v", src, perms)
	}
}

// TestPermissionResolverEmptyOverrideDenies pins the fail-closed guard on the pinned
// map itself. An override keyed with an EMPTY permission slice must deny, not resolve:
// roleEvaluator.AllowedAll(nil) returns true, so an empty pin that reached the caller as
// SourceResolved would authorize the method under ANY role — an allow bypass. No
// production entry is empty (TestOverridesAreReadOnly now rejects one statically), so
// this is the only test that exercises the runtime guard.
func TestPermissionResolverEmptyOverrideDenies(t *testing.T) {
	t.Parallel()

	// The catalog WOULD validate the derived permission, proving the deny comes from
	// the guard and is not a derivation miss.
	r := &permResolver{
		cat:       map[string]bool{"svc.things.get": true},
		prefixMap: defaultPrefixMap(),
		dataset:   emptyDataset{},
		overrides: map[string][]string{"svc.things.get": {}},
	}

	perms, src := r.Resolve(context.Background(), "svc.things.get")
	if src != SourceNone {
		t.Fatalf("empty override must deny: src=%v perms=%v", src, perms)
	}
}

// TestPermissionResolverNonOverriddenUnaffected: a near-neighbor of an override key
// that is NOT in the map still flows through derive-then-validate unchanged.
func TestPermissionResolverNonOverriddenUnaffected(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"resourcemanager.projects.get": true}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	perms, src := r.Resolve(context.Background(), "cloudresourcemanager.projects.get")
	if src != SourceResolved || len(perms) != 1 || perms[0] != "resourcemanager.projects.get" {
		t.Fatalf("non-overridden projects.get must derive normally: src=%v perms=%v", src, perms)
	}
}

// A read whose derivation fails resolves through the READ tier, which carries
// permissions the write tier deliberately omits.
func TestPermissionResolverReadUsesReadTier(t *testing.T) {
	t.Parallel()

	const method = "certificatemanager.projects.locations.certificates.list"

	// Guard: a pinned method short-circuits at the override branch and never
	// reaches the read tier, which would make this test vacuous.
	if _, pinned := methodPermissionOverrides[method]; pinned {
		t.Fatalf("%s is pinned; this test must use an unpinned method to exercise the read tier", method)
	}

	cat := map[string]bool{"certificatemanager.certs.list": true}
	ds := fakeDataset{
		write: map[string][]string{},
		read:  map[string][]string{method: {"certificatemanager.certs.list"}},
	}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(t.Context(), method)
	if src != SourceResolved {
		t.Fatalf("src = %v, want SourceResolved", src)
	}
	if !slices.Equal(perms, []string{"certificatemanager.certs.list"}) {
		t.Errorf("perms = %v, want [certificatemanager.certs.list]", perms)
	}
}

// The false-allow regression pin. A WRITE whose derivation fails must NOT pick
// up a read-tier answer: Google's apigateway...apis.create page documents only
// apigateway.locations.get, which roles/viewer grants, so unioning it in would
// authorize a resource-creating POST under a read-only ceiling.
func TestPermissionResolverWriteIgnoresReadTier(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"apigateway.locations.get": true}
	ds := fakeDataset{
		write: map[string][]string{},
		read:  map[string][]string{"apigateway.projects.locations.apis.create": {"apigateway.locations.get"}},
	}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	perms, src := r.Resolve(t.Context(), "apigateway.projects.locations.apis.create")
	if src != SourceNone {
		t.Fatalf("src = %v, want SourceNone (a write must not resolve from the read tier)", src)
	}
	if perms != nil {
		t.Errorf("perms = %v, want nil", perms)
	}
}

// Reads never lose coverage: a high-confidence-only answer still resolves,
// because readMap is a superset of writeMap. Guards the reroute to LookupRead.
func TestPermissionResolverReadKeepsHighConfidenceCoverage(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{"cloudsql.instances.get": true}
	perms := []string{"cloudsql.instances.get"}
	ds := fakeDataset{
		write: map[string][]string{"sqladmin.instances.get": perms},
		read:  map[string][]string{"sqladmin.instances.get": perms},
	}
	r := NewPermissionResolver(cat, defaultPrefixMap(), ds)

	got, src := r.Resolve(t.Context(), "sqladmin.instances.get")
	if src != SourceResolved || !slices.Equal(got, perms) {
		t.Fatalf("got %v/%v, want %v/SourceResolved", got, src, perms)
	}
}

// The denylist skips the read fallback ENTIRELY for a read-named method Google
// implements as a mutation, whichever tier holds the answer.
func TestPermissionResolverMutatingReadDenylist(t *testing.T) {
	t.Parallel()

	const method = "container.projects.aggregated.usableSubnetworks.list"

	t.Run("suppresses a read-tier answer", func(t *testing.T) {
		t.Parallel()
		ds := fakeDataset{
			write: map[string][]string{},
			read:  map[string][]string{method: {"container.clusters.list"}},
		}
		r := NewPermissionResolver(map[string]bool{"container.clusters.list": true}, defaultPrefixMap(), ds)
		perms, src := r.Resolve(t.Context(), method)
		if src != SourceNone || perms != nil {
			t.Fatalf("got %v/%v, want nil/SourceNone", perms, src)
		}
	})

	// Discriminates the two possible implementations: skipping LookupRead passes,
	// filtering it down to its high-confidence half would resolve and fail here.
	t.Run("suppresses a high-confidence answer too", func(t *testing.T) {
		t.Parallel()
		perms := []string{"container.clusters.list"}
		ds := fakeDataset{
			write: map[string][]string{method: perms},
			read:  map[string][]string{method: perms},
		}
		r := NewPermissionResolver(map[string]bool{"container.clusters.list": true}, defaultPrefixMap(), ds)
		got, src := r.Resolve(t.Context(), method)
		if src != SourceNone || got != nil {
			t.Fatalf("got %v/%v, want nil/SourceNone", got, src)
		}
	})

	// Not a general deny: a denylisted method whose derivation succeeds still
	// resolves to the derived permission.
	t.Run("does not suppress a successful derivation", func(t *testing.T) {
		t.Parallel()
		cat := map[string]bool{"container.projects.aggregated.usableSubnetworks.list": true}
		ds := fakeDataset{write: map[string][]string{}, read: map[string][]string{}}
		r := NewPermissionResolver(cat, defaultPrefixMap(), ds)
		got, src := r.Resolve(t.Context(), method)
		if src != SourceResolved ||
			!slices.Equal(got, []string{"container.projects.aggregated.usableSubnetworks.list"}) {
			t.Fatalf("got %v/%v, want the derived permission/SourceResolved", got, src)
		}
	})

	// A pinned override short-circuits before the denylist is ever consulted.
	t.Run("an explicit override still wins", func(t *testing.T) {
		t.Parallel()
		ds := fakeDataset{write: map[string][]string{}, read: map[string][]string{}}
		r, ok := NewPermissionResolver(map[string]bool{}, defaultPrefixMap(), ds).(*permResolver)
		if !ok {
			t.Fatalf("NewPermissionResolver did not return *permResolver")
		}
		r.overrides = map[string][]string{method: {"container.clusters.create"}}
		got, src := r.Resolve(t.Context(), method)
		if src != SourceResolved || !slices.Equal(got, []string{"container.clusters.create"}) {
			t.Fatalf("got %v/%v, want [container.clusters.create]/SourceResolved", got, src)
		}
	})
}
