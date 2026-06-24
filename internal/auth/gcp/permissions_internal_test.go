package gcp

import (
	"context"
	"strings"
	"testing"
)

// fakeDataset is the test datasetLookuper.
type fakeDataset struct{ m map[string][]string }

func (f fakeDataset) Lookup(_ context.Context, methodID string) []string { return f.m[methodID] }

// emptyDataset always returns nil.
type emptyDataset struct{}

func (emptyDataset) Lookup(_ context.Context, _ string) []string { return nil }

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
	ds := fakeDataset{m: map[string][]string{
		"compute.instances.insert": {"compute.instances.create", "iam.serviceAccounts.actAs"},
	}}
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
	ds := fakeDataset{m: map[string][]string{
		"compute.instances.get": {"compute.instances.get", "compute.instances.list"},
	}}
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
	ds := fakeDataset{m: map[string][]string{
		"sqladmin.instances.get": {"cloudsql.instances.get"},
	}}
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
	ds := fakeDataset{m: map[string][]string{"weird.thing.frobnicate": {"weird.thing.frobnicate"}}}
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

// TestPermissionResolverOverrides pins the methodPermissionOverrides entries: the
// override is consulted first and is independent of the catalog/dataset tiers (here
// the catalog rejects everything and the dataset is empty), so each Resource Manager
// discovery method resolves to its hand-pinned permission with SourceResolved.
func TestPermissionResolverOverrides(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{}
	r := NewPermissionResolver(cat, defaultPrefixMap(), emptyDataset{})

	tests := []struct {
		methodID string
		want     string
	}{
		{"cloudresourcemanager.projects.list", "resourcemanager.projects.list"},
		{"cloudresourcemanager.projects.search", "resourcemanager.projects.get"},
		{"cloudresourcemanager.folders.list", "resourcemanager.folders.list"},
		{"cloudresourcemanager.folders.search", "resourcemanager.folders.get"},
		{"cloudresourcemanager.organizations.search", "resourcemanager.organizations.get"},
	}
	for _, tc := range tests {
		t.Run(tc.methodID, func(t *testing.T) {
			t.Parallel()
			perms, src := r.Resolve(context.Background(), tc.methodID)
			if src != SourceResolved {
				t.Fatalf("Resolve(%q) source = %v, want SourceResolved (perms=%v)", tc.methodID, src, perms)
			}
			if len(perms) != 1 || perms[0] != tc.want {
				t.Errorf("Resolve(%q) perms = %v, want [%s]", tc.methodID, perms, tc.want)
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
// (haveDerived=false) — the ONLY condition under which a read method consults the
// dataset (the Resolve dataset gate is `r.dataset != nil && (!read || !haveDerived)`).
// The dataset returns a different permission, yet Resolve must return the pinned
// .get because the override short-circuits before the dataset is ever reached.
func TestPermissionResolverOverrideBeatsDataset(t *testing.T) {
	t.Parallel()

	cat := map[string]bool{}
	ds := fakeDataset{m: map[string][]string{
		"cloudresourcemanager.projects.search": {"resourcemanager.something.else"},
	}}
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
	want := []string{"resourcemanager.projects.list"}

	perms, _ := r.Resolve(context.Background(), "cloudresourcemanager.projects.list")
	perms[0] = "mutated"

	perms2, _ := r.Resolve(context.Background(), "cloudresourcemanager.projects.list")
	if len(perms2) != 1 || perms2[0] != want[0] {
		t.Fatalf("override slice not independent: second Resolve = %v, want %v", perms2, want)
	}
}

// TestOverridesAreReadOnly is the read-only-posture invariant: every override
// value is an IAM PERMISSION string and its verb (last dot-segment) must be a read
// PERM verb (readPermVerbs = {get,list,getIamPolicy}). It deliberately does NOT use
// readMethodVerbs, which also contains search/aggregatedList — valid as method
// verbs but never as permission verbs — so a future ".search"/".aggregatedList" or
// write-shaped override value fails closed here.
func TestOverridesAreReadOnly(t *testing.T) {
	t.Parallel()

	for methodID, perms := range methodPermissionOverrides {
		for _, p := range perms {
			i := strings.LastIndex(p, ".")
			if i < 0 || !readPermVerbs[p[i+1:]] {
				t.Errorf("override %q -> %q is not a read permission (verb not in readPermVerbs)", methodID, p)
			}
		}
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
