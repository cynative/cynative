package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"github.com/cynative/cynative/internal/cache"
)

// ErrIAMDatasetUnavailable indicates the iam-dataset GCP map could not load.
var ErrIAMDatasetUnavailable = errors.New("gcp_hardening: iam-dataset unavailable")

// writeTierMethodologies are the iam-dataset discoveryMethodology tags trusted
// to state a WRITE's required permissions: the per-method "Required permissions"
// doc block and hand-curated entries. A write unions the dataset's answer into
// the required set, so an under-stated answer would authorize a mutation the
// ceiling role should refuse.
var writeTierMethodologies = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"restcrawliamblockv1": true,
	"manual":              true,
}

// readTierMethodologies additionally admits "restcrawlv1", the tag scraped from
// Google's per-parameter authorization block. For a read whose only documented
// block is the parent resource, that parent permission is Google's complete
// documented answer; for a write the same block is incomplete (Google's own
// apigateway...apis.create page names only apigateway.locations.get). That is
// why this tier is consulted for reads alone, via LookupRead.
//
// This is an ALLOWLIST, never "every tag that is not high confidence".
// gcp/map.json already carries a "fuzzv1" tag, and a tag added upstream must not
// widen the gate without a code change.
var readTierMethodologies = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"restcrawliamblockv1": true,
	"manual":              true,
	"restcrawlv1":         true,
}

// IAMDataset is the parsed, indexed subset of iann0036/iam-dataset
// gcp/map.json: Discovery method id to required-permission set, indexed twice.
// readMap is a superset of writeMap, so a read never resolves to less than a
// write would.
type IAMDataset struct {
	writeMap map[string][]string
	readMap  map[string][]string
}

type gcpDatasetPerm struct {
	Name                   string   `json:"name"`
	DiscoveryMethodologies []string `json:"discoveryMethodologies"`
}

type gcpDatasetMethod struct {
	Permissions []gcpDatasetPerm `json:"permissions"`
}

type gcpDatasetService struct {
	Methods map[string]gcpDatasetMethod `json:"methods"`
}

// gcpDatasetDoc mirrors gcp/map.json: api.<service>.methods.<methodId>.permissions[].
type gcpDatasetDoc struct {
	API map[string]gcpDatasetService `json:"api"`
}

// ParseIAMDataset parses gcp/map.json and builds both tier indexes. A method
// whose permissions are all filtered out of a tier produces no entry in that
// tier, so the lookup returns nil and the resolver falls through rather than
// treating an empty set as permissionless.
func ParseIAMDataset(raw []byte) (*IAMDataset, error) {
	var doc gcpDatasetDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrIAMDatasetUnavailable, err)
	}
	if len(doc.API) == 0 {
		return nil, fmt.Errorf("%w: empty api map", ErrIAMDatasetUnavailable)
	}
	d := &IAMDataset{writeMap: map[string][]string{}, readMap: map[string][]string{}}
	for _, svc := range doc.API {
		for methodID, m := range svc.Methods {
			if perms := permsForTier(m.Permissions, writeTierMethodologies); len(perms) > 0 {
				d.writeMap[methodID] = perms
			}
			if perms := permsForTier(m.Permissions, readTierMethodologies); len(perms) > 0 {
				d.readMap[methodID] = perms
			}
		}
	}
	return d, nil
}

// permsForTier returns the deduped, sorted names of permissions carrying at
// least one of tier's discovery methodologies.
func permsForTier(in []gcpDatasetPerm, tier map[string]bool) []string {
	set := map[string]struct{}{}
	for _, p := range in {
		if p.Name == "" || !anyMethodology(p.DiscoveryMethodologies, tier) {
			continue
		}
		set[p.Name] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(set))
}

func anyMethodology(tags []string, tier map[string]bool) bool {
	for _, t := range tags {
		if tier[t] {
			return true
		}
	}
	return false
}

// Lookup returns methodID's write-tier permission set, or nil on miss.
func (d *IAMDataset) Lookup(methodID string) []string { return d.writeMap[methodID] }

// LookupRead returns methodID's read-tier permission set, or nil on miss.
func (d *IAMDataset) LookupRead(methodID string) []string { return d.readMap[methodID] }

// IAMDatasetRegistryConfig wires the lazy registry's dependencies.
type IAMDatasetRegistryConfig struct {
	cache.Config

	Fetcher func(ctx context.Context) ([]byte, error)
}

// IAMDatasetRegistry loads gcp/map.json once on first successful Lookup
// (in-memory → on-disk per TTL → fetcher, stale-fallback), parses it, and
// answers lookups. A transient load failure degrades to a nil result (so the
// resolver falls through to derive-then-validate) AND leaves the registry
// unloaded, so a later Lookup retries instead of locking in the nil for the
// whole process. Backed by cache.TTLCache; implements the resolver's
// permission-lookup port.
type IAMDatasetRegistry struct {
	cache *cache.TTLCache[IAMDataset]
}

// NewIAMDatasetRegistry constructs the registry. No I/O until first Lookup.
func NewIAMDatasetRegistry(cfg IAMDatasetRegistryConfig) *IAMDatasetRegistry {
	dir := filepath.Join(cfg.Dir, "iam-dataset")
	return &IAMDatasetRegistry{cache: &cache.TTLCache[IAMDataset]{
		DataPath: filepath.Join(dir, "gcp-map.json"),
		MetaPath: filepath.Join(dir, "gcp-map.meta"),
		TTL:      cfg.TTL,
		Clock:    cfg.Clock,
		Fetch:    cfg.Fetcher,
		Parse:    ParseIAMDataset,
	}}
}

// Lookup loads the dataset on first call and returns methodID's permissions;
// returns nil if the dataset is unavailable or the method is unmapped.
func (r *IAMDatasetRegistry) Lookup(ctx context.Context, methodID string) []string {
	data := r.cache.Get(ctx)
	if data == nil {
		return nil
	}
	return data.Lookup(methodID)
}

// LookupRead loads the dataset on first call and returns methodID's read-tier
// permissions; returns nil if the dataset is unavailable or the method is
// unmapped. Shares one cache entry with Lookup.
func (r *IAMDatasetRegistry) LookupRead(ctx context.Context, methodID string) []string {
	data := r.cache.Get(ctx)
	if data == nil {
		return nil
	}
	return data.LookupRead(methodID)
}
