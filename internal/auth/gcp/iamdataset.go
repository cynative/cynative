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

// highConfidenceMethodologies are the iam-dataset discoveryMethodology tags we
// trust: the per-method "Required permissions" doc block and hand-curated
// entries. Parameter-table-derived "restcrawlv1" is excluded to curb the
// over-listing that would cause false denials.
var highConfidenceMethodologies = map[string]bool{ //nolint:gochecknoglobals // immutable pinned set.
	"restcrawliamblockv1": true,
	"manual":              true,
}

// IAMDataset is the parsed, indexed subset of iann0036/iam-dataset
// gcp/map.json: a Discovery method id → high-confidence required-permission set.
type IAMDataset struct {
	methodMap map[string][]string
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

// ParseIAMDataset parses gcp/map.json and indexes method id → high-confidence
// permission names. Methods whose permissions are all low-confidence or empty
// produce no entry, so Lookup returns nil and the resolver falls through to
// derive-then-validate (empty is never treated as permissionless).
func ParseIAMDataset(raw []byte) (*IAMDataset, error) {
	var doc gcpDatasetDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrIAMDatasetUnavailable, err)
	}
	if len(doc.API) == 0 {
		return nil, fmt.Errorf("%w: empty api map", ErrIAMDatasetUnavailable)
	}
	d := &IAMDataset{methodMap: map[string][]string{}}
	for _, svc := range doc.API {
		for methodID, m := range svc.Methods {
			if perms := highConfidencePerms(m.Permissions); len(perms) > 0 {
				d.methodMap[methodID] = perms
			}
		}
	}
	return d, nil
}

// highConfidencePerms returns the deduped, sorted names of permissions carrying
// at least one high-confidence discovery methodology.
func highConfidencePerms(in []gcpDatasetPerm) []string {
	set := map[string]struct{}{}
	for _, p := range in {
		if p.Name == "" || !anyHighConfidence(p.DiscoveryMethodologies) {
			continue
		}
		set[p.Name] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(set))
}

func anyHighConfidence(tags []string) bool {
	for _, t := range tags {
		if highConfidenceMethodologies[t] {
			return true
		}
	}
	return false
}

// Lookup returns methodID's high-confidence permission set, or nil on miss.
func (d *IAMDataset) Lookup(methodID string) []string { return d.methodMap[methodID] }

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
