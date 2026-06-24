package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/cache"
)

// ErrIAMDatasetUnavailable indicates the iam-dataset map could not be loaded.
var ErrIAMDatasetUnavailable = errors.New("aws_hardening: iam-dataset unavailable")

// IAMDataset is the parsed, indexed subset of iann0036/iam-dataset map.json
// needed to resolve an operation to its IAM actions for services the Service
// Reference API does not map.
type IAMDataset struct {
	methodMap map[string][]string // "SDKID.Operation" -> ["service:action", ...].
	fold      map[string]string   // lowercase(SDKID) -> SDKID.
	normFold  map[string][]string // normalizeSDKID(SDKID) -> []SDKID (handles casing dupes).
	prefix    map[string][]string // endpointPrefix -> []SDKID (from sdk_service_mappings).
}

type iamDatasetDoc struct {
	SDKMethodIAMMappings map[string][]struct {
		Action string `json:"action"`
	} `json:"sdk_method_iam_mappings"`
	SDKServiceMappings map[string]string `json:"sdk_service_mappings"`
}

// ParseIAMDataset parses map.json and builds the lookup indexes.
func ParseIAMDataset(raw []byte) (*IAMDataset, error) {
	var doc iamDatasetDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrIAMDatasetUnavailable, err)
	}
	if len(doc.SDKMethodIAMMappings) == 0 {
		return nil, fmt.Errorf("%w: empty sdk_method_iam_mappings", ErrIAMDatasetUnavailable)
	}
	d := &IAMDataset{
		methodMap: make(map[string][]string, len(doc.SDKMethodIAMMappings)),
		fold:      make(map[string]string),
		normFold:  make(map[string][]string),
		prefix:    make(map[string][]string),
	}
	for key, acts := range doc.SDKMethodIAMMappings {
		actions := make([]string, 0, len(acts))
		for _, a := range acts {
			actions = append(actions, a.Action)
		}
		d.methodMap[key] = actions
		if sdkID, _, ok := strings.Cut(key, "."); ok {
			d.fold[strings.ToLower(sdkID)] = sdkID
			n := normalizeSDKID(sdkID)
			if !slices.Contains(d.normFold[n], sdkID) {
				d.normFold[n] = append(d.normFold[n], sdkID)
			}
		}
	}
	for sdkID, pfx := range doc.SDKServiceMappings {
		d.prefix[pfx] = append(d.prefix[pfx], sdkID)
	}
	return d, nil
}

// Lookup resolves the IAM actions for operation op in the given cynative
// service. botoNames are the operation's Service Reference SDK[].Name values
// (boto3 client ids); when empty (service wholly uncovered), the service prefix
// itself is used. Candidate iam-dataset SDK-ids come from exact case-fold of
// the boto name (preferred) plus the reverse sdk_service_mappings override; the
// first candidate that actually contains op wins. Returns nil on miss.
func (d *IAMDataset) Lookup(service string, botoNames []string, op string) []string {
	names := botoNames
	if len(names) == 0 {
		names = []string{service}
	}
	for _, b := range names { // exact-fold first across all boto names...
		if id, ok := d.fold[b]; ok {
			if acts, hit := d.methodMap[id+"."+op]; hit {
				return acts
			}
		}
	}
	for _, b := range names { // ...then reverse-override candidates.
		for _, id := range d.prefix[b] {
			if acts, hit := d.methodMap[id+"."+op]; hit {
				return acts
			}
		}
	}
	return nil
}

// normalizeSDKID lowercases s and strips every non-alphanumeric rune so the
// Smithy sdkId ("S3 Control") and the iam-dataset SDK id ("S3Control") join.
func normalizeSDKID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LookupSDKID resolves op's IAM actions by exact SDK identity. It normalizes
// sdkID and unions the actions of every dataset SDK id sharing that normalized
// form (the dataset contains casing-duplicate same-service ids such as
// IoT/Iot). The result is deterministic: candidate ids are visited in sorted
// order and actions are de-duplicated preserving first-seen order, so it matches
// the order-sensitive policy evaluator. Returns nil on miss.
func (d *IAMDataset) LookupSDKID(sdkID, op string) []string {
	candidates := slices.Clone(d.normFold[normalizeSDKID(sdkID)])
	slices.Sort(candidates)
	var out []string
	seen := map[string]struct{}{}
	for _, id := range candidates {
		for _, a := range d.methodMap[id+"."+op] {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

// IAMDatasetRegistryConfig wires the lazy registry's dependencies.
type IAMDatasetRegistryConfig struct {
	cache.Config

	Fetcher func(ctx context.Context) ([]byte, error)
}

// IAMDatasetRegistry loads the iam-dataset map once on first successful access
// (in-memory → on-disk per TTL → fetcher, stale-fallback), parses it, and
// answers lookups. A transient load failure degrades to a nil result (so the
// caller falls through to the next resolution tier) AND leaves the registry
// unloaded, so a later access retries instead of locking in the nil for the
// whole process. Backed by cache.TTLCache.
type IAMDatasetRegistry struct {
	cache *cache.TTLCache[IAMDataset]
}

// NewIAMDatasetRegistry constructs the registry. No I/O until first Lookup.
func NewIAMDatasetRegistry(cfg IAMDatasetRegistryConfig) *IAMDatasetRegistry {
	dir := filepath.Join(cfg.Dir, "iam-dataset")
	return &IAMDatasetRegistry{cache: &cache.TTLCache[IAMDataset]{
		DataPath: filepath.Join(dir, "map.json"),
		MetaPath: filepath.Join(dir, "map.meta"),
		TTL:      cfg.TTL,
		Clock:    cfg.Clock,
		Fetch:    cfg.Fetcher,
		Parse:    ParseIAMDataset,
	}}
}

// Lookup loads the dataset on first call and resolves op's actions; returns nil
// if the dataset is unavailable or the op is unmapped.
func (r *IAMDatasetRegistry) Lookup(ctx context.Context, service string, sdkNames []string, op string) []string {
	data := r.cache.Get(ctx)
	if data == nil {
		return nil
	}
	return data.Lookup(service, sdkNames, op)
}

// LookupSDKID loads the dataset on first call and resolves op's actions by exact
// SDK id; returns nil if the dataset is unavailable or the op is unmapped.
func (r *IAMDatasetRegistry) LookupSDKID(ctx context.Context, sdkID, op string) []string {
	data := r.cache.Get(ctx)
	if data == nil {
		return nil
	}
	return data.LookupSDKID(sdkID, op)
}
