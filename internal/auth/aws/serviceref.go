package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cynative/cynative/internal/cache"
)

// ErrServiceRefUnavailable indicates Service Reference data could not be loaded.
var ErrServiceRefUnavailable = errors.New("aws_hardening: service reference data unavailable")

// SROperation is the per-operation Service Reference data we consume: the
// authorized-action set as pre-rendered "service:name" strings and the SDK
// client ids (used by the tier-2 join).
type SROperation struct {
	AuthorizedActions []string
	SDKNames          []string
}

// ServiceRefModel is the parsed per-service Service Reference document, keyed
// by operation short name (== Smithy operation name).
type ServiceRefModel struct {
	Service    string
	Operations map[string]SROperation
}

type srDoc struct {
	Name       string `json:"Name"`
	Operations []struct {
		Name              string `json:"Name"`
		AuthorizedActions []struct {
			Name    string `json:"Name"`
			Service string `json:"Service"`
		} `json:"AuthorizedActions"`
		SDK []struct {
			Name string `json:"Name"`
		} `json:"SDK"`
	} `json:"Operations"`
}

// ParseServiceRef parses a Service Reference per-service JSON document.
func ParseServiceRef(raw []byte) (*ServiceRefModel, error) {
	var doc srDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrServiceRefUnavailable, err)
	}
	if doc.Name == "" {
		return nil, fmt.Errorf("%w: missing service Name", ErrServiceRefUnavailable)
	}
	m := &ServiceRefModel{Service: doc.Name, Operations: make(map[string]SROperation, len(doc.Operations))}
	for _, op := range doc.Operations {
		seen := make(map[string]struct{}, len(op.AuthorizedActions))
		actions := make([]string, 0, len(op.AuthorizedActions))
		for _, a := range op.AuthorizedActions {
			key := a.Service + ":" + a.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			actions = append(actions, key)
		}
		sdkNames := make([]string, 0, len(op.SDK))
		for _, s := range op.SDK {
			sdkNames = append(sdkNames, s.Name)
		}
		m.Operations[op.Name] = SROperation{AuthorizedActions: actions, SDKNames: sdkNames}
	}
	return m, nil
}

// ServiceRefRegistryConfig wires the registry's external dependencies.
type ServiceRefRegistryConfig struct {
	cache.Config

	Fetcher func(ctx context.Context, service string) ([]byte, error)
}

// ServiceRefRegistry resolves ServiceRefModels by service name. Each service is
// backed by its own cache.TTLCache (in-memory → on-disk per TTL → fetcher,
// with stale-disk fallback), so the cache lifecycle is the shared, tested
// primitive rather than hand-rolled here.
type ServiceRefRegistry struct {
	cfg    ServiceRefRegistryConfig
	mu     sync.Mutex
	caches map[string]*cache.TTLCache[ServiceRefModel]
}

// NewServiceRefRegistry constructs a registry. No I/O until first Get.
func NewServiceRefRegistry(cfg ServiceRefRegistryConfig) *ServiceRefRegistry {
	return &ServiceRefRegistry{
		cfg:    cfg,
		caches: map[string]*cache.TTLCache[ServiceRefModel]{},
	}
}

// Get returns the ServiceRefModel for the lowercase service short name, or nil
// when it cannot be resolved. The nil-on-miss contract lets ActionResolver fall
// through to the next tier on a miss (it never authorizes from an unavailable
// Service Reference), matching the sibling iamDataset.Lookup contract.
func (r *ServiceRefRegistry) Get(ctx context.Context, service string) *ServiceRefModel {
	return r.cacheFor(service).Get(ctx)
}

// cacheFor returns the per-service TTLCache, constructing it once on first use.
func (r *ServiceRefRegistry) cacheFor(service string) *cache.TTLCache[ServiceRefModel] {
	r.mu.Lock()
	defer r.mu.Unlock()

	if c, ok := r.caches[service]; ok {
		return c
	}

	dir := filepath.Join(r.cfg.Dir, "serviceref")
	c := &cache.TTLCache[ServiceRefModel]{
		DataPath: filepath.Join(dir, service+".json"),
		MetaPath: filepath.Join(dir, service+".meta"),
		TTL:      r.cfg.TTL,
		Clock:    r.cfg.Clock,
		Fetch:    func(ctx context.Context) ([]byte, error) { return r.cfg.Fetcher(ctx, service) },
		Parse:    ParseServiceRef,
	}
	r.caches[service] = c

	return c
}
