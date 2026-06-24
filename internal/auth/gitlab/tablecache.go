package gitlab

import (
	"context"

	"github.com/cynative/cynative/internal/cache"
)

// TableSource resolves the category table via an internal/cache.TTLCache: fresh
// on-disk → live fetch (distill+serialize) → stale on-disk → nil (fail closed).
// The admission guard runs in Parse, so it applies to every source.
type TableSource struct {
	cache *cache.TTLCache[Table]
}

// NewTableSource builds a TableSource. cfg.Dir must already be namespaced to the
// gitlab connector (e.g. <cache>/gitlab); fetch returns the raw OpenAPI bytes.
func NewTableSource(cfg cache.Config, fetch func(ctx context.Context) ([]byte, error)) *TableSource {
	return &TableSource{
		cache: cache.NewTableCache(cfg, fetch, DistillOpenAPI, (*Table).Serialize, UnmarshalTable, AdmitTable),
	}
}

// Get returns the active table, or nil when none can be resolved (the provider
// then fails closed for classification-dependent traffic).
func (s *TableSource) Get(ctx context.Context) *Table {
	return s.cache.Get(ctx)
}
