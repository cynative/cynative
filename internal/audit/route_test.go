package audit_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/cynative/cynative/internal/audit"
)

func TestRoute_UnsetIsEmpty(t *testing.T) {
	t.Parallel()

	_, r := audit.WithRoute(context.Background())
	if got := r.Value(); got != "" {
		t.Fatalf("Value() = %q, want empty before any mark", got)
	}
}

func TestMarkRoute_RecordsDirectAndProxy(t *testing.T) {
	t.Parallel()

	ctx, r := audit.WithRoute(context.Background())
	audit.MarkRoute(ctx, false)
	if got := r.Value(); got != audit.RouteDirect {
		t.Fatalf("Value() = %q, want %q", got, audit.RouteDirect)
	}
	audit.MarkRoute(ctx, true)
	if got := r.Value(); got != audit.RouteProxy {
		t.Fatalf("Value() = %q, want %q", got, audit.RouteProxy)
	}
}

func TestMarkRoute_NoRecorderIsNoop(t *testing.T) {
	t.Parallel()

	audit.MarkRoute(context.Background(), true) // must not panic.
}

func TestMarkRoute_ConcurrentWritesAreRaceFree(t *testing.T) {
	t.Parallel()

	ctx, r := audit.WithRoute(context.Background())
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(proxied bool) {
			defer wg.Done()
			audit.MarkRoute(ctx, proxied)
		}(i%2 == 0)
	}
	wg.Wait()
	if got := r.Value(); got != audit.RouteDirect && got != audit.RouteProxy {
		t.Fatalf("Value() = %q, want one of the two routes", got)
	}
}

func TestRecord_RouteSerializesOnlyWhenSet(t *testing.T) {
	t.Parallel()

	without, err := json.Marshal(audit.Record{})
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(t, without, "route") {
		t.Fatalf("zero record must omit route: %s", without)
	}
	with, err := json.Marshal(audit.Record{Route: audit.RouteProxy})
	if err != nil {
		t.Fatal(err)
	}
	if !containsKey(t, with, "route") {
		t.Fatalf("record with route must serialize it: %s", with)
	}
}

func containsKey(t *testing.T, raw []byte, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	_, ok := m[key]

	return ok
}
