package openapidoc_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// wideSchemaBudget bounds the allocation of distilling a 4.7 MB document whose one parameter has a wide object
// schema. Decoded into a tree of Go maps the schema took 88 MiB; held as raw JSON, about 9 MiB.
const wideSchemaBudget = 16 << 20

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestDistill_WideParameterSchemaAllocation(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"paths":{"/a":{"get":{"operationId":"a","parameters":[{"name":"q","in":"query","schema":{` +
		`"type":"object","properties":{"p0":{"type":"string"}`)
	for i := 1; b.Len() < 4_700_000; i++ {
		fmt.Fprintf(&b, `,"p%d":{"type":"string"}`, i)
	}
	b.WriteString(`}}}]}}}}`)
	body := []byte(b.String())
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d, err := openapidoc.Distill(body, testProfile())
	runtime.ReadMemStats(&after)
	if err != nil || d.Ops["a"].Params[0].Type != "object" {
		t.Fatalf("Distill: %v", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > wideSchemaBudget {
		t.Errorf("distilling %d bytes allocated %d bytes, budget %d", len(body), alloc, wideSchemaBudget)
	} else {
		t.Logf("distilling %d bytes allocated %d bytes", len(body), alloc)
	}
}
