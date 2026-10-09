package k8s

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// scanLiveBudget is the streaming pass's live-heap budget: its stack and key path hold at most MaxScanDepth frames.
const scanLiveBudget = 1 << 20

// hostileShape builds one of the three member-count shapes round four measured, at about size bytes: one
// method-less path item with many {} parameters, many method-less path items, or many unreferenced component
// parameters. No operation owns those elements, so only the streaming pass's element cap refuses them.
func hostileShape(kind string, size int) []byte {
	var b strings.Builder
	switch kind {
	case "parameters":
		b.WriteString(`{"paths":{"/p":{"parameters":[{}`)
		for b.Len() < size-8 {
			b.WriteString(`,{}`)
		}
		b.WriteString(`]}}}`)
	case "path items":
		b.WriteString(`{"paths":{"/z":{}`)
		for i := 0; b.Len() < size-32; i++ {
			fmt.Fprintf(&b, `,"/p%d":{}`, i)
		}
		b.WriteString(`}}`)
	default:
		b.WriteString(`{"components":{"parameters":{"z":{}`)
		for i := 0; b.Len() < size-32; i++ {
			fmt.Fprintf(&b, `,"p%d":{}`, i)
		}
		b.WriteString(`}}}`)
	}

	return []byte(b.String())
}

// liveDelta is the live heap a stage holds: HeapAlloc after a collection with the stage's result kept alive, minus
// the same figure before the stage. The input is allocated before the first reading.
func liveDelta(stage func() any) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := stage()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(v)

	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestScan_RefusesHostileShapesWithinItsLiveBudget(t *testing.T) {
	for _, kind := range []string{"parameters", "path items", "component parameters"} {
		body := hostileShape(kind, 10<<20)
		var err error
		live := liveDelta(func() any {
			_, err = Scan(t.Context(), body, MaxDocumentElements)

			return err
		})
		runtime.KeepAlive(body)
		if err == nil || err.Error() != "refused by the streaming pass: more than 100000 elements" {
			t.Fatalf("%s: err = %v, want the element cap", kind, err)
		}
		if live > scanLiveBudget {
			t.Errorf("%s: the pass held %d bytes live, budget %d", kind, live, scanLiveBudget)
		}
		t.Logf("%s: %d bytes, %d bytes live", kind, len(body), live)
	}
}
