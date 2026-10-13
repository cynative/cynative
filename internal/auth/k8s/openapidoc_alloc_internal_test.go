package k8s

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// sharedComponentBudget bounds the allocation of preparing a document whose one component parameter is referenced
// 24,800 times. Its verdict is computed once; computed per reference it allocated several times this.
const sharedComponentBudget = 8 << 20

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestPrepare_ASharedComponentIsCheckedOnce(t *testing.T) {
	ref := `{"$ref":"#/components/parameters/q"}`
	refs := strings.TrimSuffix(strings.Repeat(ref+",", 62), ",")
	var b strings.Builder
	b.WriteString(`{"components":{"parameters":{"q":{"name":"q","in":"query","schema":{"type":"string",` +
		`"description":"` + strings.Repeat("d", 4096) + `"}}}},"paths":{`)
	for i := range 400 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"/apis/apps/v1/p%d":{"get":{"operationId":"o%d","parameters":[%s]}}`, i, i, refs)
	}
	b.WriteString(`}}`)
	body := []byte(b.String())
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p, err := Prepare(t.Context(), body, appsKey)
	runtime.ReadMemStats(&after)
	if err != nil || len(p.Index) != 400 {
		t.Fatalf("Prepare: %v", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > sharedComponentBudget {
		t.Errorf("preparing %d bytes allocated %d bytes, budget %d", len(body), alloc, sharedComponentBudget)
	} else {
		t.Logf("preparing %d bytes allocated %d bytes", len(body), alloc)
	}
}

//nolint:paralleltest // testing.AllocsPerRun measures process-wide allocations.
func TestPathLabels_RefusesALongPathBeforeWalkingIt(t *testing.T) {
	long := "/" + appsKey + strings.Repeat("/a", 1<<20)
	if n := testing.AllocsPerRun(5, func() { _, _ = pathLabels(long, appsKey) }); n != 0 {
		t.Errorf("a %d-byte path allocated %.0f times before its length check", len(long), n)
	}
}

// nestedTypeBudget bounds the allocation of preparing a document just under the size cap whose one parameter's
// schema type is an object holding an array at depth 10, below the streaming pass's counted depth. The type is
// read as a string or not at all; decoded into Go values it built millions of maps.
const nestedTypeBudget = 64 << 20

// nestedTypeDocument is that document: about 3.5 million {} elements at depth 10.
func nestedTypeDocument() []byte {
	var b strings.Builder
	b.WriteString(`{"paths":{"/apis/apps/v1/a":{"get":{"operationId":"a","parameters":[{"name":"q","in":"query",` +
		`"schema":{"type":{"x":{"y":[{}`)
	for b.Len() < 10<<20-64 {
		b.WriteString(`,{}`)
	}
	b.WriteString(`]}}}}]}}}}`)

	return []byte(b.String())
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestPrepare_ANestedTypeIsNeverMaterialized(t *testing.T) {
	body := nestedTypeDocument()
	if n, err := Scan(t.Context(), body, MaxDocumentElements); err != nil {
		t.Fatalf("the streaming pass refused the shape after %d elements: %v", n, err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p, err := Prepare(t.Context(), body, appsKey)
	runtime.ReadMemStats(&after)
	if err != nil || p.Index["a"].Class != ClassAdmitted {
		t.Fatalf("Prepare: %+v %v", p, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > nestedTypeBudget {
		t.Errorf("preparing %d bytes allocated %d bytes, budget %d", len(body), alloc, nestedTypeBudget)
	} else {
		t.Logf("preparing %d bytes allocated %d bytes", len(body), alloc)
	}
}

//nolint:paralleltest // testing.AllocsPerRun measures process-wide allocations.
func TestDocument_SizeAllocatesNothing(t *testing.T) {
	body, err := os.ReadFile("testdata/openapi/api_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := ParseAPIVersion("v1")
	d, err := ParseDocument(t.Context(), body, v)
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(10, func() { _ = d.Size(1 << 30) }); n != 0 {
		t.Errorf("measuring an entry allocated %.0f times", n)
	}
}

// requestTypesDeadline bounds one requestTypes call over the most distinct types a document under the element cap can
// list. Holding every distinct type and checking each new one against all of them took about 34 seconds; the
// bounded list takes about a second under the race detector.
const requestTypesDeadline = 15 * time.Second

func TestRequestTypes_KeepsOnlySixWhileScanning(t *testing.T) {
	t.Parallel()
	types := make([]string, 99_990)
	for i := range types {
		types[i] = fmt.Sprintf("application/t%06d", len(types)-i)
	}
	want := []string{
		"application/t000001", "application/t000002", "application/t000003",
		"application/t000004", "application/t000005", "application/t000006",
	}
	start := time.Now()
	got := requestTypes(types)
	if took := time.Since(start); took > requestTypesDeadline {
		t.Errorf("scanning %d distinct types took %s, deadline %s", len(types), took, requestTypesDeadline)
	}
	if !slices.Equal(got, want) {
		t.Errorf("requestTypes = %q, want %q", got, want)
	}
}

// longRouteBudget bounds the allocation of preparing a document whose one rejected path is 9 MiB long and lists
// all seven methods under one operationId. Sorting its routes by a joined METHOD and path string allocated two
// copies of the path per comparison.
const longRouteBudget = 24 << 20

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestPrepare_SortingRoutesCopiesNoPath(t *testing.T) {
	path := "/" + appsKey + "/" + strings.Repeat("a", 9<<20)
	var ops []string
	for _, m := range []string{"get", "put", "post", "delete", "options", "head", "patch"} {
		ops = append(ops, `"`+m+`":{"operationId":"a"}`)
	}
	body := []byte(opDoc(path, strings.Join(ops, ",")))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p, err := Prepare(t.Context(), body, appsKey)
	runtime.ReadMemStats(&after)
	if err != nil || len(p.Index["a"].Routes) != 7 {
		t.Fatalf("Prepare: %+v %v", p, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > longRouteBudget {
		t.Errorf("preparing %d bytes allocated %d bytes, budget %d", len(body), alloc, longRouteBudget)
	} else {
		t.Logf("preparing %d bytes allocated %d bytes", len(body), alloc)
	}
}
