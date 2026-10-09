package k8s

import (
	"runtime"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// Stage budgets for the pre-pass, the core decode and distillation: the live heap the stage's result holds, and
// the allocation of one core decode. The pre-pass's own decode is held to the same allocation budget.
const (
	stageLiveBudget  = 40 << 20
	coreAllocBudget  = 96 << 20
	maxDocumentBytes = 10 << 20
)

// atCapDocument is the costliest at-cap shape measured for this stage: one admitted operation beside a
// method-less path item whose parameter list holds every other counted element as {}.
func atCapDocument() []byte {
	var b strings.Builder
	b.WriteString(`{"paths":{"/apis/apps/v1/a":{"get":{"operationId":"a"}},"/apis/apps/v1/p":{"parameters":[{}`)
	for range MaxDocumentElements - 7 {
		b.WriteString(`,{}`)
	}
	b.WriteString(`]}}}`)

	return []byte(b.String())
}

// scalarStringDocument is just under the document cap: one admitted operation whose description, and one
// parameter's description, are "x " repeated, a quarter and three quarters of the body.
func scalarStringDocument() []byte {
	quarter := (maxDocumentBytes - 512) / 8

	return []byte(`{"paths":{"/apis/apps/v1/a":{"get":{"operationId":"a","description":"` +
		strings.Repeat("x ", quarter) + `","parameters":[{"name":"q","in":"query","description":"` +
		strings.Repeat("x ", 3*quarter) + `","schema":{"type":"string"}}]}}}}`)
}

// methodlessItemBudget bounds the pre-pass over atCapDocument: the parameters of a path item with no operation are
// never checked. Checked, they cost about 83 MB; unchecked, about 43 MB.
const methodlessItemBudget = 64 << 20

type stageFigures struct {
	live, prepAlloc, coreAlloc uint64
}

// measureStage runs ParseDocument on body, keeping its result alive, and separately one core decode with the
// same profile, and returns the live and allocated figures.
func measureStage(t *testing.T, body []byte) (*Document, stageFigures) {
	t.Helper()
	v, _ := ParseAPIVersion("apps/v1")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d, err := ParseDocument(t.Context(), body, v)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	live := after.HeapAlloc - min(after.HeapAlloc, before.HeapAlloc)
	runtime.GC()
	runtime.ReadMemStats(&before)
	prep, err := Prepare(t.Context(), body, v.Key)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	prepAlloc := after.TotalAlloc - before.TotalAlloc
	runtime.GC()
	runtime.ReadMemStats(&before)
	docs, err := openapidoc.DistillContext(t.Context(), body, distillProfile(prep))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(docs)
	runtime.KeepAlive(body)

	return d, stageFigures{live: live, prepAlloc: prepAlloc, coreAlloc: after.TotalAlloc - before.TotalAlloc}
}

func checkStage(t *testing.T, name string, size int, f stageFigures) {
	t.Helper()
	if f.live > stageLiveBudget || f.prepAlloc > coreAllocBudget || f.coreAlloc > coreAllocBudget {
		t.Errorf("%s: live %d bytes (budget %d), the pre-pass allocated %d bytes and one core decode %d bytes "+
			"(budget %d each)", name, f.live, stageLiveBudget, f.prepAlloc, f.coreAlloc, coreAllocBudget)
	}
	t.Logf("%s: %d bytes, live %d bytes, pre-pass allocated %d bytes, core decode allocated %d bytes", name, size,
		f.live, f.prepAlloc, f.coreAlloc)
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestParseDocument_AtTheElementCapWithinItsBudgets(t *testing.T) {
	body := atCapDocument()
	n, err := Scan(t.Context(), body, MaxDocumentElements)
	if err != nil || n != MaxDocumentElements {
		t.Fatalf("the shape counts %d elements (%v), want %d", n, err, MaxDocumentElements)
	}
	d, f := measureStage(t, body)
	checkStage(t, "at the element cap", len(body), f)
	if f.prepAlloc > methodlessItemBudget {
		t.Errorf("the pre-pass allocated %d bytes, budget %d", f.prepAlloc, methodlessItemBudget)
	}
	if res := lookup(d, "a"); res.Outcome != apiref.OutcomeFound {
		t.Errorf("lookup: %+v", res)
	}
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestParseDocument_LongTextWithinItsBudgets(t *testing.T) {
	body := scalarStringDocument()
	if len(body) >= maxDocumentBytes {
		t.Fatalf("the shape is %d bytes, over the document cap", len(body))
	}
	d, f := measureStage(t, body)
	checkStage(t, "long descriptions", len(body), f)
	res := lookup(d, "a")
	if res.Outcome != apiref.OutcomeFound {
		t.Fatalf("lookup: %+v", res)
	}
	ref := res.Reference
	if !strings.HasSuffix(ref.Summary, "x...") || len([]rune(ref.Summary)) != apiref.MaxSummary ||
		!strings.HasSuffix(ref.Inputs[0].Description, "x...") ||
		len([]rune(ref.Inputs[0].Description)) != apiref.MaxInputDescription {
		t.Errorf("summary %q, input %+v", ref.Summary, ref.Inputs[0])
	}
}

// textBudget is the allocation budget of the text work on one description: an 8 KiB cut of "x " splits into
// 4,096 fields, 64 KiB of []string.
const textBudget = 256 << 10

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestPostProcess_CutsTheDescriptionBeforeStrippingIt(t *testing.T) {
	v, _ := ParseAPIVersion("apps/v1")
	x := Extras{Description: strings.Repeat("x ", 4<<20)}
	op := openapidoc.OperationDoc{Method: "GET", Path: "/apis/apps/v1/a"}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	postProcess(v, &op, x)
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > textBudget {
		t.Errorf("post-processing a %d-byte description allocated %d bytes, budget %d", len(x.Description), alloc,
			textBudget)
	} else {
		t.Logf("post-processing a %d-byte description allocated %d bytes", len(x.Description), alloc)
	}
	if !strings.HasSuffix(op.Summary, "x...") {
		t.Errorf("summary %q", op.Summary)
	}
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestParseDocument_ANestedTypeWithinItsBudgets(t *testing.T) {
	body := nestedTypeDocument()
	d, f := measureStage(t, body)
	checkStage(t, "a nested parameter type", len(body), f)
	if res := lookup(d, "a"); res.Outcome != apiref.OutcomeFound || res.Reference.Inputs[0].Type != "unknown" {
		t.Errorf("lookup: %+v", res)
	}
}

// sharedParameterBudget bounds each pass over sharedPathParameterDocument: a path item's parameters are read once,
// not once per method, so the schema is copied once. Read per method it cost about 84 MB a pass.
const sharedParameterBudget = 32 << 20

// sharedPathParameterDocument is just under the document cap: one path item whose single inline query parameter
// carries a schema description of nearly the whole body, shared by seven methods with distinct ids.
func sharedPathParameterDocument() []byte {
	var ops []string
	for _, m := range []string{"get", "put", "post", "delete", "options", "head", "patch"} {
		ops = append(ops, `"`+m+`":{"operationId":"`+m+`A"}`)
	}

	return []byte(`{"paths":{"/apis/apps/v1/a":{"parameters":[{"name":"q","in":"query","schema":{"type":"string",` +
		`"description":"` + strings.Repeat("x", maxDocumentBytes-1024) + `"}}],` + strings.Join(ops, ",") + `}}}`)
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestParseDocument_ASharedPathParameterWithinItsBudgets(t *testing.T) {
	body := sharedPathParameterDocument()
	if len(body) >= maxDocumentBytes {
		t.Fatalf("the shape is %d bytes, over the document cap", len(body))
	}
	d, f := measureStage(t, body)
	checkStage(t, "a shared path parameter", len(body), f)
	if f.prepAlloc > sharedParameterBudget || f.coreAlloc > sharedParameterBudget {
		t.Errorf("the pre-pass allocated %d bytes and one core decode %d bytes, budget %d each", f.prepAlloc,
			f.coreAlloc, sharedParameterBudget)
	}
	if res := lookup(d, "getA"); res.Outcome != apiref.OutcomeFound {
		t.Errorf("lookup: %+v", res)
	}
}

// largeRefBesideUnusedParametersDocument is just under both caps: an admitted operation whose response schema
// $ref is nearly the whole body, beside a method-less path item holding most of the counted elements as {}
// parameters. Each cost alone fits the budget; decoding the unused parameters as well did not.
func largeRefBesideUnusedParametersDocument() []byte {
	var b strings.Builder
	b.WriteString(`{"openapi":"3.0.0","info":{"title":"t","version":"v"},"paths":{"/apis/apps/v1/a":{"get":{` +
		`"operationId":"a","responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"$ref":"`)
	b.WriteString(strings.Repeat("r", 10_180_000))
	b.WriteString(`"}}}}}}},"/apis/apps/v1/p":{"parameters":[{}`)
	for range MaxDocumentElements - 21 {
		b.WriteString(`,{}`)
	}
	b.WriteString(`]}}}`)

	return []byte(b.String())
}

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestParseDocument_ALargeRefBesideUnusedParametersWithinItsBudgets(t *testing.T) {
	body := largeRefBesideUnusedParametersDocument()
	if n, err := Scan(t.Context(), body, MaxDocumentElements); err != nil || len(body) >= maxDocumentBytes {
		t.Fatalf("the shape is %d bytes and %d elements (%v), want both under their caps", len(body), n, err)
	}
	d, f := measureStage(t, body)
	checkStage(t, "a large $ref beside unused parameters", len(body), f)
	if res := lookup(d, "a"); res.Outcome != apiref.OutcomeFound {
		t.Errorf("lookup: %+v", res)
	}
}
