package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// specTestSHA is the commit every fixture index names.
const specTestSHA = "0123456789abcdef0123456789abcdef01234567"

// specFakeFiles serves spec files by path and counts the reads, for the resolver and the lookup tests.
type specFakeFiles struct {
	mu     sync.Mutex
	bodies map[string][]byte
	fail   map[string]error
	calls  map[string]int
}

func newSpecFakeFiles(bodies map[string]string) *specFakeFiles {
	f := &specFakeFiles{bodies: map[string][]byte{}, fail: map[string]error{}, calls: map[string]int{}}
	for p, b := range bodies {
		f.bodies[p] = []byte(b)
	}

	return f
}

func (f *specFakeFiles) File(_ context.Context, _ string, file IndexFile) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[file.Path]++
	if err := f.fail[file.Path]; err != nil {
		return nil, err
	}
	b, ok := f.bodies[file.Path]
	if !ok {
		return nil, fmt.Errorf("no fixture %s", file.Path)
	}

	return b, nil
}

func (f *specFakeFiles) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls[p]
}

// refIndex is an index whose ref targets are exactly paths.
func refIndex(paths ...string) *Index {
	refs := map[string]string{}
	for i, p := range paths {
		refs[p] = fmt.Sprintf("%040x", i+1)
	}

	return &Index{SHA: specTestSHA, Namespaces: map[string]*IndexNamespace{}, Refs: refs}
}

const (
	testOpFile = "specification/test/resource-manager/Microsoft.Test/Test/stable/2024-01-01/things.json"
	commonFile = "specification/common-types/resource-management/v5/types.json"
	localFile  = "specification/test/resource-manager/Microsoft.Test/Test/common/v1/common.json"
)

func TestSummarize(t *testing.T) {
	t.Parallel()
	body := `{"info":{"version":"2024-01-01"},
		"paths":{"/b":{"parameters":[],"x-ext":{},"x-foo":{"operationId":"NotAnOp"},"put":{"operationId":"B_Put"},"get":{"operationId":"B_Get"}},
			"/a":{"get":{"operationId":"A_Get"},"post":{},"delete":{"operationId":7}}},
		"x-ms-paths":{"/a?op=x":{"post":{"operationId":"A_Do"}}}}`
	got, err := Summarize([]byte(body))
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	want := []OpSummary{
		{ID: "A_Get", Method: "GET", Path: "/a"},
		{ID: "B_Get", Method: "GET", Path: "/b"},
		{ID: "B_Put", Method: "PUT", Path: "/b"},
		{ID: "A_Do", Method: "POST", Path: "/a?op=x", XMs: true},
	}
	if got.Version != "2024-01-01" || fmt.Sprint(got.Ops) != fmt.Sprint(want) {
		t.Fatalf("summarize = %+v, want version 2024-01-01 and %+v", got, want)
	}
}

func TestDecodeSwaggerRejects(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`not json`, `{"paths":{"/a":[]}}`} {
		if _, err := decodeSwagger([]byte(body)); !errors.Is(err, ErrSpecsRejected) {
			t.Errorf("decodeSwagger(%s) error = %v, want ErrSpecsRejected", body, err)
		}
		if _, err := Summarize([]byte(body)); !errors.Is(err, ErrSpecsRejected) {
			t.Errorf("Summarize(%s) error = %v, want ErrSpecsRejected", body, err)
		}
	}
}

func TestOperation(t *testing.T) {
	t.Parallel()
	d, err := decodeSwagger([]byte(`{
		"paths":{"/a":{"parameters":[{"name":"p","in":"path"}],"get":{"operationId":"A_Get","summary":"s"}},
			"/bad":{"get":{"operationId":7}},"/badcommon":{"parameters":{},"get":{"operationId":"C"}}},
		"x-ms-paths":{"/a?x":{"post":{"operationId":"A_Do","x-ms-long-running-operation":true}}}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	op, common, err := d.operation(OpSummary{ID: "A_Get", Method: "GET", Path: "/a"})
	if err != nil || op.Summary != "s" || len(common) != 1 {
		t.Fatalf("operation(/a) = %+v, %d common, %v", op, len(common), err)
	}
	op, _, err = d.operation(OpSummary{ID: "A_Do", Method: "POST", Path: "/a?x", XMs: true})
	if err != nil || !op.LongRunning {
		t.Fatalf("operation(x-ms) = %+v, %v", op, err)
	}
	for _, s := range []OpSummary{
		{ID: "A", Method: "PUT", Path: "/a"},
		{ID: "A", Method: "GET", Path: "/missing"},
		{ID: "A", Method: "GET", Path: "/bad"},
		{ID: "C", Method: "GET", Path: "/badcommon"},
		{ID: "Other_Get", Method: "GET", Path: "/a"}, // a summary that names the wrong operation
		{ID: "", Method: "GET", Path: "/a"},          // empty ID
		{ID: "A_Get", Method: "INVALID", Path: "/a"}, // invalid method
		{ID: "A_Get", Method: "x-foo", Path: "/a"},   // non-method key
	} {
		if _, _, operr := d.operation(s); !errors.Is(operr, ErrSpecsRejected) {
			t.Errorf("operation(%+v) error = %v, want ErrSpecsRejected", s, operr)
		}
	}
}

func TestRefPath(t *testing.T) {
	t.Parallel()
	ix := refIndex(testOpFile, commonFile, localFile)
	ok := map[string]string{
		"": testOpFile,
		"../../../../../../common-types/resource-management/v5/types.json": commonFile,
		"../../common/v1/common.json":                                      localFile,
		"../../common/v1/./common.json":                                    localFile,
		"%2E%2E/%2E%2E/common/v1/common.json":                              localFile,
	}
	for file, want := range ok {
		if got, err := refPath(testOpFile, file, ix); err != nil || got != want {
			t.Errorf("refPath(%q) = %q, %v, want %q", file, got, err, want)
		}
	}
	// An empty file part names the referring file, which must be a ref target too.
	if _, err := refPath("other/notarget.json", "", ix); !errors.Is(err, errRefConfined) {
		t.Errorf("refPath from outside the trees error = %v, want errRefConfined", err)
	}
	if _, err := refPath(testOpFile, "", refIndex(commonFile)); !errors.Is(err, errUnindexed) ||
		err.Error() != `the ref target is not in this commit's index: "`+testOpFile+`"` {
		t.Errorf("refPath from an admitted file the index lacks error = %v, want errUnindexed", err)
	}
	// A path inside the admitted trees that the index lacks is missing from the commit, not outside the trees.
	for _, file := range []string{"missing.json", "../../../../../../common-types/resource-management/v6/types.json"} {
		if _, err := refPath(testOpFile, file, ix); !errors.Is(err, errUnindexed) || errors.Is(err, errRefConfined) {
			t.Errorf("refPath(%q) error = %v, want errUnindexed", file, err)
		}
	}
	for _, file := range []string{
		"/specification/common-types/resource-management/v5/types.json",
		"https://example.com/types.json",
		`..\..\common\v1\common.json`,
		"../../common/v1/common.json?x=1",
		"a.json?",
		"//h/x.json",
		"../../../../../../../../../etc/passwd",
		"../../../../../../other/svc/resource-manager/Microsoft.X/stable/2024-07-01/a.json",
		"../../../../../../dev/common-types/resource-management/v1/types.json",
		"%zz",
	} {
		if _, err := refPath(testOpFile, file, ix); !errors.Is(err, errRefConfined) ||
			!strings.HasPrefix(err.Error(), "the ref target is outside the spec trees the index admits: ") {
			t.Errorf("refPath(%q) error = %v, want errRefConfined", file, err)
		}
	}
}

// within reports whether the bytes of s lie inside the bytes of of.
func within(s, of string) bool {
	p, lo := uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(unsafe.Pointer(unsafe.StringData(of)))

	return p >= lo && p < lo+uintptr(len(of))
}

func TestRefPointer(t *testing.T) {
	t.Parallel()
	for ptr, want := range map[string][2]string{
		"/parameters/ApiVersionParameter": {"parameters", "ApiVersionParameter"},
		"/definitions/A~1B~0C":            {"definitions", "A/B~C"},
		"/definitions/X~01":               {"definitions", "X~1"},
	} {
		kind, name, err := refPointer(ptr)
		if err != nil || kind != want[0] || name != want[1] {
			t.Errorf("refPointer(%q) = %q, %q, %v, want %v", ptr, kind, name, err, want)
		}
		if within(kind, ptr) || within(name, ptr) {
			t.Errorf("refPointer(%q) returned a string inside the pointer, which would keep the $ref alive", ptr)
		}
	}
	for _, ptr := range []string{"parameters/X", "/parameters", "/parameters/", "/responses/X", "/definitions/X/properties/y"} {
		if _, _, err := refPointer(ptr); !errors.Is(err, errRefKind) {
			t.Errorf("refPointer(%q) error = %v, want errRefKind", ptr, err)
		}
	}
}

func TestRefResolverResolve(t *testing.T) {
	t.Parallel()
	files := newSpecFakeFiles(map[string]string{
		commonFile: `{"parameters":{"ApiVersionParameter":{"name":"api-version","in":"query"}}}`,
		localFile:  `not json`,
	})
	ix := refIndex(testOpFile, commonFile, localFile)
	r := newRefResolver(files, ix, NewBudget(1<<20))
	own, err := decodeSwagger([]byte(`{"parameters":{"Local":{"name":"l","in":"query"}},"definitions":{"D":{}}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if adderr := r.add(testOpFile, own); adderr != nil {
		t.Fatalf("add: %v", adderr)
	}
	ctx := context.Background()
	if key, readerr := r.target(ctx, testOpFile, "#/parameters/Local"); readerr != nil || key.file != testOpFile ||
		!strings.Contains(string(r.raw(key)), `"l"`) {
		t.Fatalf("local ref = %+v, %v", key, readerr)
	}
	if _, readerr := r.target(ctx, testOpFile, "#/definitions/D"); readerr != nil {
		t.Fatalf("local definition: %v", readerr)
	}
	remote := "../../../../../../common-types/resource-management/v5/types.json#/parameters/ApiVersionParameter"
	for range 2 {
		if key, readerr := r.target(ctx, testOpFile, remote); readerr != nil || key.file != commonFile {
			t.Fatalf("remote ref = %+v, %v", key, readerr)
		}
	}
	if n := files.count(commonFile); n != 1 {
		t.Fatalf("common file read %d times, want 1 (decoded once, then reused)", n)
	}
	cases := map[string]error{
		"#/parameters/Missing":                      errRefMissing,
		"#/responses/X":                             errRefKind,
		"types.json":                                errRefKind,
		"https://e/x.json#/parameters/X":            errRefConfined,
		"../../common/v1/common.json#/parameters/X": ErrSpecsRejected,
	}
	for ref, want := range cases {
		if _, readerr := r.target(ctx, testOpFile, ref); !errors.Is(readerr, want) {
			t.Errorf("resolve(%q) error = %v, want %v", ref, readerr, want)
		}
	}
}

func TestRefResolverLoadLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	paths := []string{testOpFile}
	bodies := map[string]string{}
	for i := range 17 {
		p := fmt.Sprintf("specification/test/resource-manager/Microsoft.Test/Test/common/v1/f%02d.json", i)
		paths = append(paths, p)
		bodies[p] = `{"parameters":{"X":{"name":"x","in":"query"}}}`
	}
	ix := refIndex(paths...)
	r := newRefResolver(newSpecFakeFiles(bodies), ix, NewBudget(1<<20))
	// Files 1..16 should resolve successfully.
	for i := range 16 {
		if _, err := r.target(
			ctx,
			testOpFile,
			fmt.Sprintf("../../common/v1/f%02d.json#/parameters/X", i),
		); err != nil {
			t.Fatalf("file %d error = %v, want nil", i+1, err)
		}
	}
	// File 17 should fail with errRefLimit.
	if _, err := r.target(
		ctx,
		testOpFile,
		fmt.Sprintf("../../common/v1/f%02d.json#/parameters/X", 16),
	); !errors.Is(
		err,
		errRefLimit,
	) {
		t.Fatalf("file 17 error = %v, want errRefLimit", err)
	}

	sentinel := errors.New("load failed")
	files := newSpecFakeFiles(map[string]string{commonFile: `{}`})
	files.fail[commonFile] = sentinel
	r = newRefResolver(files, refIndex(testOpFile, commonFile), NewBudget(1<<20))
	ref := "../../../../../../common-types/resource-management/v5/types.json#/parameters/X"
	if _, err := r.target(ctx, testOpFile, ref); !errors.Is(err, sentinel) || refGap(err) {
		t.Fatalf("load error = %v (gap %v), want the sentinel, not a gap", err, refGap(err))
	}
	r = newRefResolver(newSpecFakeFiles(map[string]string{commonFile: `{"parameters":{}}`}),
		refIndex(testOpFile, commonFile), NewBudget(4))
	if _, err := r.target(ctx, testOpFile, ref); !errors.Is(err, ErrBudgetExceeded) || refGap(err) {
		t.Fatalf("budget error = %v (gap %v), want ErrBudgetExceeded, not a gap", err, refGap(err))
	}
}

func TestRefResolverParam(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	own, err := decodeSwagger([]byte(`{"parameters":{
		"A":{"$ref":"#/parameters/B"},"B":{"name":"b","in":"query","required":true},
		"Loop":{"$ref":"#/parameters/Loop"},"NoName":{"in":"query"},"Bad":[]}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r.add(testOpFile, own); adderr != nil {
		t.Fatalf("add: %v", adderr)
	}
	p, from, shared, err := r.param(ctx, testOpFile, json.RawMessage(`{"name":"i","in":"path"}`))
	if err != nil || p.Name != "i" || shared || from != testOpFile {
		t.Fatalf("inline param = %+v, %q, %v, %v", p, from, shared, err)
	}
	p, _, shared, err = r.param(ctx, testOpFile, json.RawMessage(`{"$ref":"#/parameters/A"}`))
	if err != nil || p.Name != "b" || !p.Required || !shared {
		t.Fatalf("chained param = %+v, %v, %v", p, shared, err)
	}
	cases := map[string]error{
		`{"$ref":"#/parameters/Loop"}`:   errRefLimit,
		`{"$ref":"#/parameters/NoName"}`: errBadParam,
		`{"$ref":"#/parameters/Bad"}`:    errBadParam,
		`[]`:                             errBadParam,
		`{"$ref":"#/parameters/None"}`:   errRefMissing,
	}
	for raw, want := range cases {
		if _, _, _, paramerr := r.param(
			ctx,
			testOpFile,
			json.RawMessage(raw),
		); !errors.Is(paramerr, want) ||
			!refGap(paramerr) {
			t.Errorf("param(%s) error = %v, want %v as a gap", raw, paramerr, want)
		}
	}
}

// TestRefResolverParamDepth pins the maxRefDepth bound: a chain of 8 links resolves, 9 is refused with errRefLimit.
func TestRefResolverParamDepth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Build a chain: P0 -> P1 -> ... -> P6 -> Leaf (8 resolves: depth 0-7).
	var params strings.Builder
	params.WriteString(`{"parameters":{"Leaf":{"name":"leaf","in":"query"}`)
	for i := 6; i >= 0; i-- {
		next := "Leaf"
		if i < 6 {
			next = fmt.Sprintf("P%d", i+1)
		}
		fmt.Fprintf(&params, `,"P%d":{"$ref":"#/parameters/%s"}`, i, next)
	}
	params.WriteString(`}}`)
	own, err := decodeSwagger([]byte(params.String()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r.add(testOpFile, own); adderr != nil {
		t.Fatalf("add: %v", adderr)
	}
	// Chain of 8 resolves should succeed (depth 0..7, then return at depth 8).
	if p, _, _, perr := r.param(ctx, testOpFile, json.RawMessage(`{"$ref":"#/parameters/P0"}`)); perr != nil ||
		p.Name != "leaf" {
		t.Fatalf("param chain depth 8: %+v, %v", p, perr)
	}
	// Chain of 9 resolves should fail (hits depth == 8 with another $ref to follow).
	var params9 strings.Builder
	params9.WriteString(`{"parameters":{"Leaf":{"name":"leaf","in":"query"},"P7":{"$ref":"#/parameters/P0"}`)
	for i := 6; i >= 0; i-- {
		next := "Leaf"
		if i < 6 {
			next = fmt.Sprintf("P%d", i+1)
		}
		fmt.Fprintf(&params9, `,"P%d":{"$ref":"#/parameters/%s"}`, i, next)
	}
	params9.WriteString(`}}`)
	own9, err := decodeSwagger([]byte(params9.String()))
	if err != nil {
		t.Fatalf("decode depth+1: %v", err)
	}
	r9 := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r9.add(testOpFile, own9); adderr != nil {
		t.Fatalf("add depth+1: %v", adderr)
	}
	if _, _, _, perr := r9.param(
		ctx,
		testOpFile,
		json.RawMessage(`{"$ref":"#/parameters/P7"}`),
	); !errors.Is(
		perr,
		errRefLimit,
	) {
		t.Fatalf("param chain depth 9 error = %v, want errRefLimit", perr)
	}
}

// TestRefResolverSchemaDepth pins the maxRefDepth bound for schema resolution: 8 links resolve, 9 refused.
func TestRefResolverSchemaDepth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Build a chain: D0 -> D1 -> ... -> D6 -> Leaf (8 resolves: depth 0-7).
	var defs strings.Builder
	defs.WriteString(`{"definitions":{"Leaf":{"type":"string"}`)
	for i := 6; i >= 0; i-- {
		next := "Leaf"
		if i < 6 {
			next = fmt.Sprintf("D%d", i+1)
		}
		fmt.Fprintf(&defs, `,"D%d":{"$ref":"#/definitions/%s"}`, i, next)
	}
	defs.WriteString(`}}`)
	own, err := decodeSwagger([]byte(defs.String()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r.add(testOpFile, own); adderr != nil {
		t.Fatalf("add: %v", adderr)
	}
	// Chain of 8 resolves should succeed (depth 0..7, then return at depth 8).
	if s, _, serr := r.schema(ctx, testOpFile, json.RawMessage(`{"$ref":"#/definitions/D0"}`)); serr != nil ||
		s.Type != "string" {
		t.Fatalf("schema chain depth 8: %+v, %v", s, serr)
	}
	// Chain of 9 resolves should fail (hits depth == 8 with another $ref to follow).
	var defs9 strings.Builder
	defs9.WriteString(`{"definitions":{"Leaf":{"type":"string"},"D7":{"$ref":"#/definitions/D0"}`)
	for i := 6; i >= 0; i-- {
		next := "Leaf"
		if i < 6 {
			next = fmt.Sprintf("D%d", i+1)
		}
		fmt.Fprintf(&defs9, `,"D%d":{"$ref":"#/definitions/%s"}`, i, next)
	}
	defs9.WriteString(`}}`)
	own9, err := decodeSwagger([]byte(defs9.String()))
	if err != nil {
		t.Fatalf("decode depth+1: %v", err)
	}
	r9 := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r9.add(testOpFile, own9); adderr != nil {
		t.Fatalf("add depth+1: %v", adderr)
	}
	if _, _, serr := r9.schema(
		ctx,
		testOpFile,
		json.RawMessage(`{"$ref":"#/definitions/D7"}`),
	); !errors.Is(
		serr,
		errRefLimit,
	) {
		t.Fatalf("schema chain depth 9 error = %v, want errRefLimit", serr)
	}
}

// TestRefResolverAdd pins that registered operation files count toward the per-lookup file bound: 16 files succeed,
// 17th fails with errRefLimit, and registering a file again is free.
func TestRefResolverAdd(t *testing.T) {
	t.Parallel()
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	for i := range 16 {
		if err := r.add(fmt.Sprintf("specification/x/f%02d.json", i), &swaggerDoc{}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := r.add("specification/x/f00.json", &swaggerDoc{}); err != nil {
		t.Fatalf("re-adding a registered file: %v", err)
	}
	if err := r.add("specification/x/one-more.json", &swaggerDoc{}); !errors.Is(err, errRefLimit) {
		t.Fatalf("one file past the bound: err = %v, want errRefLimit", err)
	}
}

func TestRefResolverBody(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	own, err := decodeSwagger([]byte(`{"definitions":{
		"VM":{"allOf":[{"$ref":"#/definitions/Tracked"}],"required":["properties"],
			"properties":{"properties":{"$ref":"#/definitions/Props"},"id":{"type":"string","readOnly":true}}},
		"Tracked":{"required":["location"],"properties":{"location":{"type":"string","description":"where"},
			"id":{"type":"integer"}}},
		"Props":{"type":"object"},
		"Str":{"type":"string"},
		"BadAllOf":{"allOf":[{"$ref":"#/definitions/None"}]},
		"BadProp":{"properties":{"p":{"$ref":"#/definitions/None"}}},
		"Inner":{"type":"string","description":"inner"},
		"LoopDef":{"$ref":"#/definitions/LoopDef"},
		"Sib":{"required":["etag","name"],"properties":{
			"etag":{"$ref":"#/definitions/Str","readOnly":true,"description":"outer"},
			"name":{"$ref":"#/definitions/Inner"}}}}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if adderr := r.add(testOpFile, own); adderr != nil {
		t.Fatalf("add: %v", adderr)
	}
	shape, err := r.body(ctx, testOpFile, json.RawMessage(`{"$ref":"#/definitions/VM"}`))
	if err != nil || !shape.object {
		t.Fatalf("body(VM) = %+v, %v", shape, err)
	}
	if got := fmt.Sprint(shape.required); got != "map[location:true properties:true]" {
		t.Errorf("required = %s, want location and properties", got)
	}
	if shape.props["id"].Type != "string" || !shape.props["id"].ReadOnly {
		t.Errorf("id = %+v, want the child's own read-only string", shape.props["id"])
	}
	if shape.props["properties"].Type != "object" || shape.props["location"].Description != "where" {
		t.Errorf("props = %+v", shape.props)
	}
	// Keys beside a $ref survive it: readOnly makes the required etag read-only, so the body never sends it, and
	// the outer description wins; a $ref with no siblings keeps its target's description.
	sib, err := r.body(ctx, testOpFile, json.RawMessage(`{"$ref":"#/definitions/Sib"}`))
	if err != nil || !sib.props["etag"].ReadOnly || sib.props["etag"].Description != "outer" ||
		sib.props["name"].ReadOnly || sib.props["name"].Description != "inner" {
		t.Errorf("sibling keys = %+v, %v", sib.props, err)
	}
	if strShape, strErr := r.body(
		ctx,
		testOpFile,
		json.RawMessage(`{"$ref":"#/definitions/Str"}`),
	); strErr != nil ||
		strShape.object {
		t.Errorf("body(Str) = %+v, %v, want a non-object", strShape, strErr)
	}
	for _, raw := range []string{
		`{"$ref":"#/definitions/BadAllOf"}`, `{"$ref":"#/definitions/BadProp"}`, ``, `{"$ref":"#/definitions/None"}`,
		`{"$ref":"#/definitions/LoopDef"}`, // a schema chain past maxRefDepth
	} {
		if _, bodyerr := r.body(ctx, testOpFile, json.RawMessage(raw)); !refGap(bodyerr) {
			t.Errorf("body(%s) error = %v, want a gap error", raw, bodyerr)
		}
	}
}

func TestRefGap(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errRefConfined, errUnindexed, errRefLimit, errRefKind, errRefMissing, errBadParam, errBadSchema,
	} {
		if !refGap(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("refGap(%v) = false", err)
		}
	}
	for _, err := range []error{ErrBudgetExceeded, context.DeadlineExceeded, ErrSpecsRejected, errors.New("x")} {
		if refGap(err) {
			t.Errorf("refGap(%v) = true", err)
		}
	}
}

// repeatedParents is a definitions table whose body schema VM lists the definition Big n times as an allOf parent.
// Big holds one inline property of size bytes, so each time a part is merged that property is decoded again.
func repeatedParents(n, size int) string {
	parents := strings.TrimSuffix(strings.Repeat(`{"$ref":"#/definitions/Big"},`, n), ",")

	return `{"VM":{"allOf":[` + parents + `]},"Big":{"required":["p"],"properties":{"p":{` +
		`"type":"string","description":"` + strings.Repeat("d", size) + `"}}}}`
}

// TestRefResolverBody_RepeatedParentsAreBounded pins the decode bound on the large-property fixture: one body merges
// the repeated parent Big once, decoding its 64 KiB property once, and bodies that keep reaching Big through one
// resolver, as the bodies of one lookup's candidates do, stop at maxDecodedSchema with a gap error.
func TestRefResolverBody_RepeatedParentsAreBounded(t *testing.T) {
	t.Parallel()
	defs := repeatedParents(1000, 64<<10)
	own, err := decodeSwagger([]byte(`{"definitions":` + defs + `}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if r.maxDecoded != 16<<20 {
		t.Fatalf("maxDecoded = %d, want 16 MiB", r.maxDecoded)
	}
	if err = r.add(testOpFile, own); err != nil {
		t.Fatalf("add: %v", err)
	}
	vm := json.RawMessage(`{"$ref":"#/definitions/VM"}`)
	// At most twice the document's bytes, plus the charges for the keys of VM and Big.
	keys := 2 * int64(len(testOpFile)+len("Big")+mergedNameCost)
	if _, err = r.body(t.Context(), testOpFile, vm); err != nil || r.decoded > 2*int64(len(defs))+keys {
		t.Fatalf("one body of 1000 repeated parents: err = %v after %d bytes, want Big merged once", err, r.decoded)
	}
	for range 1000 {
		if _, err = r.body(t.Context(), testOpFile, vm); err != nil {
			break
		}
	}
	if !errors.Is(err, errRefLimit) || !refGap(err) {
		t.Fatalf("bodies reaching Big again: err = %v, want errRefLimit as a gap", err)
	}
	if r.decoded > r.maxDecoded+(64<<10)+64 {
		t.Errorf("decoded %d bytes, want the stop within one object of %d", r.decoded, r.maxDecoded)
	}
}

// requiredNames is a JSON array of n distinct required names, r0 to r<n-1>.
func requiredNames(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf(`"r%d"`, i)
	}

	return "[" + strings.Join(names, ",") + "]"
}

// TestRefResolverBody_MergesEachNameOnce pins the merge's deduplication with parts that each lead to a parent of 2,000
// required names: 2,000 parts naming a repeated parent, 2,000 distinct ref chains that end at one parent, 4,000 parts
// alternating between two distinct parents that share their names, and 2,000 parts naming a parent with properties
// too. Each body holds 2,000 names once and stays far inside the decode bound, where merging every part's names would
// charge about a gigabyte.
func TestRefResolverBody_MergesEachNameOnce(t *testing.T) {
	t.Parallel()
	const n = 2000
	names := requiredNames(n)
	repeat := func(part string) string { return strings.TrimSuffix(strings.Repeat(part+",", n), ",") }
	chains, links := make([]string, n), make([]string, n)
	for i := range n {
		chains[i] = fmt.Sprintf(`{"$ref":"#/definitions/Q%d"}`, i)
		links[i] = fmt.Sprintf(`"Q%d":{"$ref":"#/definitions/P"}`, i)
	}
	props := strings.NewReplacer("[", "{", "]", "}", `",`, `":{"type":"string"},`).Replace(names)
	props = strings.TrimSuffix(props, `"}`) + `":{"type":"string"}}`
	for name, tc := range map[string]struct {
		defs  string
		props int
	}{
		"repeated parent": {defs: `"VM":{"allOf":[` + repeat(`{"$ref":"#/definitions/P"}`) + `]},` +
			`"P":{"required":` + names + `}`},
		"ref chains to one parent": {defs: `"VM":{"allOf":[` + strings.Join(chains, ",") + `]},` +
			strings.Join(links, ",") + `,"P":{"required":` + names + `}`},
		"parents sharing names": {defs: `"VM":{"allOf":[` + repeat(`{"$ref":"#/definitions/P"},`+
			`{"$ref":"#/definitions/P2"}`) + `]},"P":{"required":` + names + `},"P2":{"required":` + names + `}`},
		"properties and required": {defs: `"VM":{"allOf":[` + repeat(`{"$ref":"#/definitions/P"}`) + `]},` +
			`"P":{"required":` + names + `,"properties":` + props + `}`, props: n},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doc := `{"definitions":{` + tc.defs + `}}`
			own, err := decodeSwagger([]byte(doc))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
			if err = r.add(testOpFile, own); err != nil {
				t.Fatalf("add: %v", err)
			}
			shape, err := r.body(t.Context(), testOpFile, json.RawMessage(`{"$ref":"#/definitions/VM"}`))
			if err != nil || len(shape.required) != n || len(shape.props) != tc.props {
				t.Fatalf("body: %d required, %d properties, %v; want %d and %d", len(shape.required),
					len(shape.props), err, n, tc.props)
			}
			// Two merges of the parent's names, one decode of the document's objects and one of each part.
			if limit := int64(2*n*(len(`"r1999",`)+mergedNameCost) + 3*len(doc)); r.decoded > limit {
				t.Errorf("charged %d bytes, want at most %d", r.decoded, limit)
			}
		})
	}
}

// TestRefResolverBody_ChargesEveryMerge pins the merge charge: a memoized parent is decoded once, but every body that
// merges it is charged for its required and property names, so bodies that keep reaching it through one resolver stop
// at the decode bound.
func TestRefResolverBody_ChargesEveryMerge(t *testing.T) {
	t.Parallel()
	props := make([]string, 100)
	for i := range props {
		props[i] = fmt.Sprintf(`"r%d":{"type":"string"}`, i)
	}
	for name, parent := range map[string]string{
		"required names": `{"type":"object","required":` + requiredNames(100) + `}`,
		"property names": `{"type":"object","properties":{` + strings.Join(props, ",") + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			own, err := decodeSwagger([]byte(`{"definitions":{"P":` + parent + `}}`))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
			r.maxDecoded = 1 << 20
			if err = r.add(testOpFile, own); err != nil {
				t.Fatalf("add: %v", err)
			}
			merges := 0
			for range 100 {
				if _, err = r.body(t.Context(), testOpFile, json.RawMessage(`{"$ref":"#/definitions/P"}`)); err != nil {
					break
				}
				merges++
			}
			if !errors.Is(err, errRefLimit) || merges > int(r.maxDecoded)/(100*mergedNameCost) {
				t.Fatalf("%d bodies merged before %v; want errRefLimit within %d", merges, err,
					int(r.maxDecoded)/(100*mergedNameCost))
			}
		})
	}
}

// distinctEmptyParents is a definitions document whose body schema VM lists n distinct empty definitions as allOf
// parents, each through a ref that names the document's own file by its base name, so refPath builds the file's whole
// path afresh for every parent.
func distinctEmptyParents(n int) string {
	parts, defs := make([]string, n), make([]string, n)
	for i := range n {
		parts[i] = fmt.Sprintf(`{"$ref":"types.json#/definitions/P%d"}`, i)
		defs[i] = fmt.Sprintf(`"P%d":{}`, i)
	}

	return `{"definitions":{"VM":{"allOf":[` + strings.Join(parts, ",") + `]},` + strings.Join(defs, ",") + `}}`
}

// TestRefResolverBody_ChargesEachMergedTarget pins the charge for each merged ref target's key and the one copy of a
// path every key shares: distinct empty parents in a file whose path is about 1,000 bytes charge the path and the name
// of each, every key the resolver keeps holds the path it was given, and enough of them stop at the decode bound.
func TestRefResolverBody_ChargesEachMergedTarget(t *testing.T) {
	t.Parallel()
	long := "specification/common-types/resource-management/" + strings.Repeat("d", 940) + "/v5/types.json"
	body := func(n int) (*refResolver, bodyShape, error) {
		own, err := decodeSwagger([]byte(distinctEmptyParents(n)))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		r := newRefResolver(newSpecFakeFiles(nil), refIndex(long), NewBudget(1<<20))
		if err = r.add(long, own); err != nil {
			t.Fatalf("add: %v", err)
		}
		shape, err := r.body(t.Context(), long, json.RawMessage(`{"$ref":"#/definitions/VM"}`))

		return r, shape, err
	}
	small, shape, err := body(1000)
	if err != nil || len(shape.merged) != 1001 {
		t.Fatalf("1,000 parents: %d keys merged, %v; want VM and every parent", len(shape.merged), err)
	}
	for k := range shape.merged {
		if unsafe.StringData(k.file) != unsafe.StringData(long) {
			t.Fatalf("merged key %s/%s holds its own copy of the path", k.table, k.name)
		}
	}
	for k := range small.schemas {
		if unsafe.StringData(k.file) != unsafe.StringData(long) {
			t.Fatalf("memoized key %s/%s holds its own copy of the path", k.table, k.name)
		}
	}
	large, _, err := body(2000)
	if err != nil {
		t.Fatalf("2,000 parents: %v", err)
	}
	if grew, least := large.decoded-small.decoded, int64(1000*(len(long)+mergedNameCost)); grew < least {
		t.Errorf("1,000 more parents charged %d bytes, want at least %d", grew, least)
	}
	over, _, err := body(20000)
	if !errors.Is(err, errRefLimit) || !refGap(err) {
		t.Fatalf("20,000 parents: err = %v, want errRefLimit as a gap", err)
	}
	if over.decoded > over.maxDecoded+int64(len(long)+len("P19999")+mergedNameCost) {
		t.Errorf("charged %d bytes, want the stop within one key of %d", over.decoded, over.maxDecoded)
	}
}

// TestRefResolverBody_ChecksTheContextBeforeAMerge pins the context check before a part's merge: a done context stops
// a body whose only part has required names and no property, where no other check runs.
func TestRefResolverBody_ChecksTheContextBeforeAMerge(t *testing.T) {
	t.Parallel()
	own, err := decodeSwagger([]byte(`{"definitions":{"P":{"type":"object","required":["a"]}}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	if err = r.add(testOpFile, own); err != nil {
		t.Fatalf("add: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = r.body(ctx, testOpFile, json.RawMessage(`{"$ref":"#/definitions/P"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("body with a done context: err = %v, want context.Canceled", err)
	}
}

// TestRefResolverBody_DecodesEachTargetOnce pins the memo: a definition named a hundred times is decoded once, so a
// bound that fits one copy and the refs, but not a hundred copies, is never reached.
func TestRefResolverBody_DecodesEachTargetOnce(t *testing.T) {
	t.Parallel()
	parents := strings.TrimSuffix(strings.Repeat(`{"$ref":"#/definitions/Base"},`, 100), ",")
	own, err := decodeSwagger([]byte(`{"definitions":{"VM":{"allOf":[` + parents + `]},"Base":{"type":"object",` +
		`"description":"` + strings.Repeat("d", 4<<10) + `"}}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	r.maxDecoded = 64 << 10
	if err = r.add(testOpFile, own); err != nil {
		t.Fatalf("add: %v", err)
	}
	if shape, berr := r.body(t.Context(), testOpFile, json.RawMessage(`{"$ref":"#/definitions/VM"}`)); berr != nil ||
		!shape.object {
		t.Fatalf("body = %+v, %v; want an object within the bound", shape, berr)
	}
}

// cancelOnFile cancels a context when the file at path is read, then serves it.
type cancelOnFile struct {
	*specFakeFiles

	path   string
	cancel context.CancelFunc
}

func (c *cancelOnFile) File(ctx context.Context, sha string, f IndexFile) ([]byte, error) {
	if f.Path == c.path {
		c.cancel()
	}

	return c.specFakeFiles.File(ctx, sha, f)
}

// TestRefResolverBody_StopsWhenCancelled pins both context checks of the merge: the context is cancelled while the
// common file loads, for an allOf parent with no properties and for a property, and the parts and properties that
// follow, all in the operation's own file, are never merged.
func TestRefResolverBody_StopsWhenCancelled(t *testing.T) {
	t.Parallel()
	common := "../../../../../../common-types/resource-management/v5/types.json#/definitions/"
	defs := `{"definitions":{
		"Parents":{"allOf":[{"$ref":"` + common + `Base"},{"$ref":"#/definitions/Local"}]},
		"Props":{"properties":{"a":{"$ref":"` + common + `Base"},"b":{"type":"string"}}},
		"Local":{"type":"object"}}}`
	for name, def := range map[string]string{"allOf parent": "Parents", "property": "Props"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			own, err := decodeSwagger([]byte(defs))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			src := &cancelOnFile{
				specFakeFiles: newSpecFakeFiles(map[string]string{commonFile: `{"definitions":{"Base":{}}}`}),
				path:          commonFile, cancel: cancel,
			}
			r := newRefResolver(src, refIndex(testOpFile, commonFile), NewBudget(1<<20))
			if err = r.add(testOpFile, own); err != nil {
				t.Fatalf("add: %v", err)
			}
			_, err = r.body(ctx, testOpFile, json.RawMessage(`{"$ref":"#/definitions/`+def+`"}`))
			if !errors.Is(err, context.Canceled) || refGap(err) {
				t.Fatalf("err = %v, want context.Canceled, not a gap", err)
			}
		})
	}
}
