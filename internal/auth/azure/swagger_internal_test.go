package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
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
		"paths":{"/b":{"parameters":[],"x-ext":{},"put":{"operationId":"B_Put"},"get":{"operationId":"B_Get"}},
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
	for _, file := range []string{
		"/specification/common-types/resource-management/v5/types.json",
		"https://example.com/types.json",
		`..\..\common\v1\common.json`,
		"../../common/v1/common.json?x=1",
		"../../../../../../../../../etc/passwd",
		"missing.json",
		"%zz",
	} {
		if _, err := refPath(testOpFile, file, ix); !errors.Is(err, errRefConfined) {
			t.Errorf("refPath(%q) error = %v, want errRefConfined", file, err)
		}
	}
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
	if raw, from, readerr := r.resolve(ctx, testOpFile, "#/parameters/Local"); readerr != nil || from != testOpFile ||
		!strings.Contains(string(raw), `"l"`) {
		t.Fatalf("local ref = %s, %q, %v", raw, from, readerr)
	}
	if _, _, readerr := r.resolve(ctx, testOpFile, "#/definitions/D"); readerr != nil {
		t.Fatalf("local definition: %v", readerr)
	}
	remote := "../../../../../../common-types/resource-management/v5/types.json#/parameters/ApiVersionParameter"
	for range 2 {
		if _, from, readerr := r.resolve(ctx, testOpFile, remote); readerr != nil || from != commonFile {
			t.Fatalf("remote ref = %q, %v", from, readerr)
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
		if _, _, readerr := r.resolve(ctx, testOpFile, ref); !errors.Is(readerr, want) {
			t.Errorf("resolve(%q) error = %v, want %v", ref, readerr, want)
		}
	}
}

func TestRefResolverLoadLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	paths := []string{testOpFile}
	bodies := map[string]string{}
	for i := range maxRefFiles + 1 {
		p := fmt.Sprintf("specification/test/resource-manager/Microsoft.Test/Test/common/v1/f%02d.json", i)
		paths = append(paths, p)
		bodies[p] = `{"parameters":{"X":{"name":"x","in":"query"}}}`
	}
	ix := refIndex(paths...)
	r := newRefResolver(newSpecFakeFiles(bodies), ix, NewBudget(1<<20))
	var last error
	for i := range maxRefFiles + 1 {
		_, _, last = r.resolve(ctx, testOpFile, fmt.Sprintf("../../common/v1/f%02d.json#/parameters/X", i))
	}
	if !errors.Is(last, errRefLimit) {
		t.Fatalf("file %d error = %v, want errRefLimit", maxRefFiles+1, last)
	}

	sentinel := errors.New("load failed")
	files := newSpecFakeFiles(map[string]string{commonFile: `{}`})
	files.fail[commonFile] = sentinel
	r = newRefResolver(files, refIndex(testOpFile, commonFile), NewBudget(1<<20))
	ref := "../../../../../../common-types/resource-management/v5/types.json#/parameters/X"
	if _, _, err := r.resolve(ctx, testOpFile, ref); !errors.Is(err, sentinel) || refGap(err) {
		t.Fatalf("load error = %v (gap %v), want the sentinel, not a gap", err, refGap(err))
	}
	r = newRefResolver(newSpecFakeFiles(map[string]string{commonFile: `{"parameters":{}}`}),
		refIndex(testOpFile, commonFile), NewBudget(4))
	if _, _, err := r.resolve(ctx, testOpFile, ref); !errors.Is(err, ErrBudgetExceeded) || refGap(err) {
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

// TestRefResolverAdd pins that registered operation files count toward the per-lookup file bound, and that
// registering a file again is free.
func TestRefResolverAdd(t *testing.T) {
	t.Parallel()
	r := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	for i := range maxRefFiles {
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
	if got := fmt.Sprint(shape.required); got != "[properties location]" {
		t.Errorf("required = %s, want [properties location]", got)
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
	for _, err := range []error{errRefConfined, errRefLimit, errRefKind, errRefMissing, errBadParam, errBadSchema} {
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
