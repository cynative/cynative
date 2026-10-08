package k8s

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const appsKey = "apis/apps/v1"

// opDoc returns an apps/v1 document with one path item holding body, a path item's JSON members.
func opDoc(path, item string) string {
	return `{"paths":{"` + path + `":{` + item + `}}}`
}

const nsParam = `{"name":"namespace","in":"path","required":true,"schema":{"type":"string"}}`

func prepare(t *testing.T, doc string) *Prepared {
	t.Helper()
	p, err := Prepare(t.Context(), []byte(doc), appsKey)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	return p
}

func TestPrepare_Admitted(t *testing.T) {
	t.Parallel()
	p := prepare(t, `{"paths":{"/apis/apps/v1/namespaces/{namespace}/deployments":{"parameters":[`+nsParam+`],
	"get":{"operationId":"listAppsV1NamespacedDeployment","description":"list <b>them</b>",
		"x-kubernetes-group-version-kind":{"group":"apps","kind":"Deployment","version":"v1"},
		"parameters":[{"$ref":"#/components/parameters/limit"}],
		"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/DeploymentList"}},
			"application/yaml":{}}}}},
	"post":{"operationId":"createAppsV1NamespacedDeployment","requestBody":{"required":true,"content":{
		"application/json":{},"*/*":{}}},"responses":{"200":{"content":{"application/json":{"schema":{"type":"object"}}}}}}},
	"/apis/apps/v1/":{"get":{"operationId":"getAppsV1APIResources"}},
	"/apis/apps/v1":{"GET":{"operationId":"getAppsV1Root"}}},
	"components":{"parameters":{"limit":{"name":"limit","in":"query","schema":{"type":"integer"}}}}}`)
	for id, route := range map[string]Route{
		"listAppsV1NamespacedDeployment":   {"GET", "/apis/apps/v1/namespaces/{namespace}/deployments", true},
		"createAppsV1NamespacedDeployment": {"POST", "/apis/apps/v1/namespaces/{namespace}/deployments", true},
		"getAppsV1APIResources":            {"GET", "/apis/apps/v1/", true},
		"getAppsV1Root":                    {"GET", "/apis/apps/v1", true},
	} {
		e := p.Index[id]
		if e.Class != ClassAdmitted || len(e.Routes) != 1 || e.Routes[0] != route ||
			!p.Admitted(route.Method, route.Path, id) {
			t.Errorf("%s: %+v", id, e)
		}
	}
	if p.Admitted("PUT", "/apis/apps/v1", "getAppsV1Root") || p.Admitted("GET", "/x", "getAppsV1Root") ||
		p.Admitted("GET", "/apis/apps/v1", "missing") {
		t.Error("Admitted matched another route")
	}
	want := Extras{
		Description: "list <b>them</b>", Kind: "Deployment", ResponseRef: "#/components/schemas/DeploymentList",
	}
	if got := p.Extras["listAppsV1NamespacedDeployment"]; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("list extras = %+v", got)
	}
	if got := p.Extras["createAppsV1NamespacedDeployment"]; !slices.Equal(got.RequestTypes,
		[]string{"*/*", "application/json"}) || got.ResponseType != "object" {
		t.Errorf("create extras = %+v", got)
	}
	if p.Excluded != 0 || len(p.Index) != 4 {
		t.Errorf("excluded %d, index %d", p.Excluded, len(p.Index))
	}
}

func TestPrepare_Caps(t *testing.T) {
	t.Parallel()
	many := func(n int, s string) string { return strings.TrimSuffix(strings.Repeat(s+",", n), ",") }
	q := `{"name":"q","in":"query"}`
	var ops strings.Builder
	for i := range MaxOperations + 1 {
		if i > 0 {
			ops.WriteByte(',')
		}
		fmt.Fprintf(&ops, `"/apis/apps/v1/p%d":{"get":{"operationId":"o%d"}}`, i, i)
	}
	var refs strings.Builder
	for i := range MaxParamRefs/MaxOperationParams + 1 {
		if i > 0 {
			refs.WriteByte(',')
		}
		fmt.Fprintf(&refs, `"/apis/apps/v1/p%d":{"get":{"operationId":"o%d","parameters":[%s]}}`, i, i,
			many(MaxOperationParams, q))
	}
	cases := []struct {
		name, doc, want string
	}{
		{"operations", `{"paths":{` + ops.String() + `}}`, "the document has more than 4000 operations"},
		{
			"parameters per operation",
			opDoc("/apis/apps/v1/x", `"parameters":[`+many(33, q)+`],"get":{"operationId":"x","parameters":[`+
				many(32, q)+`]}`),
			"the document has an operation with more than 64 parameters",
		},
		{
			"parameter references",
			`{"paths":{` + refs.String() + `}}`,
			"the document has more than 25000 parameter references",
		},
	}
	for _, tc := range cases {
		_, err := Prepare(t.Context(), []byte(tc.doc), appsKey)
		if !errors.Is(err, ErrDocument) || err.Error() != tc.want {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	at := opDoc("/apis/apps/v1/x", `"parameters":[`+many(32, q)+`],"get":{"operationId":"x","parameters":[`+
		many(32, q)+`]}`)
	if _, err := Prepare(t.Context(), []byte(at), appsKey); err != nil {
		t.Errorf("64 parameters: %v", err)
	}
}

func TestPrepare_PathForm(t *testing.T) {
	t.Parallel()
	ok := []string{
		"/apis/apps/v1", "/apis/apps/v1/", "/apis/apps/v1/a", "/apis/apps/v1/namespaces/{namespace}/x.y-z_1",
		"/apis/apps/v1/watch/namespaces/{namespace}",
	}
	bad := []string{
		"/apis/apps/v1/..", "/apis/apps/v1/.", "/apis/apps/v1/%2e%2e", "/apis/apps/v1/a%2Fb", "/apis/apps/v1/a?b",
		"/apis/apps/v1/a#b", "/apis/apps/v1/a;b", "/apis/apps/v1//a", "/apis/apps/v1/a/", "/apis/apps/v1/x{namespace}",
		"/apis/apps/v1/{namespace}x", "/apis/apps/v1/{name{space}}", "/apis/apps/v1/{}", "/apis/apps/v1x",
		"/apis/apps/v2/a", "/api/v1/a", "apis/apps/v1", "/apis/apps/v1/-a", "/apis/apps/v1/a-",
		"/apis/apps/v1/" + strings.Repeat("a", maxPathBytes),
	}
	for _, path := range append(ok, bad...) {
		p := prepare(t, opDoc(path, `"parameters":[`+nsParam+`],"get":{"operationId":"op"}`))
		want := ClassAdmitted
		if slices.Contains(bad, path) {
			want = ClassUnrenderable
		}
		if e := p.Index["op"]; e.Class != want || e.Routes[0].PathOK != (want == ClassAdmitted) ||
			(want == ClassUnrenderable && e.Reason != reasonPath) {
			t.Errorf("%q: %+v, want class %d", path, e, want)
		}
	}
	at := "/apis/apps/v1/" + strings.Repeat("a", maxPathBytes-len("/apis/apps/v1/"))
	if p := prepare(t, opDoc(at, `"get":{"operationId":"op"}`)); p.Index["op"].Class != ClassAdmitted {
		t.Errorf("a path of %d bytes: %+v", len(at), p.Index["op"])
	}
}

func TestPrepare_Parameters(t *testing.T) {
	t.Parallel()
	const path = "/apis/apps/v1/namespaces/{namespace}/x"
	cases := []struct {
		name, params, want string
	}{
		{"undeclared label", ``, reasonLabel},
		{"label declared in the query", `{"name":"namespace","in":"query"}`, reasonLabel},
		{"bad name", nsParam + `,{"name":"1q","in":"query"}`, reasonName},
		{"long name", nsParam + `,{"name":"` + strings.Repeat("q", 101) + `","in":"query"}`, reasonName},
		{"non-string name", nsParam + `,{"name":5,"in":"query"}`, reasonName},
		{"cookie", nsParam + `,{"name":"c","in":"cookie"}`, reasonLocation},
		{"other location", nsParam + `,{"name":"c","in":"body"}`, reasonLocation},
		{"unknown type", nsParam + `,{"name":"q","in":"query","schema":{"type":"file"}}`, reasonType},
		{"unknown type with spaces", nsParam + `,{"name":"q","in":"query","schema":{ "type" :  "file" }}`, reasonType},
		{"an object type is no type", nsParam + `,{"name":"q","in":"query","schema":{"type":{"x":[1]}}}`, ""},
		{
			"long type", nsParam + `,{"name":"q","in":"query","schema":{"type":"` + strings.Repeat("x", 9000) + `"}}`,
			reasonType,
		},
		{"dangling ref", nsParam + `,{"$ref":"#/components/parameters/missing"}`, reasonRef},
		{"non-component ref", nsParam + `,{"$ref":"#/components/schemas/q"}`, reasonRef},
		{"chained ref", nsParam + `,{"$ref":"#/components/parameters/chain"}`, reasonRef},
		{"bad component", nsParam + `,{"$ref":"#/components/parameters/cookie"}`, reasonLocation},
		{"good component", `{"$ref":"#/components/parameters/ns"}`, ""},
		{"non-string type is unknown, not refused", nsParam + `,{"name":"q","in":"query","schema":{"type":5}}`, ""},
		{"schema not an object", nsParam + `,{"name":"q","in":"query","schema":"string"}`, ""},
		{"header", nsParam + `,{"name":"X-Thing","in":"header","schema":{"type":"string"}}`, ""},
	}
	for _, tc := range cases {
		for _, level := range []string{"path", "operation"} {
			item := `"parameters":[` + tc.params + `],"get":{"operationId":"op"}`
			if level == "operation" {
				item = `"get":{"operationId":"op","parameters":[` + tc.params + `]}`
			}
			doc := `{"paths":{"` + path + `":{` + item + `}},"components":{"parameters":{
			"ns":` + nsParam + `,"cookie":{"name":"c","in":"cookie"},"chain":{"$ref":"#/components/parameters/ns"}}}}`
			e := prepare(t, doc).Index["op"]
			want := ClassUnrenderable
			if tc.want == "" {
				want = ClassAdmitted
			}
			if e.Class != want || e.Reason != tc.want {
				t.Errorf("%s at the %s level: %+v, want reason %q", tc.name, level, e, tc.want)
			}
		}
	}
}

func TestPrepare_IndexClasses(t *testing.T) {
	t.Parallel()
	p := prepare(t, `{"paths":{
	"/apis/apps/v1/a":{"get":{"operationId":"dup"},"put":{"operationId":"dup"},"post":{},"delete":{"operationId":5},
		"patch":{"operationId":"not-in-grammar"},"head":{"operationId":"x"}},
	"/apis/apps/v1/b/..":{"get":{"operationId":"dup"},"options":{"operationId":"bad"}}}}`)
	dup := p.Index["dup"]
	want := []Route{
		{http.MethodGet, "/apis/apps/v1/a", true},
		{http.MethodGet, "/apis/apps/v1/b/..", false},
		{http.MethodPut, "/apis/apps/v1/a", true},
	}
	if dup.Class != ClassDuplicate || !slices.Equal(dup.Routes, want) {
		t.Errorf("dup = %+v", dup)
	}
	if e := p.Index["bad"]; e.Class != ClassUnrenderable || e.Reason != reasonPath {
		t.Errorf("bad = %+v", e)
	}
	if _, ok := p.Extras["dup"]; ok {
		t.Error("a duplicate id kept extras")
	}
	if p.Index["x"].Class != ClassAdmitted || p.Excluded != 3 || len(p.Index) != 3 {
		t.Errorf("index %+v excluded %d", p.Index, p.Excluded)
	}
}

func TestPrepare_Refusals(t *testing.T) {
	t.Parallel()
	for doc, want := range map[string]string{
		`{"paths":[]}`:                       "the document does not decode into the OpenAPI shape this tool reads",
		`{"paths":{"/a":{"get":5}}}`:         "the document does not decode into the OpenAPI shape this tool reads",
		`{"paths":{"/a":{"parameters":{}}}}`: "the document does not decode into the OpenAPI shape this tool reads",
		`{"paths":{"/a":{"get":{"parameters":[{"$ref":5}]}}}}`: "the document does not decode into the OpenAPI shape " +
			"this tool reads",
		`{"paths":{}}`:                                "the document lists no operation",
		`{"paths":{"/a":{}}}`:                         "the document lists no operation",
		`{"paths":{"/a":{"get":{}}}}`:                 "the document lists no operation id this tool can look up",
		`{"paths":{"/a":{"get":{"operationId":""}}}}`: "the document lists no operation id this tool can look up",
	} {
		if _, err := Prepare(t.Context(), []byte(doc), appsKey); !errors.Is(err, ErrDocument) || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", doc, err, want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Prepare(ctx, []byte(opDoc("/apis/apps/v1", `"get":{"operationId":"a"}`)), appsKey); !errors.Is(
		err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
}

func TestValidOperationID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"a", "listAppsV1NamespacedDeployment", "a_1", "A" + strings.Repeat("b", 199)} {
		if !ValidOperationID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range []string{"", "1a", "_a", "a-b", "a.b", "a b", "A" + strings.Repeat("b", 200), "é"} {
		if ValidOperationID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}

// TestPrepare_RoutesAreSafeForOutputOnlyWhenTheWholeFormHolds pins PathOK, which decides whether a duplicate's
// route may be shown as an ambiguity choice: a label must name a declared path parameter and pass the name grammar,
// for duplicates as well as for admitted operations.
func TestPrepare_RoutesAreSafeForOutputOnlyWhenTheWholeFormHolds(t *testing.T) {
	t.Parallel()
	p := prepare(t, `{"paths":{
	"/apis/apps/v1/ok":{"get":{"operationId":"sibling"}},
	"/apis/apps/v1/{missing}":{"get":{"operationId":"dup"},"put":{"operationId":"dup"}},
	"/apis/apps/v1/{bad?x}":{"parameters":[{"name":"bad?x","in":"path"}],"get":{"operationId":"odd"},
		"put":{"operationId":"odd"}},
	"/apis/apps/v1/ns/{namespace}":{"parameters":[`+nsParam+`],"get":{"operationId":"good"},"put":{"operationId":"good"}},
	"/apis/apps/v1/q/{namespace}":{"get":{"operationId":"queryOnly","parameters":[{"name":"namespace","in":"query"}]}}}}`)
	for id, want := range map[string]bool{"dup": false, "odd": false, "good": true} {
		e := p.Index[id]
		if e.Class != ClassDuplicate || len(e.Routes) != 2 || e.Routes[0].PathOK != want || e.Routes[1].PathOK != want {
			t.Errorf("%s: %+v, want PathOK %v", id, e, want)
		}
	}
	if e := p.Index["queryOnly"]; e.Class != ClassUnrenderable || e.Reason != reasonLabel || e.Routes[0].PathOK {
		t.Errorf("queryOnly: %+v", e)
	}
	if _, ok := pathLabels("/apis/apps/v1/{bad?x}", appsKey); ok {
		t.Error("a label outside the name grammar passed the path form")
	}
}

// TestPrepare_PathOKIgnoresParameterOrder declares the path's label beside an unrelated invalid parameter, in both
// orders. The invalid parameter makes the operation unrenderable either way, but it must not hide the declaration,
// so the route stays safe to show as an ambiguity choice.
func TestPrepare_PathOKIgnoresParameterOrder(t *testing.T) {
	t.Parallel()
	cookie := `{"name":"q","in":"cookie"}`
	for name, params := range map[string]string{
		"cookie first": cookie + "," + nsParam,
		"cookie last":  nsParam + "," + cookie,
	} {
		p := prepare(t, `{"paths":{"/apis/apps/v1/{namespace}":{"parameters":[`+params+`],`+
			`"get":{"operationId":"dup"},"put":{"operationId":"dup"}},`+
			`"/apis/apps/v1/x/{namespace}":{"parameters":[`+params+`],"get":{"operationId":"one"}}}}`)
		if e := p.Index["dup"]; e.Class != ClassDuplicate || !e.Routes[0].PathOK || !e.Routes[1].PathOK {
			t.Errorf("%s: dup = %+v, want both routes PathOK", name, e)
		}
		if e := p.Index["one"]; e.Class != ClassUnrenderable || e.Reason != reasonLocation || !e.Routes[0].PathOK {
			t.Errorf("%s: one = %+v, want the location reason and PathOK", name, e)
		}
	}
}

// TestPrepare_TheFirstInvalidParameterNamesTheReason keeps the first validation error when several parameters are
// invalid, in parameter order.
func TestPrepare_TheFirstInvalidParameterNamesTheReason(t *testing.T) {
	t.Parallel()
	cookie, badName := `{"name":"q","in":"cookie"}`, `{"name":"1q","in":"query"}`
	for params, want := range map[string]string{cookie + "," + badName: reasonLocation, badName + "," + cookie: reasonName} {
		p := prepare(t, opDoc("/apis/apps/v1/a", `"parameters":[`+params+`],"get":{"operationId":"one"}`))
		if e := p.Index["one"]; e.Class != ClassUnrenderable || e.Reason != want {
			t.Errorf("%s: %+v, want %q", params, e, want)
		}
	}
}
