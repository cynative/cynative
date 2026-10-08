package k8s

import (
	"slices"
	"strings"
	"testing"
)

// FuzzPrepare checks that the pre-pass never panics and admits only an operation whose path passes the path form
// and stays inside its group-version, with an id in the lookup grammar. The seeds reach every branch: each cap,
// each unrenderable reason, two invalid parameters before a valid path declaration, a duplicate, an excluded id, each refusal and a component reference.
func FuzzPrepare(f *testing.F) {
	for _, s := range []string{
		opDoc("/apis/apps/v1/namespaces/{namespace}", `"parameters":[`+nsParam+`],"get":{"operationId":"a"}`),
		opDoc("/apis/apps/v1/{x}", `"get":{"operationId":"a"}`),
		opDoc("/apis/apps/v1/..", `"get":{"operationId":"a"},"put":{"operationId":"a"},"post":{"operationId":"b-c"}`),
		opDoc("/apis/apps/v1", `"get":{"operationId":"a","parameters":[{"name":"q","in":"cookie"}]}`),
		opDoc("/apis/apps/v1/{namespace}", `"parameters":[{"name":"q","in":"cookie"},{"name":"1q","in":"query"},`+
			nsParam+`],"get":{"operationId":"a"}`),
		opDoc("/apis/apps/v1", `"get":{"operationId":"a","parameters":[{"name":"9","in":"query"}]}`),
		opDoc("/apis/apps/v1", `"get":{"operationId":"a","parameters":[{"name":"q","in":"query","schema":{"type":"x"}}]}`),
		opDoc("/apis/apps/v1", `"get":{"operationId":"a","parameters":[{"$ref":"#/components/parameters/p"}]}`),
		`{"paths":{"/apis/apps/v1":{"get":{"operationId":"a","parameters":[{"$ref":"#/components/parameters/p"}]}}},` +
			`"components":{"parameters":{"p":{"name":"p","in":"query"}}}}`,
		opDoc("/apis/apps/v1", `"get":{"operationId":"a","parameters":[`+strings.Repeat(`{},`, 64)+`{}]}`),
		`{"paths":[]}`, `{"paths":{}}`, `{"paths":{"/a":{"get":{}}}}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		p, err := Prepare(t.Context(), []byte(doc), appsKey)
		if err != nil {
			return
		}
		for id, e := range p.Index {
			if !ValidOperationID(id) {
				t.Fatalf("indexed id %q is outside the grammar", id)
			}
			if e.Class != ClassAdmitted {
				continue
			}
			r := e.Routes[0]
			_, ok := pathLabels(r.Path, appsKey)
			segs := strings.Split(r.Path, "/")
			if !ok || !strings.HasPrefix(r.Path, "/"+appsKey) || strings.ContainsAny(r.Path, "%?#;") ||
				slices.Contains(segs, ".") || slices.Contains(segs, "..") {
				t.Fatalf("admitted %q at %q", id, r.Path)
			}
		}
	})
}
