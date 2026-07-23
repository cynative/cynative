package k8s

import (
	"errors"
	"net/url"
	"testing"
)

// FuzzClassify pins panic-freedom of the kube-apiserver RequestInfo classifier
// over arbitrary method/path pairs (#181). Malformed input must never panic;
// non-API paths stay non-resource.
func FuzzClassify(f *testing.F) {
	f.Add("GET", "/api/v1/namespaces/default/pods")
	f.Add("GET", "/version")
	f.Add("GET", "/api/v1/pods")
	f.Add("DELETE", "/api/v1/namespaces/default/pods")
	f.Add("POST", "/apis/apps/v1/namespaces/ns/deployments")
	f.Add("", "")
	f.Add("GET", "not-a-path")

	f.Fuzz(func(t *testing.T, method, path string) {
		ri := Classify(method, path, nil)
		if path != "" && !ri.IsResourceRequest && ri.Path != path {
			t.Fatalf("non-resource Path = %q, want %q", ri.Path, path)
		}
		_ = Classify(method, path, url.Values{"watch": []string{"true"}})
	})
}

// FuzzParseClusterRoleRules pins fail-closed parsing: malformed input never
// authorizes (returns ErrUnclassifiable), and never panics (#181).
func FuzzParseClusterRoleRules(f *testing.F) {
	f.Add([]byte(sampleClusterRole))
	f.Add([]byte(`{not json`))
	f.Add([]byte(`{"kind":"Status","code":403}`))
	f.Add([]byte(`{"kind":"ClusterRole","rules":[]}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"kind":"ClusterRole","rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		rules, err := ParseClusterRoleRules(data)
		if err == nil {
			if len(rules) == 0 {
				t.Fatal("success with zero rules; parser must reject empty rules")
			}

			return
		}
		if !errors.Is(err, ErrUnclassifiable) {
			t.Fatalf("err = %v, want ErrUnclassifiable", err)
		}
		if rules != nil {
			t.Fatalf("rules = %v on error, want nil", rules)
		}
	})
}
