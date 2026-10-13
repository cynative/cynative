package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

func loadGoldenPolicy(t *testing.T, name string) *ViewPolicy {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	rules, err := ParseClusterRoleRules(data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	return BuildViewPolicy(rules)
}

func TestGoldenViewRolesEnforceReadOnly(t *testing.T) {
	t.Parallel()

	denied := []RequestInfo{
		{IsResourceRequest: true, Verb: "list", Resource: "secrets"},
		{IsResourceRequest: true, Verb: "get", Resource: "secrets", Name: "sa-token"},
		{IsResourceRequest: true, Verb: "create", Resource: "pods", Subresource: "exec", Name: "web"},
		{IsResourceRequest: true, Verb: "create", Resource: "pods", Subresource: "attach", Name: "web"},
		{IsResourceRequest: true, Verb: "get", Resource: "pods", Subresource: "portforward", Name: "web"},
		{IsResourceRequest: true, Verb: "get", Resource: "nodes", Subresource: "proxy", Name: "n1"},
		{IsResourceRequest: true, Verb: "get", Resource: "services", Subresource: "proxy", Name: "s1"},
		{IsResourceRequest: true, Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: "sa"},
		{IsResourceRequest: true, Verb: "create", Resource: "pods"},
		{IsResourceRequest: true, Verb: "delete", Resource: "deployments", APIGroup: "apps", Name: "web"},
	}

	allowed := []RequestInfo{
		{IsResourceRequest: true, Verb: "list", Resource: "pods"},
		{IsResourceRequest: true, Verb: "get", Resource: "pods", Subresource: "log", Name: "web"},
		{IsResourceRequest: true, Verb: "list", Resource: "configmaps"},
		{IsResourceRequest: true, Verb: "list", Resource: "deployments", APIGroup: "apps"},
		{IsResourceRequest: true, Verb: "list", Resource: "namespaces"},
	}

	for _, name := range []string{"eks-view.json", "gke-view.json", "aks-view.json"} {
		vp := loadGoldenPolicy(t, name)
		for _, ri := range denied {
			if vp.Allows(ri) {
				t.Errorf("%s: %s %s/%s must be DENIED", name, ri.Verb, ri.Resource, ri.Subresource)
			}
		}
		for _, ri := range allowed {
			if !vp.Allows(ri) {
				t.Errorf("%s: %s %s/%s must be ALLOWED", name, ri.Verb, ri.Resource, ri.Subresource)
			}
		}
	}
}

// TestGoldenViewRolesNamespaceSubresources classifies the namespace
// subresource paths and checks them against the built-in view roles, which
// grant namespaces/status and nothing that allows a finalize write (#381).
func TestGoldenViewRolesNamespaceSubresources(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method, path string
		want         bool
	}{
		{method: "GET", path: "/api/v1/namespaces/default/status", want: true},
		{method: "PUT", path: "/api/v1/namespaces/default/finalize", want: false},
	}

	for _, name := range []string{"eks-view.json", "gke-view.json", "aks-view.json"} {
		vp := loadGoldenPolicy(t, name)
		for _, tc := range cases {
			if got := vp.Allows(Classify(tc.method, tc.path, nil)); got != tc.want {
				t.Errorf("%s: %s %s allowed = %v, want %v", name, tc.method, tc.path, got, tc.want)
			}
		}
	}
}
