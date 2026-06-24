package k8s

import "testing"

func viewLikePolicy() *ViewPolicy {
	return BuildViewPolicy([]PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "configmaps", "services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods/log", "pods/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
	})
}

func TestViewPolicyAllows(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ri   RequestInfo
		want bool
	}{
		{"list pods", RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "pods"}, true},
		{"get pods/log", RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods", Subresource: "log"}, true},
		{
			"get deployments (apps)",
			RequestInfo{IsResourceRequest: true, Verb: "get", APIGroup: "apps", Resource: "deployments"},
			true,
		},
		{"secrets denied (not listed)", RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "secrets"}, false},
		{
			"pods/exec denied (subresource not listed)",
			RequestInfo{IsResourceRequest: true, Verb: "create", Resource: "pods", Subresource: "exec"},
			false,
		},
		{
			"create pods denied (verb not listed)",
			RequestInfo{IsResourceRequest: true, Verb: "create", Resource: "pods"},
			false,
		},
		{
			"wrong group denied",
			RequestInfo{IsResourceRequest: true, Verb: "get", APIGroup: "batch", Resource: "deployments"},
			false,
		},
		{"non-resource denied here", RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/version"}, false},
	}

	vp := viewLikePolicy()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := vp.Allows(tc.ri); got != tc.want {
				t.Fatalf("Allows(%+v) = %v, want %v", tc.ri, got, tc.want)
			}
		})
	}
}

func TestViewPolicyResourceNames(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"kube-root-ca.crt"},
			Verbs:         []string{"get"},
		},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
	})

	cases := []struct {
		name string
		ri   RequestInfo
		want bool
	}{
		{
			"named rule allows the named object",
			RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "configmaps", Name: "kube-root-ca.crt"},
			true,
		},
		{
			"named rule denies a different name",
			RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "configmaps", Name: "other"},
			false,
		},
		{
			"named rule denies nameless list",
			RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "configmaps"},
			false,
		},
		{
			"named rule denies nameless get",
			RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "configmaps"},
			false,
		},
		{
			"unrestricted rule still allows any name",
			RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods", Name: "anything"},
			true,
		},
		{
			"unrestricted rule still allows nameless list",
			RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "pods"},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := vp.Allows(tc.ri); got != tc.want {
				t.Fatalf("Allows(%+v) = %v, want %v", tc.ri, got, tc.want)
			}
		})
	}
}

func TestViewPolicyWildcardAndNil(t *testing.T) {
	t.Parallel()

	star := BuildViewPolicy(
		[]PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}}},
	)
	if !star.Allows(RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "secrets"}) {
		t.Fatal("wildcard policy must allow get secrets")
	}

	var nilVP *ViewPolicy
	if nilVP.Allows(RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods"}) {
		t.Fatal("nil ViewPolicy must deny everything")
	}
}
