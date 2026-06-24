package k8s

import (
	"errors"
	"testing"
)

func TestAuthorizeResource(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
	})

	if err := Authorize(RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "pods"}, vp); err != nil {
		t.Fatalf("list pods should be allowed, got %v", err)
	}

	err := Authorize(RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "secrets"}, vp)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("list secrets should be ErrForbidden, got %v", err)
	}
}

func TestAuthorizeNonResource(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})

	allowed := []string{"/version", "/healthz", "/openapi/v2", "/api", "/apis", "/apis/apps/v1", "/livez"}
	for _, p := range allowed {
		if err := Authorize(RequestInfo{IsResourceRequest: false, Verb: "get", Path: p}, vp); err != nil {
			t.Fatalf("GET %s should be allowed, got %v", p, err)
		}
	}

	denied := []RequestInfo{
		{IsResourceRequest: false, Verb: "post", Path: "/version"},
		{IsResourceRequest: false, Verb: "get", Path: "/metrics"},
		{IsResourceRequest: false, Verb: "get", Path: "/logs/kubelet.log"},
		{IsResourceRequest: false, Verb: "delete", Path: "/api"},
		{IsResourceRequest: false, Verb: "put", Path: "/api"},
	}
	for _, ri := range denied {
		if err := Authorize(ri, vp); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s %s should be ErrForbidden, got %v", ri.Verb, ri.Path, err)
		}
	}
}

func TestAuthorizeNonResourceHead(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})

	if err := Authorize(RequestInfo{IsResourceRequest: false, Verb: "head", Path: "/version"}, vp); err != nil {
		t.Fatalf("HEAD /version should be allowed, got %v", err)
	}
}

func TestAuthorizeResourceWithSubresource(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	})

	err := Authorize(RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		Resource:          "pods",
		Subresource:       "log",
		APIGroup:          "",
	}, vp)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("get pods/log should be ErrForbidden (not in policy), got %v", err)
	}
}

func TestAuthorizeRootPath(t *testing.T) {
	t.Parallel()

	vp := BuildViewPolicy([]PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})

	if err := Authorize(RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/"}, vp); err != nil {
		t.Fatalf("GET / should be allowed, got %v", err)
	}
}
