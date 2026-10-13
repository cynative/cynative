package k8s

import (
	"net/url"
	"testing"
)

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()

	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}

	return v
}

func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		path   string
		query  string
		want   RequestInfo
	}{
		{
			name:   "list pods (nameless GET)",
			method: "GET",
			path:   "/api/v1/namespaces/default/pods",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Namespace: "default", Resource: "pods",
				Path: "/api/v1/namespaces/default/pods",
			},
		},
		{
			name:   "get named pod",
			method: "GET",
			path:   "/api/v1/namespaces/default/pods/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web",
				Path: "/api/v1/namespaces/default/pods/web",
			},
		},
		{
			name:   "watch via query",
			method: "GET",
			path:   "/api/v1/pods",
			query:  "watch=true",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "watch", APIVersion: "v1",
				Resource: "pods", Path: "/api/v1/pods",
			},
		},
		{
			name:   "watch=false stays list",
			method: "GET",
			path:   "/api/v1/pods",
			query:  "watch=false",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Resource: "pods", Path: "/api/v1/pods",
			},
		},
		{
			name:   "create pod (POST)",
			method: "POST",
			path:   "/api/v1/namespaces/default/pods",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "create", APIVersion: "v1",
				Namespace: "default", Resource: "pods",
				Path: "/api/v1/namespaces/default/pods",
			},
		},
		{
			name:   "deletecollection (nameless DELETE)",
			method: "DELETE",
			path:   "/api/v1/namespaces/default/pods",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "deletecollection", APIVersion: "v1",
				Namespace: "default", Resource: "pods",
				Path: "/api/v1/namespaces/default/pods",
			},
		},
		{
			name:   "subresource pods/log",
			method: "GET",
			path:   "/api/v1/namespaces/default/pods/web/log",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web", Subresource: "log",
				Path: "/api/v1/namespaces/default/pods/web/log",
			},
		},
		{
			name:   "subresource pods/exec",
			method: "POST",
			path:   "/api/v1/namespaces/default/pods/web/exec",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "create", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web", Subresource: "exec",
				Path: "/api/v1/namespaces/default/pods/web/exec",
			},
		},
		{
			name:   "named resource in api group",
			method: "GET",
			path:   "/apis/apps/v1/namespaces/default/deployments/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIGroup: "apps", APIVersion: "v1",
				Namespace: "default", Resource: "deployments", Name: "web",
				Path: "/apis/apps/v1/namespaces/default/deployments/web",
			},
		},
		{
			name:   "cluster-scoped list nodes",
			method: "GET",
			path:   "/api/v1/nodes",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Resource: "nodes", Path: "/api/v1/nodes",
			},
		},
		{
			name:   "non-resource version",
			method: "GET",
			path:   "/version",
			want:   RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/version"},
		},
		{
			name:   "non-resource discovery root /apis",
			method: "GET",
			path:   "/apis",
			want:   RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/apis"},
		},
		{
			name:   "nodes/proxy subresource",
			method: "GET",
			path:   "/api/v1/nodes/n1/proxy/logs",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Resource: "nodes", Name: "n1", Subresource: "proxy",
				Path: "/api/v1/nodes/n1/proxy/logs",
			},
		},
		// Additional cases for branch coverage.
		{
			name:   "empty path (root)",
			method: "GET",
			path:   "/",
			want:   RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/"},
		},
		{
			name:   "apis group without version (short /apis/batch)",
			method: "GET",
			path:   "/apis/batch",
			want:   RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/apis/batch"},
		},
		{
			// /apis/<group>/<version> has exactly 3 segments: passes the first guard
			// (len >= 3) but fails the apis-branch guard (len < 4), falling back to
			// a non-resource URL — covers the minAPIsSegments early return.
			name:   "apis group+version only (no resource segment)",
			method: "GET",
			path:   "/apis/batch/v1",
			want:   RequestInfo{IsResourceRequest: false, Verb: "get", Path: "/apis/batch/v1"},
		},
		{
			name:   "PATCH becomes patch",
			method: "PATCH",
			path:   "/api/v1/namespaces/default/pods/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "patch", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web",
				Path: "/api/v1/namespaces/default/pods/web",
			},
		},
		{
			name:   "HEAD becomes get",
			method: "HEAD",
			path:   "/api/v1/namespaces/default/pods/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web",
				Path: "/api/v1/namespaces/default/pods/web",
			},
		},
		{
			name:   "PUT becomes update",
			method: "PUT",
			path:   "/api/v1/namespaces/default/pods/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "update", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web",
				Path: "/api/v1/namespaces/default/pods/web",
			},
		},
		{
			name:   "unknown method passes through",
			method: "OPTIONS",
			path:   "/api/v1/namespaces/default/pods/web",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "options", APIVersion: "v1",
				Namespace: "default", Resource: "pods", Name: "web",
				Path: "/api/v1/namespaces/default/pods/web",
			},
		},
		{
			name:   "list namespaces resource (bare /api/v1/namespaces)",
			method: "GET",
			path:   "/api/v1/namespaces",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Resource: "namespaces",
				Path:     "/api/v1/namespaces",
			},
		},
		{
			name:   "get named namespace (/api/v1/namespaces/kube-system)",
			method: "GET",
			path:   "/api/v1/namespaces/kube-system",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Resource: "namespaces", Name: "kube-system",
				Path: "/api/v1/namespaces/kube-system",
			},
		},
		{
			// kube-apiserver's namespaceSubresources: status under namespaces/<name>
			// is a subresource of the namespace, not a namespaced resource (#381).
			name:   "get namespace status subresource",
			method: "GET",
			path:   "/api/v1/namespaces/default/status",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Resource: "namespaces", Name: "default", Subresource: "status",
				Path: "/api/v1/namespaces/default/status",
			},
		},
		{
			name:   "update namespace finalize subresource",
			method: "PUT",
			path:   "/api/v1/namespaces/default/finalize",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "update", APIVersion: "v1",
				Resource: "namespaces", Name: "default", Subresource: "finalize",
				Path: "/api/v1/namespaces/default/finalize",
			},
		},
		{
			// Segments past the subresource are not interpreted, as upstream.
			name:   "namespace status with trailing segments",
			method: "GET",
			path:   "/api/v1/namespaces/default/status/extra",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIVersion: "v1",
				Resource: "namespaces", Name: "default", Subresource: "status",
				Path: "/api/v1/namespaces/default/status/extra",
			},
		},
		{
			// Upstream applies the rule in every API group, not only the core one.
			name:   "namespace status under a named group",
			method: "GET",
			path:   "/apis/example.io/v1/namespaces/default/status",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "get", APIGroup: "example.io", APIVersion: "v1",
				Resource: "namespaces", Name: "default", Subresource: "status",
				Path: "/apis/example.io/v1/namespaces/default/status",
			},
		},
		{
			// Only status and finalize are namespace subresources; a namespace
			// named status still scopes the resource that follows it.
			name:   "namespace named status scopes its resources",
			method: "GET",
			path:   "/api/v1/namespaces/status/pods",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Namespace: "status", Resource: "pods",
				Path: "/api/v1/namespaces/status/pods",
			},
		},
		{
			name:   "watch=1 is truthy",
			method: "GET",
			path:   "/api/v1/pods",
			query:  "watch=1",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "watch", APIVersion: "v1",
				Resource: "pods", Path: "/api/v1/pods",
			},
		},
		{
			// watch=0 must NOT become a watch (spec: only empty/absent, "0", and
			// "false" are non-watch values).
			name:   "watch=0 stays list",
			method: "GET",
			path:   "/api/v1/pods",
			query:  "watch=0",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Resource: "pods", Path: "/api/v1/pods",
			},
		},
		{
			// watch=False (capital F) is accepted by strconv.ParseBool as false, so
			// it must remain a list — validates ParseBool case-insensitive handling.
			name:   "watch=False stays list",
			method: "GET",
			path:   "/api/v1/pods",
			query:  "watch=False",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "list", APIVersion: "v1",
				Resource: "pods", Path: "/api/v1/pods",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(tc.method, tc.path, mustQuery(t, tc.query))
			if got != tc.want {
				t.Fatalf("Classify(%q,%q)\n got: %+v\nwant: %+v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// TestIsWatchNilQuery verifies the nil-query guard inside isWatch.
func TestIsWatchNilQuery(t *testing.T) {
	t.Parallel()

	// The table loop in TestClassify always passes a non-nil url.Values from
	// mustQuery, so this nil path is only reachable via a direct call to the
	// unexported isWatch function, which must return false.
	if isWatch(nil) {
		t.Fatal("isWatch(nil) must return false.")
	}
}

// TestClassifyProxyVerbInPath exercises the early-set proxy/watch path verb
// that fires when the verb appears as the first resource segment after the
// version (e.g. /api/v1/proxy/...) rather than as a subresource. This reaches
// the applyVerb early-return (ri.Verb != "") and, with nothing after the verb,
// the consumeResource empty-parts early return.
func TestClassifyProxyVerbInPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		path   string
		want   RequestInfo
	}{
		{
			name:   "proxy as first segment after version",
			method: "GET",
			path:   "/api/v1/proxy/nodes/n1",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "proxy", APIVersion: "v1",
				Resource: "nodes", Name: "n1",
				Path: "/api/v1/proxy/nodes/n1",
			},
		},
		{
			name:   "watch as first segment after version",
			method: "GET",
			path:   "/api/v1/watch/pods",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "watch", APIVersion: "v1",
				Resource: "pods",
				Path:     "/api/v1/watch/pods",
			},
		},
		{
			name:   "watch with no resource after it",
			method: "GET",
			path:   "/api/v1/watch",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "watch", APIVersion: "v1",
				Path: "/api/v1/watch",
			},
		},
		{
			// 3+ post-proxy segments: proxy verb is already set before consumeResource,
			// so the ri.Verb != verbProxy guard suppresses the subresource field even
			// though the tail has enough segments to fill it.
			name:   "proxy-prefix verb suppresses subresource in tail",
			method: "GET",
			path:   "/api/v1/proxy/nodes/n1/logs",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "proxy", APIVersion: "v1",
				Resource: "nodes", Name: "n1",
				Path: "/api/v1/proxy/nodes/n1/logs",
			},
		},
		{
			// The namespace-subresource rule still names the namespace under the
			// proxy verb, which then drops the subresource as it does elsewhere.
			name:   "proxy-prefix verb on namespace status",
			method: "GET",
			path:   "/api/v1/proxy/namespaces/default/status",
			want: RequestInfo{
				IsResourceRequest: true, Verb: "proxy", APIVersion: "v1",
				Resource: "namespaces", Name: "default",
				Path: "/api/v1/proxy/namespaces/default/status",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(tc.method, tc.path, nil)
			if got != tc.want {
				t.Fatalf("Classify(%q,%q)\n got: %+v\nwant: %+v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}
