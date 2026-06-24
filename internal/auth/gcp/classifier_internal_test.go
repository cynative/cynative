package gcp

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func req(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()

	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	return &http.Request{Method: method, URL: u, Header: http.Header{}}
}

func computeIndex() MethodIndex {
	return MethodIndex{
		"compute.instances.list": {
			ID:          "compute.instances.list",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances",
			ServicePath: "compute/v1/",
		},
		"compute.instances.insert": {
			ID:          "compute.instances.insert",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/zones/{zone}/instances",
			ServicePath: "compute/v1/",
		},
		"compute.instances.get": {
			ID:          "compute.instances.get",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}",
			ServicePath: "compute/v1/",
		},
		"compute.instances.delete": {
			ID:          "compute.instances.delete",
			HTTPMethod:  "DELETE",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}",
			ServicePath: "compute/v1/",
		},
		"compute.instances.start": {
			ID:          "compute.instances.start",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}/start",
			ServicePath: "compute/v1/",
		},
	}
}

// storageIndex returns a storage v1 index: no flatPath, so servicePath+path fallback is used.
func storageIndex() MethodIndex {
	return MethodIndex{
		"storage.buckets.list": {
			ID:          "storage.buckets.list",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b",
		},
		"storage.buckets.getIamPolicy": {
			ID:          "storage.buckets.getIamPolicy",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b/{bucket}/iam",
		},
		"storage.objects.insert": {
			ID:          "storage.objects.insert",
			HTTPMethod:  "POST",
			ServicePath: "upload/storage/v1/",
			Path:        "b/{bucket}/o",
		},
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		idx     MethodIndex
		req     *http.Request
		want    string
		wantErr bool
	}{
		{
			name: "list",
			idx:  computeIndex(),
			req:  req(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
			want: "compute.instances.list",
		},
		{
			name: "insert same template POST",
			idx:  computeIndex(),
			req:  req(t, "POST", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
			want: "compute.instances.insert",
		},
		{
			name: "get vs delete by method GET",
			idx:  computeIndex(),
			req:  req(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
			want: "compute.instances.get",
		},
		{
			name: "delete",
			idx:  computeIndex(),
			req:  req(t, "DELETE", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
			want: "compute.instances.delete",
		},
		{
			name: "literal verb start",
			idx:  computeIndex(),
			req:  req(t, "POST", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i/start"),
			want: "compute.instances.start",
		},
		{
			name: "storage list fallback",
			idx:  storageIndex(),
			req:  req(t, "GET", "https://storage.googleapis.com/storage/v1/b"),
			want: "storage.buckets.list",
		},
		{
			name: "media upload",
			idx:  storageIndex(),
			req:  req(t, "POST", "https://storage.googleapis.com/upload/storage/v1/b/mybucket/o"),
			want: "storage.objects.insert",
		},
		{
			name:    "zero match fails",
			idx:     computeIndex(),
			req:     req(t, "GET", "https://compute.googleapis.com/compute/v1/nope"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Classify(tc.idx, tc.req)
			if tc.wantErr {
				if !errors.Is(err, ErrClassifierUnknownOp) {
					t.Fatalf("Classify err = %v, want ErrClassifierUnknownOp", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Classify: %v", err)
			}

			if got != tc.want {
				t.Errorf("Classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyColonVerb(t *testing.T) {
	t.Parallel()

	idx := storageIndex()
	got, err := Classify(idx, req(t, "GET", "https://storage.googleapis.com/storage/v1/b/mybucket/iam"))
	if err != nil || got != "storage.buckets.getIamPolicy" {
		t.Fatalf("getIamPolicy classify = %q err=%v", got, err)
	}
}

func TestClassifyAmbiguousFailClosed(t *testing.T) {
	t.Parallel()

	// Two methods with the same HTTP method and template must return ErrClassifierUnknownOp.
	ambiguous := MethodIndex{
		"svc.foo.get": {ID: "svc.foo.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
		"svc.bar.get": {ID: "svc.bar.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
	}

	_, err := Classify(ambiguous, req(t, "GET", "https://example.googleapis.com/v1/projects/p/foo/f"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("ambiguous match must return ErrClassifierUnknownOp, got %v", err)
	}
}

// TestClassifyLiteralMismatch covers the branch where segment count matches but a
// literal template segment differs from the request (matchTemplate returns false
// via the segmentEqual path).
func TestClassifyLiteralMismatch(t *testing.T) {
	t.Parallel()

	// "compute/v2/projects/..." has the same segment count as the v1 templates but
	// the literal "v1" segment will not match "v2", so no survivor → fail closed.
	_, err := Classify(
		computeIndex(),
		req(t, "GET", "https://compute.googleapis.com/compute/v2/projects/p/zones/z/instances"),
	)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("literal mismatch must return ErrClassifierUnknownOp, got %v", err)
	}
}

// TestClassifyColonVerbCustom covers segmentEqual's colon branch:
//   - placeholder base matches any resource value when verbs agree
//   - mismatched colon-verbs fail closed (returns ErrClassifierUnknownOp)
//   - literal base in a colon-verb template matches the corresponding literal
func TestClassifyColonVerbCustom(t *testing.T) {
	t.Parallel()

	// Index with a placeholder-base colon-verb and a literal-base colon-verb.
	idx := MethodIndex{
		"svc.res.setIamPolicy": {
			ID:         "svc.res.setIamPolicy",
			HTTPMethod: "POST",
			FlatPath:   "v1/projects/{project}/resources/{resource}:setIamPolicy",
		},
		"svc.globalRes.testPermissions": {
			ID:         "svc.globalRes.testPermissions",
			HTTPMethod: "POST",
			FlatPath:   "v1/globalResources/myRes:testPermissions",
		},
	}

	// Placeholder-base colon-verb: verb matches, base is placeholder → match.
	got, err := Classify(idx, req(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:setIamPolicy"))
	if err != nil || got != "svc.res.setIamPolicy" {
		t.Fatalf("placeholder colon-verb: got %q err=%v", got, err)
	}

	// Mismatched colon-verb: request has :getIamPolicy but only :setIamPolicy exists → fail closed.
	_, err = Classify(idx, req(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:getIamPolicy"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("mismatched colon-verb must return ErrClassifierUnknownOp, got %v", err)
	}

	// Literal-base colon-verb: template literal "myRes" matches request literal exactly.
	got, err = Classify(idx, req(t, "POST", "https://example.googleapis.com/v1/globalResources/myRes:testPermissions"))
	if err != nil || got != "svc.globalRes.testPermissions" {
		t.Fatalf("literal colon-verb: got %q err=%v", got, err)
	}
}

// TestClassifyRealFlatPathShape pins Bug C: real Discovery flatPath is RELATIVE
// to servicePath (no version prefix); the classifier must prepend servicePath to
// match the real request path /compute/v1/projects/.../instances.
func TestClassifyRealFlatPathShape(t *testing.T) {
	t.Parallel()

	idx := MethodIndex{
		"compute.instances.list": {
			ID:          "compute.instances.list",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances", // real shape: no compute/v1/.
			ServicePath: "compute/v1/",
		},
	}
	got, err := Classify(idx, req(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"))
	if err != nil || got != "compute.instances.list" {
		t.Fatalf("real-shape classify: got=%q err=%v, want compute.instances.list", got, err)
	}
}

// TestClassifySplitSegmentsEmpty covers splitSegments("") returning nil so that
// an empty-path template (a zero-segment method) matches only an empty request path.
func TestClassifySplitSegmentsEmpty(t *testing.T) {
	t.Parallel()

	// A method whose FlatPath is "" (root-level REST call).
	idx := MethodIndex{
		"svc.root.get": {ID: "svc.root.get", HTTPMethod: "GET", FlatPath: ""},
	}
	// A request to the root "/" path (trimmed → "") must match.
	got, err := Classify(idx, req(t, "GET", "https://example.googleapis.com/"))
	if err != nil || got != "svc.root.get" {
		t.Fatalf("empty flatPath root match: got %q err=%v", got, err)
	}
	// A request with any non-empty path must not match.
	_, err = Classify(idx, req(t, "GET", "https://example.googleapis.com/v1/something"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("non-empty path vs empty template must fail closed, got %v", err)
	}
}

// TestClassifyBarePlaceholderRejectsCustomVerb pins that a bare {placeholder}
// template segment must NOT swallow a request segment carrying a custom verb:
// a POST to .../resources/r:customVerb must not classify as the sibling
// .../resources/{resource} write method.
func TestClassifyBarePlaceholderRejectsCustomVerb(t *testing.T) {
	t.Parallel()

	idx := MethodIndex{
		"svc.res.update": {
			ID:         "svc.res.update",
			HTTPMethod: "POST",
			FlatPath:   "v1/projects/{project}/resources/{resource}",
		},
	}

	_, err := Classify(idx, req(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:customVerb"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("custom-verb request must not match a bare-placeholder template, got %v", err)
	}
}
