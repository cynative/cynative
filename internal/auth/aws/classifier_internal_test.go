package aws

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestMatchURITemplate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		template string
		path     string
		want     bool
	}{
		{"/", "/", true},
		{"/", "/anything", false},
		{"/{Bucket}", "/foo", true},
		{"/{Bucket}", "/", false},
		{"/{Bucket}", "/foo/bar", false},
		{"/{Bucket}/{Key+}", "/foo/bar/baz", true},
		{"/{Bucket}/{Key+}", "/foo", false},
		{"/{Bucket}/{Key+}", "/foo/", false},
		{"/foo", "/foo?query", true},
		{"/literal", "/literal", true},
		{"/literal", "/other", false},
	}
	for _, c := range cases {
		t.Run(c.template+"|"+c.path, func(t *testing.T) {
			t.Parallel()
			got := matchURITemplate(c.template, c.path)
			if got != c.want {
				t.Errorf("matchURITemplate(%q, %q) = %v, want %v", c.template, c.path, got, c.want)
			}
		})
	}
}

func TestClassifyREST_ListBucketsAtRoot(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	req := newClassifyReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	op, err := classifyREST(model, req, req.URL.Path)
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if op != "ListBuckets" {
		t.Errorf("op = %q, want ListBuckets", op)
	}
}

func TestClassifyREST_GetObject(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	req := newClassifyReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/my-bucket/path/to/key")
	op, err := classifyREST(model, req, req.URL.Path)
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if op != "GetObject" {
		t.Errorf("op = %q, want GetObject", op)
	}
}

func TestClassifyREST_QueryDisambiguator(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetBucketLifecycle": {HTTPMethod: "GET", URITemplate: "/{Bucket}?lifecycle"},
			"GetBucketPolicy":    {HTTPMethod: "GET", URITemplate: "/{Bucket}?policy"},
			"ListObjectsV2":      {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
		},
	}

	cases := []struct {
		url    string
		wantOp string
	}{
		{"https://s3.amazonaws.com/foo?lifecycle", "GetBucketLifecycle"},
		{"https://s3.amazonaws.com/foo?policy", "GetBucketPolicy"},
		{"https://s3.amazonaws.com/foo?list-type=2", "ListObjectsV2"},
		{"https://s3.amazonaws.com/foo", "ListObjectsV2"},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()
			req := newClassifyReq(t, http.MethodGet, c.url)
			op, err := classifyREST(model, req, req.URL.Path)
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestClassifyREST_NoMatchReturnsUnknown(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	req := newClassifyReq(t, http.MethodPost, "https://s3.us-east-1.amazonaws.com/foo")
	_, err := classifyREST(model, req, req.URL.Path)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyREST_HigherScoreCandidateWinsOverEarlierAlphabetical(t *testing.T) {
	t.Parallel()
	// Sorted by name: A then Z. A has lower score (no query flag); Z requires
	// "flag" which is present in the request, giving it score=1. The loop must
	// promote best=A → best=Z, exercising the inner reassignment branch.
	model := &ServiceModel{
		ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"AAA": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ZZZ": {HTTPMethod: "GET", URITemplate: "/{Bucket}?flag"},
		},
	}
	req := newClassifyReq(t, http.MethodGet, "https://x.amazonaws.com/foo?flag")
	op, err := classifyREST(model, req, req.URL.Path)
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if op != "ZZZ" {
		t.Errorf("op = %q, want ZZZ", op)
	}
}

func TestClassifyREST_SkipsOperationsWithoutHTTPMethod(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"NoHTTP":  {},
			"WithGet": {HTTPMethod: "GET", URITemplate: "/"},
		},
	}
	req := newClassifyReq(t, http.MethodGet, "https://x.amazonaws.com/")
	op, err := classifyREST(model, req, req.URL.Path)
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if op != "WithGet" {
		t.Errorf("op = %q, want WithGet", op)
	}
}

func TestSplitTemplateQuery_NoQuery(t *testing.T) {
	t.Parallel()
	path, flags := splitTemplateQuery("/foo/{Bar}")
	if path != "/foo/{Bar}" || flags != nil {
		t.Errorf("got (%q, %v), want (/foo/{Bar}, nil)", path, flags)
	}
}

func TestSplitTemplateQuery_EmptyQuery(t *testing.T) {
	t.Parallel()
	path, flags := splitTemplateQuery("/foo?")
	if path != "/foo" || flags != nil {
		t.Errorf("got (%q, %v), want (/foo, nil)", path, flags)
	}
}

func TestSplitTemplateQuery_WithEmptyFlagSegment(t *testing.T) {
	t.Parallel()
	// "?&policy" — leading & yields an empty flag name which must be skipped.
	_, flags := splitTemplateQuery("/foo?&policy")
	if len(flags) != 1 || flags[0] != "policy" {
		t.Errorf("flags = %v, want [policy]", flags)
	}
}

func TestSplitTemplateQuery_DropsXID(t *testing.T) {
	t.Parallel()
	// x-id is an AWS SDK-injected operation tag (e.g. S3's "/?x-id=ListBuckets"),
	// not a semantic discriminator; canonical/non-SDK requests omit it, so it must
	// not be treated as a required query flag. Real discriminators are kept.
	cases := []struct {
		uri      string
		wantPath string
		wantFlag []string
	}{
		{"/?x-id=ListBuckets", "/", nil},
		{"/{Bucket}/{Key+}?x-id=GetObject", "/{Bucket}/{Key+}", nil},
		{"/{Bucket}?acl&x-id=GetObjectAcl", "/{Bucket}", []string{"acl"}},
	}
	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			t.Parallel()
			path, flags := splitTemplateQuery(c.uri)
			if path != c.wantPath || !slices.Equal(flags, c.wantFlag) {
				t.Errorf("splitTemplateQuery(%q) = (%q, %v), want (%q, %v)",
					c.uri, path, flags, c.wantPath, c.wantFlag)
			}
		})
	}
}

func TestClassifyREST_MemberBoundDiscriminators(t *testing.T) {
	t.Parallel()
	// S3 distinguishes ops sharing a (method, path) by REQUIRED member-bound
	// @httpQuery/@httpHeader params (uploadId, x-amz-copy-source), not the x-id
	// literal. Without these, dropping x-id collides DeleteObject with
	// AbortMultipartUpload and PutObject with CopyObject, and the action check
	// would authorize the wrong (weaker) action.
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"DeleteObject": {HTTPMethod: "DELETE", URITemplate: "/{Bucket}/{Key+}"},
			"AbortMultipartUpload": {
				HTTPMethod:    "DELETE",
				URITemplate:   "/{Bucket}/{Key+}",
				RequiredQuery: []string{"uploadId"},
			},
			"PutObject": {HTTPMethod: "PUT", URITemplate: "/{Bucket}/{Key+}"},
			"CopyObject": {
				HTTPMethod:     "PUT",
				URITemplate:    "/{Bucket}/{Key+}",
				RequiredHeader: []string{"x-amz-copy-source"},
			},
		},
	}
	cases := []struct {
		method, url, copySource, wantOp string
	}{
		{http.MethodDelete, "https://s3.us-east-1.amazonaws.com/b/k", "", "DeleteObject"},
		{http.MethodDelete, "https://s3.us-east-1.amazonaws.com/b/k?uploadId=abc", "", "AbortMultipartUpload"},
		{http.MethodPut, "https://s3.us-east-1.amazonaws.com/b/k", "", "PutObject"},
		{http.MethodPut, "https://s3.us-east-1.amazonaws.com/b/k", "/src/obj", "CopyObject"},
	}
	for _, c := range cases {
		t.Run(c.method+c.url+c.copySource, func(t *testing.T) {
			t.Parallel()
			req := newClassifyReq(t, c.method, c.url)
			if c.copySource != "" {
				req.Header.Set("X-Amz-Copy-Source", c.copySource)
			}
			op, err := classifyREST(model, req, req.URL.Path)
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestClassifyREST_XIDOnlyDiscriminatorMatchesCanonicalRequest(t *testing.T) {
	t.Parallel()
	// Real S3 models carry an SDK-injected x-id query flag (GET /?x-id=ListBuckets,
	// GET /{Bucket}/{Key+}?x-id=GetObject). A non-SDK wire request omits x-id, so
	// the classifier must still match the canonical request rather than fail closed.
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"ListBuckets": {HTTPMethod: "GET", URITemplate: "/?x-id=ListBuckets"},
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}?x-id=GetObject"},
		},
	}
	cases := []struct{ url, wantOp string }{
		{"https://s3.us-east-1.amazonaws.com/", "ListBuckets"},
		{"https://s3.us-east-1.amazonaws.com/my-bucket/path/to/key", "GetObject"},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()
			req := newClassifyReq(t, http.MethodGet, c.url)
			op, err := classifyREST(model, req, req.URL.Path)
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestClassificationPath(t *testing.T) {
	t.Parallel()
	const ph = "/" + vhostBucketPlaceholder
	cases := []struct {
		name         string
		bucketInHost bool
		rawPath      string
		want         string
	}{
		{"path-style identity root", false, "/", "/"},
		{"path-style identity key", false, "/bucket/key.txt", "/bucket/key.txt"},
		{"path-style identity empty", false, "", ""},
		{"vhost root slash", true, "/", ph},
		{"vhost empty path", true, "", ph},
		{"vhost single segment", true, "/key.txt", ph + "/key.txt"},
		{"vhost multi segment", true, "/a/b.txt", ph + "/a/b.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := classificationPath(ParsedHost{Service: "s3", BucketInHost: c.bucketInHost}, c.rawPath)
			if got != c.want {
				t.Errorf("classificationPath(BucketInHost=%v, %q) = %q, want %q",
					c.bucketInHost, c.rawPath, got, c.want)
			}
		})
	}
}

func TestClassifyOperation_virtualHostedSynthesizesBucket(t *testing.T) {
	t.Parallel()
	// Inline S3-shaped model: object op (/{Bucket}/{Key+}), bucket-listing
	// (/{Bucket}), account-level ListBuckets (/), and an object sub-resource.
	// For virtual-hosted hosts the bucket is in the host, so the classifier must
	// prepend a synthetic {Bucket} segment before matching these templates.
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetObject":    {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
			"ListObjects":  {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ListBuckets":  {HTTPMethod: "GET", URITemplate: "/"},
			"GetObjectAcl": {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}?acl"},
		},
	}
	parsed := ParsedHost{Service: "s3", Region: "us-east-1", BucketInHost: true}
	cases := []struct{ name, url, wantOp string }{
		{"single-segment object", "https://my-bucket.s3.us-east-1.amazonaws.com/key.txt", "GetObject"},
		{"multi-segment object", "https://my-bucket.s3.us-east-1.amazonaws.com/a/b.txt", "GetObject"},
		{"bucket root is ListObjects not ListBuckets", "https://my-bucket.s3.us-east-1.amazonaws.com/", "ListObjects"},
		{"object sub-resource acl", "https://my-bucket.s3.us-east-1.amazonaws.com/key.txt?acl", "GetObjectAcl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			req := newClassifyReq(t, http.MethodGet, c.url)
			op, err := ClassifyOperation(model, req, parsed)
			if err != nil {
				t.Fatalf("ClassifyOperation: %v", err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestClassifyOperation_pathStyleUnchanged(t *testing.T) {
	t.Parallel()
	// BucketInHost=false ⇒ classificationPath is identity ⇒ path-style classifies
	// exactly as before (no regression).
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ListBuckets": {HTTPMethod: "GET", URITemplate: "/"},
		},
	}
	parsed := ParsedHost{Service: "s3", Region: "us-east-1", BucketInHost: false}
	cases := []struct{ name, url, wantOp string }{
		{"root is ListBuckets", "https://s3.us-east-1.amazonaws.com/", "ListBuckets"},
		{"bucket root is ListObjects", "https://s3.us-east-1.amazonaws.com/my-bucket", "ListObjects"},
		{"bucket key is GetObject", "https://s3.us-east-1.amazonaws.com/my-bucket/key.txt", "GetObject"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			req := newClassifyReq(t, http.MethodGet, c.url)
			op, err := ClassifyOperation(model, req, parsed)
			if err != nil {
				t.Fatalf("ClassifyOperation: %v", err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestVhostPlaceholder_NoLiteralFirstSegmentCollision(t *testing.T) {
	t.Parallel()
	// WriteGetObjectResponse (POST /WriteGetObjectResponse) is the only S3 op whose
	// path-style template begins with a path LITERAL rather than the {Bucket}
	// placeholder. The synthetic vhost placeholder must not equal that literal, or
	// a virtual-hosted "POST /" would synthesize "/WriteGetObjectResponse" and
	// spuriously classify to it.

	// (a) Template-level invariant: the placeholder segment never matches the literal.
	if matchURITemplate("/WriteGetObjectResponse", "/"+vhostBucketPlaceholder) {
		t.Fatalf("vhostBucketPlaceholder %q collides with the WriteGetObjectResponse literal segment",
			vhostBucketPlaceholder)
	}

	// (b) Behavior-level: a virtual-hosted POST / does not classify to the literal op.
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"WriteGetObjectResponse": {HTTPMethod: "POST", URITemplate: "/WriteGetObjectResponse"},
		},
	}
	req := newClassifyReq(t, http.MethodPost, "https://my-bucket.s3.us-east-1.amazonaws.com/")
	_, err := ClassifyOperation(model, req, ParsedHost{Service: "s3", BucketInHost: true})
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp (placeholder must not match the literal op)", err)
	}
}

func s3MinModel(t *testing.T) *ServiceModel {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return m
}

func newClassifyReq(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
