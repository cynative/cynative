package aws

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
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
		// A trailing slash leaves a greedy label one empty segment to take, and
		// that value joins to the empty string: S3 treats it as no key at all and
		// runs the bucket operation, not the object one.
		{"/{Bucket}/{Key+}", "/foo/", false},
		// A doubled trailing slash leaves the greedy label two empty segments,
		// which join to "/": a real key, the one S3 answers with 404 NoSuchKey.
		{"/{Bucket}/{Key+}", "/foo//", true},
		// The path arrives without a query (the view carries RawQuery apart), so
		// a "?" in it is a decoded %3F: part of the segment, not a separator.
		{"/foo", "/foo?query", false},
		{"/{Bar}", "/foo?query", true},
		{"/literal", "/literal", true},
		{"/literal", "/other", false},
		// Segments after a greedy label must match the tail of the path; the
		// greedy label takes what is left in between and needs at least one segment.
		{"/portals/{Arn+}/identityProviders", "/portals/a/b/identityProviders", true},
		{"/portals/{Arn+}/identityProviders", "/portals/a/identityProviders", true},
		{"/portals/{Arn+}/identityProviders", "/portals/identityProviders", false},
		{"/portals/{Arn+}/identityProviders", "/portals/x", false},
		{"/portals/{Arn+}/identityProviders", "/portals/x/foo", false},
		{"/portals/{Arn+}/identityProviders", "/portals/x/identityProviders/extra", false},
		{"/mrap/instances/{Name+}/policy", "/mrap/instances/my-mrap", false},
		{"/mrap/instances/{Name+}/policy", "/mrap/instances/my-mrap/policy", true},
		{"/a/{X+}/b/{Y}", "/a/1/2/b/c", true},
		{"/a/{X+}/b/{Y}", "/a/1/2/b/", false},
		// The doubled slash puts an empty segment inside the greedy span, not in
		// the trailing single label, so the greedy label absorbs it and matches.
		{"/a/{X+}/b", "/a/1//b", true},
		// No segment before the doubled slash leaves the greedy span exactly one
		// empty segment, the join-to-empty-string case the guard rejects.
		{"/a/{X+}/b", "/a//b", false},
	}
	for _, c := range cases {
		t.Run(c.template+"|"+c.path, func(t *testing.T) {
			t.Parallel()
			got := matchURITemplate(c.template, splitSegments(c.path))
			if got != c.want {
				t.Errorf("matchURITemplate(%q, %q) = %v, want %v", c.template, c.path, got, c.want)
			}
		})
	}
}

// TestClassifyREST_RootTiesListBucketsWithDirectoryBuckets pins the shape of the
// real S3 model: ListBuckets and ListDirectoryBuckets are both GET / once the
// SDK-only x-id tag is dropped, so the canonical bucket listing is a tie and the
// classifier must return both candidates rather than the lexically first.
func TestClassifyREST_RootTiesListBucketsWithDirectoryBuckets(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	v := newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"ListBuckets", "ListDirectoryBuckets"}) {
		t.Errorf("ops = %v, want [ListBuckets ListDirectoryBuckets]", ops)
	}
}

// TestClassifyREST_EqualScoreReturnsEveryCandidateSorted: equal-score matches
// are all returned, in name order, whatever order the map yields them.
func TestClassifyREST_EqualScoreReturnsEveryCandidateSorted(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestJSON1,
		Operations: map[string]Operation{
			"ZWrite": {HTTPMethod: "POST", URITemplate: "/resource"},
			"ARead":  {HTTPMethod: "POST", URITemplate: "/resource"},
			"MRead":  {HTTPMethod: "POST", URITemplate: "/resource"},
			"Other":  {HTTPMethod: "GET", URITemplate: "/resource"},
		},
	}
	v := newClassifyView(t, http.MethodPost, "https://x.amazonaws.com/resource")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"ARead", "MRead", "ZWrite"}) {
		t.Errorf("ops = %v, want [ARead MRead ZWrite]", ops)
	}
}

// TestClassifyREST_HigherScoreExcludesTiedLowerCandidates: a tie below the top
// score is not a tie; only the most specific match is returned.
func TestClassifyREST_HigherScoreExcludesTiedLowerCandidates(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"AAA": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"BBB": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ZZZ": {HTTPMethod: "GET", URITemplate: "/{Bucket}?flag"},
		},
	}
	v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com/foo?flag")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"ZZZ"}) {
		t.Errorf("ops = %v, want [ZZZ]", ops)
	}
}

// TestClassifyREST_RequestCarryingTwoSubresourcesTies: a request that carries
// the discriminators of two sibling operations (something no SDK sends) ties
// them at the top score, and both come back so the gate authorizes both.
func TestClassifyREST_RequestCarryingTwoSubresourcesTies(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetBucketTagging": {HTTPMethod: "GET", URITemplate: "/{Bucket}?tagging"},
			"GetBucketAcl":     {HTTPMethod: "GET", URITemplate: "/{Bucket}?acl"},
			"ListObjects":      {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
		},
	}
	v := newClassifyView(t, http.MethodGet, "https://s3.amazonaws.com/foo?acl&tagging")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"GetBucketAcl", "GetBucketTagging"}) {
		t.Errorf("ops = %v, want [GetBucketAcl GetBucketTagging]", ops)
	}
}

// TestClassifyREST_LongerGreedyTemplateOutranksItsPrefix mirrors the S3
// Control multi-region access point reads: four GET templates share a greedy
// prefix and the same required header. The literal after the greedy label
// excludes a sub-resource template from paths that do not end in it, and where
// both the plain template and a sub-resource template match, the longer one is
// the more specific and wins alone.
func TestClassifyREST_LongerGreedyTemplateOutranksItsPrefix(t *testing.T) {
	t.Parallel()
	model := mrapModel()
	cases := []struct {
		path string
		want []string
	}{
		{"/v20180820/mrap/instances/my-mrap", []string{"GetMultiRegionAccessPoint"}},
		{"/v20180820/mrap/instances/my-mrap/policy", []string{"GetMultiRegionAccessPointPolicy"}},
		{"/v20180820/mrap/instances/my-mrap/policystatus", []string{"GetMultiRegionAccessPointPolicyStatus"}},
		{"/v20180820/mrap/instances/my-mrap/routes", []string{"GetMultiRegionAccessPointRoutes"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			v := newClassifyView(t, http.MethodGet, "https://123456789012.s3-control.us-east-1.amazonaws.com"+c.path)
			v.Header.Set("X-Amz-Account-Id", "123456789012")
			ops, err := classifyREST(model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, c.want) {
				t.Errorf("ops = %v, want %v", ops, c.want)
			}
		})
	}
}

// TestClassifyREST_EncodedQuestionMarkIsPathData: the view's Path is decoded,
// so a %3F in a path segment arrives as a literal "?". It is data inside that
// segment, and matching it as a query separator would let an escaped suffix
// forge a match against a literal template: AWS routes
// /automationrulesv2/list%3Fx to the read of the identifier "list?x", never to
// the list operation.
func TestClassifyREST_EncodedQuestionMarkIsPathData(t *testing.T) {
	t.Parallel()
	model := restModel(http.MethodGet, map[string]string{
		"GetAutomationRuleV2":   "/automationrulesv2/{Identifier}",
		"ListAutomationRulesV2": "/automationrulesv2/list",
	})
	v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com/automationrulesv2/list%3Fx")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"GetAutomationRuleV2"}) {
		t.Errorf("ops = %v, want [GetAutomationRuleV2]", ops)
	}
}

// TestClassifyREST_SpecificityRoutingSpecExamples runs the three routing
// examples of the Smithy 2.0 http-bindings specification ("Specificity
// Routing") as written there: a literal outranks a label at the same index,
// path specificity outranks a query literal, and a longer template outranks
// the greedy template it extends.
func TestClassifyREST_SpecificityRoutingSpecExamples(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		uris map[string]string
		path string
		want string
	}{
		{"example 1: literal bcd beats label", example1, "/abc/bcd/cde", "Pattern1"},
		{"example 1: literal abc beats label", example1, "/abc/foo/cde", "Pattern2"},
		{"example 1: non-ambiguous", example1, "/foo/bcd/cde", "Pattern3"},
		{"example 2: path specificity wins over query literal", example2, "/abc/bcd/cde?def=efg", "Pattern1"},
		{"example 2: literal abc beats label", example2, "/abc/foo/cde?def=efg", "Pattern2"},
		{"example 2: non-ambiguous", example2, "/foo/bcd/cde?def=efg", "Pattern3"},
		{"example 3: literal after greedy beats bare greedy", example3, "/abc/foo/bar/bcd", "Pattern1"},
		{"example 3: non-ambiguous", example3, "/abc/foo/bar/baz", "Pattern2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			model := restModel(http.MethodGet, c.uris)
			v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com"+c.path)
			ops, err := classifyREST(model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, []string{c.want}) {
				t.Errorf("ops = %v, want [%s]", ops, c.want)
			}
		})
	}
}

// The URI patterns of the specification's routing examples, keyed by the
// pattern number the specification uses.
var (
	example1 = map[string]string{ //nolint:gochecknoglobals // immutable fixture
		"Pattern1": "/abc/bcd/{xyz}",
		"Pattern2": "/abc/{xyz}/cde",
		"Pattern3": "/{xyz}/bcd/cde",
	}
	example2 = map[string]string{ //nolint:gochecknoglobals // immutable fixture
		"Pattern1": "/abc/bcd/{xyz}",
		"Pattern2": "/abc/{xyz}/cde",
		"Pattern3": "/{xyz}/bcd/cde?def=efg",
	}
	example3 = map[string]string{ //nolint:gochecknoglobals // immutable fixture
		"Pattern1": "/abc/{xyz+}/bcd",
		"Pattern2": "/abc/{xyz+}",
	}
)

// TestClassifyREST_SpecificityRoutingShippedModels pins, per service, the
// template pairs in the shipped aws/api-models-aws models that tie on
// discriminator count and that specificity routing resolves: a literal
// segment against a label at the same index, and a bare greedy template
// against the longer templates that extend it. Each request is one the model
// could send, and the expected operation is the one AWS routes it to.
func TestClassifyREST_SpecificityRoutingShippedModels(t *testing.T) {
	t.Parallel()
	iotsitewise := restModel(http.MethodPost, map[string]string{
		"ListComputationModelDataBindingUsages": "/computation-models/data-binding-usages",
		"UpdateComputationModel":                "/computation-models/{computationModelId}",
	})
	securityhub := restModel(http.MethodGet, map[string]string{
		"GetAutomationRuleV2":   "/automationrulesv2/{Identifier}",
		"ListAutomationRulesV2": "/automationrulesv2/list",
	})
	wickr := restModel(http.MethodGet, map[string]string{
		"GetBot":        "/networks/{networkId}/bots/{botId}",
		"GetBotsCount":  "/networks/{networkId}/bots/count",
		"GetUser":       "/networks/{networkId}/users/{userId}",
		"GetUsersCount": "/networks/{networkId}/users/count",
	})
	quicksight := restModel(http.MethodPost, map[string]string{
		"BatchDeleteKnowledgeBase": "/v1/accounts/{AwsAccountId}/knowledge-bases/batch-delete",
		"UpdateKnowledgeBase":      "/v1/accounts/{AwsAccountId}/knowledge-bases/{KnowledgeBaseId}",
	})
	mediaconnect := restModel(http.MethodPost, map[string]string{
		"AddFlowMediaStreams":   "/v1/flows/{FlowArn}/mediaStreams",
		"AddFlowOutputs":        "/v1/flows/{FlowArn}/outputs",
		"AddFlowSources":        "/v1/flows/{FlowArn}/source",
		"AddFlowVpcInterfaces":  "/v1/flows/{FlowArn}/vpcInterfaces",
		"GrantFlowEntitlements": "/v1/flows/{FlowArn}/entitlements",
		"StartFlow":             "/v1/flows/start/{FlowArn}",
		"StopFlow":              "/v1/flows/stop/{FlowArn}",
	})
	workspacesWeb := restModel(http.MethodGet, map[string]string{
		"GetPortal":                  "/portals/{portalArn+}",
		"GetSession":                 "/portals/{portalId}/sessions/{sessionId}",
		"GetTrustStore":              "/trustStores/{trustStoreArn+}",
		"ListIdentityProviders":      "/portals/{portalArn+}/identityProviders",
		"ListSessions":               "/portals/{portalId}/sessions",
		"ListTrustStoreCertificates": "/trustStores/{trustStoreArn+}/certificates",
	})
	cases := []struct {
		name   string
		model  *ServiceModel
		method string
		path   string
		want   string
	}{
		{
			"iotsitewise literal usages",
			iotsitewise,
			http.MethodPost,
			"/computation-models/data-binding-usages",
			"ListComputationModelDataBindingUsages",
		},
		{"iotsitewise label id", iotsitewise, http.MethodPost, "/computation-models/cm-1", "UpdateComputationModel"},
		{"securityhub literal list", securityhub, http.MethodGet, "/automationrulesv2/list", "ListAutomationRulesV2"},
		{"securityhub label id", securityhub, http.MethodGet, "/automationrulesv2/x", "GetAutomationRuleV2"},
		{"wickr literal bots count", wickr, http.MethodGet, "/networks/n/bots/count", "GetBotsCount"},
		{"wickr label bot id", wickr, http.MethodGet, "/networks/n/bots/b", "GetBot"},
		{"wickr literal users count", wickr, http.MethodGet, "/networks/n/users/count", "GetUsersCount"},
		{"wickr label user id", wickr, http.MethodGet, "/networks/n/users/u", "GetUser"},
		{
			"quicksight literal batch-delete",
			quicksight,
			http.MethodPost,
			"/v1/accounts/1/knowledge-bases/batch-delete",
			"BatchDeleteKnowledgeBase",
		},
		{
			"quicksight label id",
			quicksight,
			http.MethodPost,
			"/v1/accounts/1/knowledge-bases/kb",
			"UpdateKnowledgeBase",
		},
		{
			"mediaconnect literal start beats label",
			mediaconnect,
			http.MethodPost,
			"/v1/flows/start/outputs",
			"StartFlow",
		},
		{
			"mediaconnect literal stop beats label",
			mediaconnect,
			http.MethodPost,
			"/v1/flows/stop/entitlements",
			"StopFlow",
		},
		{"mediaconnect label flow arn", mediaconnect, http.MethodPost, "/v1/flows/f/outputs", "AddFlowOutputs"},
		{"workspaces-web bare greedy portal", workspacesWeb, http.MethodGet, "/portals/a/b", "GetPortal"},
		{
			"workspaces-web greedy plus literal",
			workspacesWeb,
			http.MethodGet,
			"/portals/a/b/identityProviders",
			"ListIdentityProviders",
		},
		{
			"workspaces-web single label beats greedy",
			workspacesWeb,
			http.MethodGet,
			"/portals/p/sessions",
			"ListSessions",
		},
		{
			"workspaces-web longer single-label template",
			workspacesWeb,
			http.MethodGet,
			"/portals/p/sessions/s",
			"GetSession",
		},
		{"workspaces-web bare greedy trust store", workspacesWeb, http.MethodGet, "/trustStores/a/b", "GetTrustStore"},
		{
			"workspaces-web greedy plus certificates",
			workspacesWeb,
			http.MethodGet,
			"/trustStores/a/b/certificates",
			"ListTrustStoreCertificates",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			v := newClassifyView(t, c.method, "https://x.amazonaws.com"+c.path)
			ops, err := classifyREST(c.model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, []string{c.want}) {
				t.Errorf("ops = %v, want [%s]", ops, c.want)
			}
		})
	}
}

// TestClassifyREST_PathShapeOutranksDiscriminatorCount: the template with the
// more specific path wins even when its rival carries more discriminators the
// request satisfies. The specification ranks query literals only after the
// path, and the member-bound discriminators count with them.
func TestClassifyREST_PathShapeOutranksDiscriminatorCount(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestJSON1,
		Operations: map[string]Operation{
			"ALabel":   {HTTPMethod: "GET", URITemplate: "/{y}/{b}?flag", RequiredHeader: []string{"x-hint"}},
			"BLiteral": {HTTPMethod: "GET", URITemplate: "/x/{a}"},
		},
	}
	v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com/x/z?flag")
	v.Header.Set("X-Hint", "1")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"BLiteral"}) {
		t.Errorf("ops = %v, want [BLiteral]", ops)
	}
}

// restModel builds a REST model whose operations all use method, one per
// name → URI template pair.
func restModel(method string, uris map[string]string) *ServiceModel {
	ops := make(map[string]Operation, len(uris))
	for name, uri := range uris {
		ops[name] = Operation{HTTPMethod: method, URITemplate: uri}
	}
	return &ServiceModel{ARNNamespace: "x", EndpointPrefix: "x", Protocol: ProtocolRestJSON1, Operations: ops}
}

// mrapModel is the S3 Control multi-region access point read family as the
// shipped model declares it: a greedy name label, literal sub-resource suffixes,
// and the account id header every S3 Control call must carry.
func mrapModel() *ServiceModel {
	op := func(uri string) Operation {
		return Operation{HTTPMethod: "GET", URITemplate: uri, RequiredHeader: []string{"x-amz-account-id"}}
	}
	return &ServiceModel{
		Dir: "s3-control", ARNNamespace: "s3", EndpointPrefix: "s3-control", SigningName: "s3",
		Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetMultiRegionAccessPoint":             op("/v20180820/mrap/instances/{Name+}"),
			"GetMultiRegionAccessPointPolicy":       op("/v20180820/mrap/instances/{Name+}/policy"),
			"GetMultiRegionAccessPointPolicyStatus": op("/v20180820/mrap/instances/{Name+}/policystatus"),
			"GetMultiRegionAccessPointRoutes":       op("/v20180820/mrap/instances/{Mrap+}/routes"),
		},
	}
}

func TestClassifyREST_GetObject(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	v := newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/my-bucket/path/to/key")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"GetObject"}) {
		t.Errorf("ops = %v, want [GetObject]", ops)
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
			v := newClassifyView(t, http.MethodGet, c.url)
			ops, err := classifyREST(model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, []string{c.wantOp}) {
				t.Errorf("ops = %v, want [%s]", ops, c.wantOp)
			}
		})
	}
}

func TestClassifyREST_NoMatchReturnsUnknown(t *testing.T) {
	t.Parallel()
	model := s3MinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://s3.us-east-1.amazonaws.com/foo")
	_, err := classifyREST(model, v, splitSegments(v.Path))
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
	v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com/foo?flag")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"ZZZ"}) {
		t.Errorf("ops = %v, want [ZZZ]", ops)
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
	v := newClassifyView(t, http.MethodGet, "https://x.amazonaws.com/")
	ops, err := classifyREST(model, v, splitSegments(v.Path))
	if err != nil {
		t.Fatalf("classifyREST: %v", err)
	}
	if !slices.Equal(ops, []string{"WithGet"}) {
		t.Errorf("ops = %v, want [WithGet]", ops)
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
			v := newClassifyView(t, c.method, c.url)
			if c.copySource != "" {
				v.Header.Set("X-Amz-Copy-Source", c.copySource)
			}
			ops, err := classifyREST(model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, []string{c.wantOp}) {
				t.Errorf("ops = %v, want [%s]", ops, c.wantOp)
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
			v := newClassifyView(t, http.MethodGet, c.url)
			ops, err := classifyREST(model, v, splitSegments(v.Path))
			if err != nil {
				t.Fatalf("classifyREST: %v", err)
			}
			if !slices.Equal(ops, []string{c.wantOp}) {
				t.Errorf("ops = %v, want [%s]", ops, c.wantOp)
			}
		})
	}
}

func TestClassificationSegments(t *testing.T) {
	t.Parallel()
	const ph = vhostBucketPlaceholder
	cases := []struct {
		name         string
		bucketInHost bool
		rawPath      string
		want         []string
	}{
		{"path-style identity root", false, "/", []string{""}},
		{"path-style identity key", false, "/bucket/key.txt", []string{"bucket", "key.txt"}},
		{"path-style identity empty", false, "", []string{""}},
		{"vhost root slash", true, "/", []string{ph}},
		{"vhost empty path", true, "", []string{ph}},
		{"vhost single segment", true, "/key.txt", []string{ph, "key.txt"}},
		{"vhost multi segment", true, "/a/b.txt", []string{ph, "a", "b.txt"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := classificationSegments(
				ParsedHost{Service: "s3", BucketInHost: c.bucketInHost},
				splitSegments(c.rawPath),
			)
			if !slices.Equal(got, c.want) {
				t.Errorf("classificationSegments(BucketInHost=%v, %q) = %v, want %v",
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
			v := newClassifyView(t, http.MethodGet, c.url)
			ops, err := ClassifyOperation(model, v, parsed)
			if err != nil {
				t.Fatalf("ClassifyOperation: %v", err)
			}
			if !slices.Equal(ops, []string{c.wantOp}) {
				t.Errorf("ops = %v, want [%s]", ops, c.wantOp)
			}
		})
	}
}

func TestClassifyOperation_pathStyleUnchanged(t *testing.T) {
	t.Parallel()
	// BucketInHost=false ⇒ classificationSegments is identity ⇒ path-style classifies
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
			v := newClassifyView(t, http.MethodGet, c.url)
			ops, err := ClassifyOperation(model, v, parsed)
			if err != nil {
				t.Fatalf("ClassifyOperation: %v", err)
			}
			if !slices.Equal(ops, []string{c.wantOp}) {
				t.Errorf("ops = %v, want [%s]", ops, c.wantOp)
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
	if matchURITemplate("/WriteGetObjectResponse", []string{vhostBucketPlaceholder}) {
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
	v := newClassifyView(t, http.MethodPost, "https://my-bucket.s3.us-east-1.amazonaws.com/")
	_, err := ClassifyOperation(model, v, ParsedHost{Service: "s3", BucketInHost: true})
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

func newClassifyView(t *testing.T, method, rawurl string) authreq.View {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, rawurl, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return authreq.NewView(req, "")
}
