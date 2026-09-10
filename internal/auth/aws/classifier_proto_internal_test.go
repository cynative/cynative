package aws

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

func TestClassifyJSONRPC_putItem(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
	op, err := classifyJSONRPC(model, v)
	if err != nil {
		t.Fatalf("classifyJSONRPC: %v", err)
	}
	if op != "PutItem" {
		t.Errorf("op = %q, want PutItem", op)
	}
}

func TestClassifyJSONRPC_missingHeader(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	_, err := classifyJSONRPC(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyJSONRPC_malformedHeader(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "no-dot-here")
	_, err := classifyJSONRPC(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyJSONRPC_trailingDot(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "DynamoDB_20120810.")
	_, err := classifyJSONRPC(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyJSONRPC_multipleDots(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "Some.Service.PutItem")
	op, err := classifyJSONRPC(model, v)
	if err != nil {
		t.Fatalf("classifyJSONRPC: %v", err)
	}
	if op != "PutItem" {
		t.Errorf("op = %q, want PutItem", op)
	}
}

func TestClassifyJSONRPC_multipleDotsWithEmptyTail(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "Some.Service.")
	_, err := classifyJSONRPC(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyJSONRPC_unknownOperation(t *testing.T) {
	t.Parallel()
	model := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "DynamoDB_20120810.NoSuchOp")
	_, err := classifyJSONRPC(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyQuery_bodyAction(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	v.Body = "Action=ListUsers&Version=2010-05-08"
	op, err := classifyQuery(model, v)
	if err != nil {
		t.Fatalf("classifyQuery: %v", err)
	}
	if op != "ListUsers" {
		t.Errorf("op = %q, want ListUsers", op)
	}
}

func TestClassifyQuery_urlAction(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
	op, err := classifyQuery(model, v)
	if err != nil {
		t.Fatalf("classifyQuery: %v", err)
	}
	if op != "ListUsers" {
		t.Errorf("op = %q, want ListUsers", op)
	}
}

func TestClassifyQuery_unknownOpInURL(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=NoSuchOp")
	_, err := classifyQuery(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyQuery_unknownOpInBody(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	body := "Action=NoSuchOp"
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	v.Body = body
	_, err := classifyQuery(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyQuery_nilBodyAndNoURLAction(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/")
	_, err := classifyQuery(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyQuery_bodyMissingActionParam(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	body := "Version=2010-05-08"
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	v.Body = body
	_, err := classifyQuery(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyQuery_bodyMalformedQueryString(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// "%ZZ" is an invalid percent escape — url.ParseQuery returns an error.
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	v.Body = "Action=%ZZ"
	_, err := classifyQuery(model, v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyOperation_dispatchByProtocol(t *testing.T) {
	t.Parallel()
	s3 := s3MinModel(t)
	dyn := dynamodbMinModel(t)
	iam := iamMinModel()
	iam.Protocol = ProtocolAWSQuery

	cases := []struct {
		name  string
		model *ServiceModel
		setup func(*testing.T) authreq.View
		want  []string
	}{
		{
			"rest-xml", s3,
			func(t *testing.T) authreq.View {
				t.Helper()
				return newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
			},
			[]string{"ListBuckets", "ListDirectoryBuckets"},
		},
		{
			"json-rpc", dyn,
			func(t *testing.T) authreq.View {
				t.Helper()
				r := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
				r.Header.Set("X-Amz-Target", "DynamoDB_20120810.ListTables")
				return r
			},
			[]string{"ListTables"},
		},
		{
			"query", iam,
			func(t *testing.T) authreq.View {
				t.Helper()
				return newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers")
			},
			[]string{"ListUsers"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ops, err := ClassifyOperation(c.model, c.setup(t), ParsedHost{})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if !slices.Equal(ops, c.want) {
				t.Errorf("ops = %v, want %v", ops, c.want)
			}
		})
	}
}

func TestClassifyOperation_restJSON1RoutesThroughREST(t *testing.T) {
	t.Parallel()
	m := s3MinModel(t)
	m.Protocol = ProtocolRestJSON1
	v := newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	ops, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"ListBuckets", "ListDirectoryBuckets"}) {
		t.Errorf("ops = %v, want [ListBuckets ListDirectoryBuckets]", ops)
	}
}

// TestClassifyOperation_singletonClassifierErrorPropagates: a non-REST
// classifier's failure comes back unchanged through ClassifyOperation with no
// candidate set beside it.
func TestClassifyOperation_singletonClassifierErrorPropagates(t *testing.T) {
	t.Parallel()
	m := dynamodbMinModel(t)
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	ops, err := ClassifyOperation(m, v, ParsedHost{}) // no X-Amz-Target header.
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("err = %v, want ErrClassifierUnknownOp", err)
	}
	if ops != nil {
		t.Errorf("ops = %v, want nil on error", ops)
	}
}

func TestClassifyOperation_awsJSON11RoutesThroughJSONRPC(t *testing.T) {
	t.Parallel()
	m := dynamodbMinModel(t)
	m.Protocol = ProtocolAWSJSON11
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "X.ListTables")
	ops, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"ListTables"}) {
		t.Errorf("ops = %v, want [ListTables]", ops)
	}
}

func TestClassifyOperation_ec2QueryRoutesThroughQuery(t *testing.T) {
	t.Parallel()
	m := iamMinModel()
	m.Protocol = ProtocolEC2Query
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers")
	ops, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"ListUsers"}) {
		t.Errorf("ops = %v, want [ListUsers]", ops)
	}
}

func TestClassifyOperation_unknownProtocolFails(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{Protocol: ProtocolUnknown, Operations: map[string]Operation{}}
	_, err := ClassifyOperation(model, newClassifyView(t, http.MethodGet, "https://example/"), ParsedHost{})
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func TestClassifyOperation_unsupportedProtocolFails(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{Protocol: Protocol(99), Operations: map[string]Operation{}}
	_, err := ClassifyOperation(model, newClassifyView(t, http.MethodGet, "https://example/"), ParsedHost{})
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp", err)
	}
}

func dynamodbMinModel(t *testing.T) *ServiceModel {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "dynamodb-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return m
}

func iamMinModel() *ServiceModel {
	return &ServiceModel{
		ARNNamespace: "iam", EndpointPrefix: "iam", Protocol: ProtocolAWSQuery,
		Operations: map[string]Operation{
			"ListUsers":  {},
			"CreateUser": {},
		},
	}
}

func TestClassifyQuery_postURLActionRejected_reportedAttack(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// URL says a benign op; body says another. AWS executes the body — deny.
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/?Action=ListUsers")
	v.Body = "Action=CreateUser&Version=2010-05-08"
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want ErrClassifierUnknownOp (URL Action on POST must deny)", err)
	}
}

func TestClassifyQuery_postURLActionRejected_evenWhenAgreeing(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/?Action=ListUsers")
	v.Body = "Action=ListUsers"
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (strict: any URL Action on POST denies)", err)
	}
}

func TestClassifyQuery_postEmptyURLActionRejected(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// "?Action=" — present but empty; still a smuggling tell on a POST.
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/?Action=")
	v.Body = "Action=ListUsers"
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (empty URL Action present on POST)", err)
	}
}

func TestClassifyQuery_postDuplicateBodyAction(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	v.Body = "Action=ListUsers&Action=CreateUser"
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (duplicate Action in body)", err)
	}
}

func TestClassifyQuery_postEmptyBody(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// POST, no URL Action, empty body string -> distinct empty-body branch.
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (POST empty body)", err)
	}
}

func TestClassifyQuery_getDuplicateURLAction(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Action=CreateUser")
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (duplicate Action in URL)", err)
	}
}

func TestClassifyQuery_emptyActionValueDenied(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// "?Action=" — Action present but empty value → deny. Reaches singleAction's
	// empty-Action arm via the GET/URL path (on a POST the URL-Action guard would
	// intercept it first), so this is the case that covers that branch.
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=")
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (empty Action value)", err)
	}
}

func TestClassifyQuery_lowercaseMethodClassifies(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// Model-supplied lowercase "post"/"get" must still classify, not fall to deny.
	post := newClassifyView(t, "post", "https://iam.amazonaws.com/")
	post.Body = "Action=ListUsers"
	if op, err := classifyQuery(model, post); err != nil || op != "ListUsers" {
		t.Errorf("lowercase post: op=%q err=%v, want ListUsers", op, err)
	}
	get := newClassifyView(t, "get", "https://iam.amazonaws.com/?Action=ListUsers")
	if op, err := classifyQuery(model, get); err != nil || op != "ListUsers" {
		t.Errorf("lowercase get: op=%q err=%v, want ListUsers", op, err)
	}
}

func TestClassifyQuery_unsupportedMethod(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	v := newClassifyView(t, http.MethodDelete, "https://iam.amazonaws.com/?Action=ListUsers")
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (method not used by query protocol)", err)
	}
}

// lambdaShapedModel is the pair the encoded-slash case turns on: two GET
// operations whose templates differ only in a trailing literal segment.
func lambdaShapedModel() *ServiceModel {
	return &ServiceModel{
		ARNNamespace: "lambda", EndpointPrefix: "lambda", Protocol: ProtocolRestJSON1,
		Operations: map[string]Operation{
			"GetFunction": {HTTPMethod: "GET", URITemplate: "/2015-03-31/functions/{FunctionName}"},
			"GetPolicy":   {HTTPMethod: "GET", URITemplate: "/2015-03-31/functions/{FunctionName}/policy"},
		},
	}
}

// TestClassifyOperation_EncodedSlashNamesBothReadings: the wire reading keeps
// the encoded slash inside the name segment and names GetFunction, the decoded
// reading splits it and names GetPolicy. Nothing in the request says which one
// the service runs, so both are returned and the caller authorizes both.
func TestClassifyOperation_EncodedSlashNamesBothReadings(t *testing.T) {
	t.Parallel()
	v := newClassifyView(t, http.MethodGet,
		"https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my%2Fpolicy")
	parsed, err := ParseHost(v.Hostname)
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	ops, err := ClassifyOperation(lambdaShapedModel(), v, parsed)
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"GetFunction", "GetPolicy"}) {
		t.Errorf("ops = %v, want [GetFunction GetPolicy]", ops)
	}
}

// TestClassifyOperation_PlainPathReadsOnce: an ordinary path has one reading,
// so the union changes nothing for the traffic that carries no encoding.
func TestClassifyOperation_PlainPathReadsOnce(t *testing.T) {
	t.Parallel()
	v := newClassifyView(t, http.MethodGet,
		"https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/myfunc")
	parsed, err := ParseHost(v.Hostname)
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	ops, err := ClassifyOperation(lambdaShapedModel(), v, parsed)
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"GetFunction"}) {
		t.Errorf("ops = %v, want [GetFunction]", ops)
	}
}

// TestClassifyOperation_WireOnlyMatchStandsAlone: an ARN label carries an
// encoded slash on the wire, so only the wire reading matches a template. The
// decoded reading names nothing and contributes nothing, and the request
// classifies instead of failing closed.
func TestClassifyOperation_WireOnlyMatchStandsAlone(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "eks", EndpointPrefix: "eks", Protocol: ProtocolRestJSON1,
		Operations: map[string]Operation{
			"ListTagsForResource": {HTTPMethod: "GET", URITemplate: "/tags/{resourceArn}"},
		},
	}
	v := newClassifyView(t, http.MethodGet,
		"https://eks.us-east-1.amazonaws.com/tags/arn%3Aaws%3Aeks%3Aus-east-1%3A1%3Acluster%2Fmine")
	parsed, err := ParseHost(v.Hostname)
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	ops, err := ClassifyOperation(model, v, parsed)
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"ListTagsForResource"}) {
		t.Errorf("ops = %v, want [ListTagsForResource]", ops)
	}
}

// TestClassifyOperation_NoReadingMatchesDenies: when no reading names an
// operation the request still fails closed, and the message names the path.
func TestClassifyOperation_NoReadingMatchesDenies(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "eks", EndpointPrefix: "eks", Protocol: ProtocolRestJSON1,
		Operations: map[string]Operation{
			"ListTagsForResource": {HTTPMethod: "GET", URITemplate: "/tags/{resourceArn}"},
		},
	}
	v := newClassifyView(t, http.MethodGet, "https://eks.us-east-1.amazonaws.com/other/a%2Fb")
	parsed, err := ParseHost(v.Hostname)
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	_, err = ClassifyOperation(model, v, parsed)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("err = %v, want ErrClassifierUnknownOp", err)
	}
	if !strings.Contains(err.Error(), "/other/a%2Fb") {
		t.Errorf("err = %v, want it to name the wire reading /other/a%%2Fb", err)
	}
}

// TestClassifyOperation_TrailingSlashNamesBucketListing: a path-style GET on
// /mybucket/ has no reading that matches the greedy /{Bucket}/{Key+} template,
// because its span is one empty segment, but the trailing-empty-dropped
// reading matches /{Bucket} and names the bucket-listing operation. S3 answers
// this exact request with a bucket listing, not an object read.
func TestClassifyOperation_TrailingSlashNamesBucketListing(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
		},
	}
	v := newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/mybucket/")
	parsed, err := ParseHost(v.Hostname)
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	ops, err := ClassifyOperation(model, v, parsed)
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"ListObjects"}) {
		t.Errorf("ops = %v, want [ListObjects]", ops)
	}
}

// TestClassifyOperation_VirtualHostedSeparatorsOnlyIsObjectRead: a
// virtual-hosted GET whose path is nothing but separators, such as "//", has
// only its own reading, because a reading left with nothing but empty
// segments after the trailing one drops is not offered. classificationSegments
// prepends the synthetic bucket segment ahead of both remaining path segments,
// which matches the greedy /{Bucket}/{Key+} template and names an object read
// of the key "/", never the bucket listing.
func TestClassifyOperation_VirtualHostedSeparatorsOnlyIsObjectRead(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		ARNNamespace: "s3", EndpointPrefix: "s3", Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
		},
	}
	parsed := ParsedHost{Service: "s3", Region: "us-east-1", BucketInHost: true}
	v := newClassifyView(t, http.MethodGet, "https://my-bucket.s3.us-east-1.amazonaws.com//")
	ops, err := ClassifyOperation(model, v, parsed)
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if !slices.Equal(ops, []string{"GetObject"}) {
		t.Errorf("ops = %v, want [GetObject]", ops)
	}
}
