package aws

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
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
		name   string
		model  *ServiceModel
		setup  func(*testing.T) authreq.View
		wantOp string
	}{
		{
			"rest-xml", s3,
			func(t *testing.T) authreq.View {
				t.Helper()
				return newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
			},
			"ListBuckets",
		},
		{
			"json-rpc", dyn,
			func(t *testing.T) authreq.View {
				t.Helper()
				r := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
				r.Header.Set("X-Amz-Target", "DynamoDB_20120810.ListTables")
				return r
			},
			"ListTables",
		},
		{
			"query", iam,
			func(t *testing.T) authreq.View {
				t.Helper()
				return newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers")
			},
			"ListUsers",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			op, err := ClassifyOperation(c.model, c.setup(t), ParsedHost{})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
		})
	}
}

func TestClassifyOperation_restJSON1RoutesThroughREST(t *testing.T) {
	t.Parallel()
	m := s3MinModel(t)
	m.Protocol = ProtocolRestJSON1
	v := newClassifyView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	op, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if op != "ListBuckets" {
		t.Errorf("op = %q, want ListBuckets", op)
	}
}

func TestClassifyOperation_awsJSON11RoutesThroughJSONRPC(t *testing.T) {
	t.Parallel()
	m := dynamodbMinModel(t)
	m.Protocol = ProtocolAWSJSON11
	v := newClassifyView(t, http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/")
	v.Header.Set("X-Amz-Target", "X.ListTables")
	op, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if op != "ListTables" {
		t.Errorf("op = %q, want ListTables", op)
	}
}

func TestClassifyOperation_ec2QueryRoutesThroughQuery(t *testing.T) {
	t.Parallel()
	m := iamMinModel()
	m.Protocol = ProtocolEC2Query
	v := newClassifyView(t, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers")
	op, err := ClassifyOperation(m, v, ParsedHost{})
	if err != nil {
		t.Fatalf("ClassifyOperation: %v", err)
	}
	if op != "ListUsers" {
		t.Errorf("op = %q, want ListUsers", op)
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

func TestClassifyQuery_postNilBody(t *testing.T) {
	t.Parallel()
	model := iamMinModel()
	// POST, no URL Action, nil body → distinct nil-body branch.
	v := newClassifyView(t, http.MethodPost, "https://iam.amazonaws.com/")
	if _, err := classifyQuery(model, v); !errors.Is(err, ErrClassifierUnknownOp) {
		t.Errorf("err = %v, want deny (POST nil body)", err)
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
