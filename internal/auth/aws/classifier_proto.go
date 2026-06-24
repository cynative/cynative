package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// classifyJSONRPC identifies the operation for AWS JSON RPC services
// (awsJson1_0, awsJson1_1). The operation is encoded in the X-Amz-Target
// header as "<ServiceName>.<Operation>".
func classifyJSONRPC(model *ServiceModel, req *http.Request) (string, error) {
	target := req.Header.Get("X-Amz-Target")
	if target == "" {
		return "", fmt.Errorf("%w: X-Amz-Target header missing", ErrClassifierUnknownOp)
	}
	// X-Amz-Target is "<ServiceName>.<Operation>"; the operation is the final
	// dot-segment (a single split also handles multi-dot targets).
	i := strings.LastIndexByte(target, '.')
	if i < 0 || i == len(target)-1 {
		return "", fmt.Errorf("%w: malformed X-Amz-Target %q", ErrClassifierUnknownOp, target)
	}
	op := target[i+1:]
	if _, found := model.Operations[op]; !found {
		return "", fmt.Errorf("%w: %q not in service model", ErrClassifierUnknownOp, op)
	}
	return op, nil
}

// classifyQuery identifies the operation for awsQuery / ec2Query services. AWS
// runs the operation named by the form-body Action on a POST and the URL-query
// Action on a (legacy) GET, so classification follows the channel AWS executes
// and fails closed on any ambiguity: exactly one Action, in exactly one place.
// The method is case-normalized because req.Method is model-supplied and Go does
// not canonicalize it.
func classifyQuery(model *ServiceModel, req *http.Request) (string, error) {
	switch strings.ToUpper(req.Method) {
	case http.MethodPost:
		return classifyQueryBody(model, req)
	case http.MethodGet:
		return classifyQueryURL(model, req)
	default:
		return "", fmt.Errorf("%w: method %q not used by the query protocol", ErrClassifierUnknownOp, req.Method)
	}
}

// classifyQueryURL classifies a GET: the URL query is authoritative. Exactly one
// Action value is required (duplicates deny).
func classifyQueryURL(model *ServiceModel, req *http.Request) (string, error) {
	op, err := singleAction(req.URL.Query(), "URL query")
	if err != nil {
		return "", err
	}
	return knownOp(model, op)
}

// classifyQueryBody classifies a POST: the form body is authoritative and any
// Action in the URL query is rejected as a smuggling tell (AWS ignores it). The
// body is rewound for the downstream SigV4 signer.
func classifyQueryBody(model *ServiceModel, req *http.Request) (string, error) {
	if req.URL.Query().Has("Action") {
		return "", fmt.Errorf("%w: Action in URL query on a POST (body is authoritative)", ErrClassifierUnknownOp)
	}
	if req.Body == nil {
		return "", fmt.Errorf("%w: POST has no body", ErrClassifierUnknownOp)
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return "", fmt.Errorf("%w: read body: %w", ErrClassifierUnknownOp, err)
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	parsed, err := url.ParseQuery(string(body))
	if err != nil {
		return "", fmt.Errorf("%w: parse body: %w", ErrClassifierUnknownOp, err)
	}
	op, err := singleAction(parsed, "form body")
	if err != nil {
		return "", err
	}
	return knownOp(model, op)
}

// singleAction returns the sole non-empty Action value in vals, or an error if it
// is missing, empty, or appears more than once (parameter pollution denies).
func singleAction(vals url.Values, where string) (string, error) {
	actions := vals["Action"]
	switch {
	case len(actions) == 0:
		return "", fmt.Errorf("%w: no Action in %s", ErrClassifierUnknownOp, where)
	case len(actions) > 1:
		return "", fmt.Errorf("%w: %d Action values in %s (exactly one required)",
			ErrClassifierUnknownOp, len(actions), where)
	case actions[0] == "":
		return "", fmt.Errorf("%w: empty Action in %s", ErrClassifierUnknownOp, where)
	default:
		return actions[0], nil
	}
}

// knownOp confirms op is an operation registered in the service model.
func knownOp(model *ServiceModel, op string) (string, error) {
	if _, ok := model.Operations[op]; !ok {
		return "", fmt.Errorf("%w: Action %q not in service model", ErrClassifierUnknownOp, op)
	}
	return op, nil
}

// ClassifyOperation dispatches to the appropriate per-protocol classifier based
// on model.Protocol and returns the matched operation's short name (e.g.
// "GetObject", "PutItem", "ListUsers"). For the REST protocols the path is
// normalized via classificationPath(parsed, …) so virtual-hosted S3 requests
// (bucket in the host) match the path-style URI templates; the non-REST
// classifiers do not use parsed (S3 is the only virtual-hosted service and it is
// REST). Returns ErrClassifierUnknownOp on no match.
func ClassifyOperation(model *ServiceModel, req *http.Request, parsed ParsedHost) (string, error) {
	switch model.Protocol {
	case ProtocolRestXML, ProtocolRestJSON1:
		return classifyREST(model, req, classificationPath(parsed, req.URL.Path))
	case ProtocolAWSJSON10, ProtocolAWSJSON11:
		return classifyJSONRPC(model, req)
	case ProtocolAWSQuery, ProtocolEC2Query:
		return classifyQuery(model, req)
	case ProtocolUnknown:
		return "", fmt.Errorf("%w: unknown service protocol", ErrClassifierUnknownOp)
	default:
		return "", fmt.Errorf("%w: unsupported protocol %v", ErrClassifierUnknownOp, model.Protocol)
	}
}
