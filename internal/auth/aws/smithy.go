package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Protocol enumerates the AWS service protocols we classify against.
type Protocol int

const (
	ProtocolUnknown Protocol = iota
	ProtocolRestXML
	ProtocolRestJSON1
	ProtocolAWSJSON10
	ProtocolAWSJSON11
	ProtocolAWSQuery
	ProtocolEC2Query
)

// Operation captures the per-operation metadata classifier dispatch needs.
// For REST protocols, HTTPMethod and URITemplate are populated; for awsJson
// and awsQuery protocols, only the operation name in ServiceModel.Operations
// is consulted.
type Operation struct {
	HTTPMethod  string
	URITemplate string
	// RequiredQuery / RequiredHeader are the required member-bound @httpQuery /
	// @httpHeader discriminators (e.g. uploadId, x-amz-copy-source) that S3 uses
	// to distinguish operations sharing a (method, URI) — they are NOT in the
	// @http URI literal, so they must be matched in addition to it.
	RequiredQuery  []string
	RequiredHeader []string
}

// ServiceModel is the parsed subset of a Smithy JSON-AST that we use for
// classification.
type ServiceModel struct {
	Dir               string // resolved archive directory (set by ModelArchive).
	SDKID             string // aws.api#service sdkId (e.g. "S3 Control") — disambiguates namespace-shared services.
	ARNNamespace      string
	EndpointPrefix    string // host endpoint prefix (e.g. "api.ecr") — used for host pinning.
	SigningName       string // SigV4 signing name (e.g. "ecr") — differs from EndpointPrefix for ECR et al.
	NamespaceShadowed bool   // a different-dir model owns ARNNamespace as its endpoint prefix (set by ModelArchive).
	Protocol          Protocol
	Operations        map[string]Operation
}

// ErrSmithyUnavailable indicates a Smithy model could not be loaded.
var ErrSmithyUnavailable = errors.New("aws_hardening: smithy model unavailable")

type smithyDoc struct {
	Smithy string                     `json:"smithy"`
	Shapes map[string]json.RawMessage `json:"shapes"`
}

type smithyShape struct {
	Type   string                     `json:"type"`
	Traits map[string]json.RawMessage `json:"traits"`
	Input  struct {
		Target string `json:"target"`
	} `json:"input"` // operation shapes only.
	Members map[string]struct {
		Traits map[string]json.RawMessage `json:"traits"`
	} `json:"members"` // structure shapes only.
}

// serviceShapeType is the Smithy shape type identifying the service shape.
const serviceShapeType = "service"

type awsAPIService struct {
	SDKID          string `json:"sdkId"`
	ARNNamespace   string `json:"arnNamespace"`
	EndpointPrefix string `json:"endpointPrefix"`
}

type awsAuthSigV4 struct {
	Name string `json:"name"`
}

type smithyHTTP struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
}

// ParseModel parses raw Smithy 2.0 JSON-AST bytes into a ServiceModel.
func ParseModel(raw []byte) (*ServiceModel, error) {
	var doc smithyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrSmithyUnavailable, err)
	}
	if !strings.HasPrefix(doc.Smithy, "2.") {
		return nil, fmt.Errorf("%w: unsupported smithy version %q", ErrSmithyUnavailable, doc.Smithy)
	}

	sm := &ServiceModel{Operations: make(map[string]Operation)}
	var sawSvc bool

	for fqName, rawShape := range doc.Shapes {
		var sh smithyShape
		if err := json.Unmarshal(rawShape, &sh); err != nil {
			return nil, fmt.Errorf("%w: shape %q: %w", ErrSmithyUnavailable, fqName, err)
		}

		switch sh.Type {
		case serviceShapeType:
			if err := decodeService(sh, sm); err != nil {
				return nil, err
			}
			sawSvc = true
		case "operation":
			short := shortName(fqName)
			op := Operation{}
			if rawHTTP, ok := sh.Traits["smithy.api#http"]; ok {
				var h smithyHTTP
				if err := json.Unmarshal(rawHTTP, &h); err != nil {
					return nil, fmt.Errorf("%w: operation %q http trait: %w", ErrSmithyUnavailable, short, err)
				}
				op.HTTPMethod = h.Method
				op.URITemplate = h.URI
			}
			op.RequiredQuery, op.RequiredHeader = inputDiscriminators(doc, sh.Input.Target)
			sm.Operations[short] = op
		}
	}

	if !sawSvc {
		return nil, fmt.Errorf("%w: no service shape found", ErrSmithyUnavailable)
	}
	if sm.Protocol == ProtocolUnknown {
		return nil, fmt.Errorf("%w: service shape has no recognized protocol trait", ErrSmithyUnavailable)
	}
	if sm.EndpointPrefix == "" {
		// No endpoint prefix ⇒ no usable host pinning or signing name; reject
		// rather than index an empty-keyed model (mirrors the protocol check).
		return nil, fmt.Errorf("%w: service shape has no endpoint prefix", ErrSmithyUnavailable)
	}
	return sm, nil
}

// inputDiscriminators returns the required member-bound @httpQuery params and
// @httpHeader names of the operation input shape named by inputTarget — the
// discriminators S3 uses to route operations that share a (method, URI), and
// which are NOT present in the @http URI literal. Optional members and
// @httpLabel path members contribute none; an absent or non-structure input
// shape (e.g. smithy.api#Unit) yields no discriminators.
func inputDiscriminators(doc smithyDoc, inputTarget string) ([]string, []string) {
	var in smithyShape
	_ = json.Unmarshal(doc.Shapes[inputTarget], &in) // absent/non-struct input → no members.
	var query, header []string
	for _, m := range in.Members {
		if _, required := m.Traits["smithy.api#required"]; !required {
			continue
		}
		if name := traitName(m.Traits["smithy.api#httpQuery"]); name != "" {
			query = append(query, name)
		}
		if name := traitName(m.Traits["smithy.api#httpHeader"]); name != "" {
			header = append(header, name)
		}
	}
	return query, header
}

// traitName decodes a string-valued Smithy trait (e.g. the @httpQuery parameter
// name); returns "" when the trait is absent or not a plain string.
func traitName(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s) // absent/non-string trait → "".
	return s
}

func decodeService(sh smithyShape, sm *ServiceModel) error {
	if raw, ok := sh.Traits["aws.api#service"]; ok {
		var svc awsAPIService
		if err := json.Unmarshal(raw, &svc); err != nil {
			return fmt.Errorf("%w: aws.api#service: %w", ErrSmithyUnavailable, err)
		}
		sm.ARNNamespace = svc.ARNNamespace
		sm.SDKID = svc.SDKID
	}
	sm.EndpointPrefix = extractEndpointPrefix(sh.Traits)
	sm.SigningName = extractSigningName(sh.Traits)
	if sm.SigningName == "" {
		// Most services sign under their endpoint prefix; only a few (ECR's
		// api.ecr → ecr, etc.) declare a distinct aws.auth#sigv4 name.
		sm.SigningName = sm.EndpointPrefix
	}
	sm.Protocol = detectProtocol(sh.Traits)
	return nil
}

// extractSigningName returns the SigV4 signing name from a service shape's
// aws.auth#sigv4 trait, or "" when the trait is absent, malformed, or carries
// no name.
func extractSigningName(traits map[string]json.RawMessage) string {
	raw, ok := traits["aws.auth#sigv4"]
	if !ok {
		return ""
	}
	var sig awsAuthSigV4
	if json.Unmarshal(raw, &sig) != nil {
		return ""
	}
	return sig.Name
}

func detectProtocol(traits map[string]json.RawMessage) Protocol {
	switch {
	case has(traits, "aws.protocols#restXml"):
		return ProtocolRestXML
	case has(traits, "aws.protocols#restJson1"):
		return ProtocolRestJSON1
	case has(traits, "aws.protocols#awsJson1_0"):
		return ProtocolAWSJSON10
	case has(traits, "aws.protocols#awsJson1_1"):
		return ProtocolAWSJSON11
	case has(traits, "aws.protocols#awsQuery"):
		return ProtocolAWSQuery
	case has(traits, "aws.protocols#ec2Query"):
		return ProtocolEC2Query
	}
	return ProtocolUnknown
}

func has(m map[string]json.RawMessage, k string) bool {
	_, ok := m[k]
	return ok
}

// shortName converts "com.amazonaws.s3#ListBuckets" → "ListBuckets".
func shortName(fqName string) string {
	if i := strings.LastIndex(fqName, "#"); i >= 0 {
		return fqName[i+1:]
	}
	return fqName
}

// extractEndpointPrefix returns the host endpoint prefix for a service shape:
// the aws.api#service endpointPrefix when present, else the prefix derived from
// the endpoint ruleset URL templates. Returns "" when neither yields one.
func extractEndpointPrefix(traits map[string]json.RawMessage) string {
	if raw, ok := traits["aws.api#service"]; ok {
		var svc awsAPIService
		if json.Unmarshal(raw, &svc) == nil && svc.EndpointPrefix != "" {
			return svc.EndpointPrefix
		}
	}
	raw, ok := traits["smithy.rules#endpointRuleSet"]
	if !ok {
		return ""
	}
	return prefixFromRuleset(raw)
}

// prefixFromRuleset extracts the standard host prefix from an endpoint ruleset:
// every endpoint url template's host labels before the first "{" placeholder,
// excluding FIPS variants, shortest-then-lexical for determinism.
func prefixFromRuleset(raw json.RawMessage) string {
	var node any
	if json.Unmarshal(raw, &node) != nil {
		return ""
	}
	var urls []string
	collectURLs(node, &urls)
	var best string
	for _, u := range urls {
		const scheme = "https://"
		if !strings.HasPrefix(u, scheme) {
			continue
		}
		host := u[len(scheme):]
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		cand, _, ok := strings.Cut(host, ".{")
		if !ok {
			continue
		}
		if cand == "" || strings.Contains(cand, "{") || strings.Contains(strings.ToLower(cand), "fips") {
			continue
		}
		if best == "" || len(cand) < len(best) || (len(cand) == len(best) && cand < best) {
			best = cand
		}
	}
	return best
}

// collectURLs walks a decoded JSON tree appending every string value found
// under a "url" key.
func collectURLs(node any, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if k == "url" {
				if s, ok := val.(string); ok {
					*out = append(*out, s)
				}
			}
			collectURLs(val, out)
		}
	case []any:
		for _, e := range v {
			collectURLs(e, out)
		}
	}
}
