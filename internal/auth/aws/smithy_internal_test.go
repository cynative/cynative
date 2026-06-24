package aws

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseModel_s3(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.ARNNamespace != "s3" {
		t.Errorf("ARNNamespace = %q, want %q", m.ARNNamespace, "s3")
	}
	if m.EndpointPrefix != "s3" {
		t.Errorf("EndpointPrefix = %q, want %q", m.EndpointPrefix, "s3")
	}
	if m.Protocol != ProtocolRestXML {
		t.Errorf("Protocol = %v, want ProtocolRestXML", m.Protocol)
	}
	const wantOps = 5 // ListBuckets, GetObject, DeleteObject, AbortMultipartUpload, CopyObject.
	if got := len(m.Operations); got != wantOps {
		t.Errorf("Operations len = %d, want %d", got, wantOps)
	}
	if _, ok := m.Operations["ListBuckets"]; !ok {
		t.Errorf("ListBuckets missing from Operations")
	}
}

func TestParseModel_memberBoundDiscriminators(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	// Required member-bound @httpQuery / @httpHeader become discriminators;
	// optional members (RequestPayer) and @httpLabel path members do not.
	if got := m.Operations["AbortMultipartUpload"].RequiredQuery; !slices.Equal(got, []string{"uploadId"}) {
		t.Errorf("AbortMultipartUpload.RequiredQuery = %v, want [uploadId]", got)
	}
	if got := m.Operations["AbortMultipartUpload"].RequiredHeader; len(got) != 0 {
		t.Errorf("AbortMultipartUpload.RequiredHeader = %v, want [] (RequestPayer is optional)", got)
	}
	if got := m.Operations["CopyObject"].RequiredHeader; !slices.Equal(got, []string{"x-amz-copy-source"}) {
		t.Errorf("CopyObject.RequiredHeader = %v, want [x-amz-copy-source]", got)
	}
	if got := m.Operations["DeleteObject"].RequiredQuery; got != nil {
		t.Errorf("DeleteObject.RequiredQuery = %v, want nil (input is Unit)", got)
	}
}

func TestParseModel_dynamodb(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "dynamodb-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Protocol != ProtocolAWSJSON10 {
		t.Errorf("Protocol = %v, want ProtocolAWSJSON10", m.Protocol)
	}
	if _, ok := m.Operations["PutItem"]; !ok {
		t.Errorf("PutItem missing")
	}
}

func TestParseModel_unsupportedVersion(t *testing.T) {
	t.Parallel()
	_, err := ParseModel([]byte(`{"smithy":"1.0","shapes":{}}`))
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_malformedJSON(t *testing.T) {
	t.Parallel()
	_, err := ParseModel([]byte("{not-json"))
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_malformedShape(t *testing.T) {
	t.Parallel()
	_, err := ParseModel([]byte(`{"smithy":"2.0","shapes":{"foo#bar":123}}`))
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_malformedServiceTrait(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":[]}}}}`)
	_, err := ParseModel(raw)
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_noServiceShape(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"smithy":"2.0","shapes":{"x#Op":{"type":"operation"}}}`)
	_, err := ParseModel(raw)
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_unknownProtocol(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"}}}}}`,
	)
	_, err := ParseModel(raw)
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_malformedHTTPTrait(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"},"aws.protocols#restJson1":{}}},"x#Op":{"type":"operation","traits":{"smithy.api#http":"not-an-object"}}}}`,
	)
	_, err := ParseModel(raw)
	if !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("expected ErrSmithyUnavailable, got %v", err)
	}
}

func TestParseModel_protocolRestJSON1(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"},"aws.protocols#restJson1":{}}}}}`,
	)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Protocol != ProtocolRestJSON1 {
		t.Errorf("Protocol = %v, want ProtocolRestJSON1", m.Protocol)
	}
}

func TestParseModel_protocolAWSJSON11(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"},"aws.protocols#awsJson1_1":{}}}}}`,
	)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Protocol != ProtocolAWSJSON11 {
		t.Errorf("Protocol = %v, want ProtocolAWSJSON11", m.Protocol)
	}
}

func TestParseModel_protocolAWSQuery(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"},"aws.protocols#awsQuery":{}}}}}`,
	)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Protocol != ProtocolAWSQuery {
		t.Errorf("Protocol = %v, want ProtocolAWSQuery", m.Protocol)
	}
}

func TestParseModel_protocolEC2Query(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"smithy":"2.0","shapes":{"x#Svc":{"type":"service","traits":{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"x"},"aws.protocols#ec2Query":{}}}}}`,
	)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Protocol != ProtocolEC2Query {
		t.Errorf("Protocol = %v, want ProtocolEC2Query", m.Protocol)
	}
}

func TestShortName_noHash(t *testing.T) {
	t.Parallel()
	if got := shortName("noHash"); got != "noHash" {
		t.Errorf("shortName(\"noHash\") = %q, want %q", got, "noHash")
	}
}

func traitsFrom(t *testing.T, js string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatalf("traitsFrom: %v", err)
	}
	return m
}

func TestExtractEndpointPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, traits, want string
	}{
		{
			"trait wins",
			`{"aws.api#service":{"endpointPrefix":"secretsmanager","sdkId":"Secrets Manager"}}`,
			"secretsmanager",
		},
		{
			"ruleset single",
			`{"aws.api#service":{"sdkId":"MPA"},"smithy.rules#endpointRuleSet":{"rules":[{"endpoint":{"url":"https://mpa.{Region}.{PartitionResult#dualStackDnsSuffix}"}}]}}`,
			"mpa",
		},
		{
			"ruleset multi-label",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"rules":[{"endpoint":{"url":"https://access-analyzer.{Region}.amazonaws.com"}}]}}`,
			"access-analyzer",
		},
		{
			"ruleset skips fips",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"a":{"url":"https://aps-fips.{Region}.x"},"b":{"url":"https://aps.{Region}.x"}}}`,
			"aps",
		},
		{
			"ruleset global",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"url":"https://account.{PartitionResult#implicitGlobalRegion}.x"}}`,
			"account",
		},
		{"none", `{"aws.api#service":{"sdkId":"X"}}`, ""},
		// ruleset url with a path component — path is stripped before host parsing.
		{
			"ruleset url with path",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"url":"https://foo.{Region}.x/some/path"}}`,
			"foo",
		},
		// ruleset url that is not https — skipped.
		{
			"ruleset non-https skipped",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"url":"http://foo.{Region}.x"}}`,
			"",
		},
		// ruleset url whose host has no ".{" — skipped.
		{
			"ruleset no placeholder",
			`{"aws.api#service":{"sdkId":"X"},"smithy.rules#endpointRuleSet":{"url":"https://static.example.com"}}`,
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractEndpointPrefix(traitsFrom(t, tc.traits)); got != tc.want {
				t.Errorf("extractEndpointPrefix = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseModel_rejectsEmptyEndpointPrefix covers the fail-fast guard: a
// service shape with a recognized protocol but no resolvable endpoint prefix
// (no aws.api#service endpointPrefix and no endpoint ruleset) is rejected rather
// than indexed under an empty key.
func TestParseModel_rejectsEmptyEndpointPrefix(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"smithy":"2.0","shapes":{
		"com.x#Svc":{"type":"service","traits":{
			"aws.api#service":{"sdkId":"X","arnNamespace":"x"},
			"aws.protocols#awsJson1_0":{}
		}}
	}}`)
	if _, err := ParseModel(raw); !errors.Is(err, ErrSmithyUnavailable) {
		t.Errorf("ParseModel(empty prefix) err = %v, want ErrSmithyUnavailable", err)
	}
}

func TestExtractSigningName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, traits, want string
	}{
		{"sigv4 name", `{"aws.auth#sigv4":{"name":"ecr"}}`, "ecr"},
		{"sigv4 name equals prefix", `{"aws.auth#sigv4":{"name":"s3"}}`, "s3"},
		{"absent", `{"aws.api#service":{"sdkId":"X"}}`, ""},
		{"malformed (string, not object)", `{"aws.auth#sigv4":"nope"}`, ""},
		{"empty name", `{"aws.auth#sigv4":{}}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractSigningName(traitsFrom(t, tc.traits)); got != tc.want {
				t.Errorf("extractSigningName = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseModel_signingNameFromSigV4 covers a service whose SigV4 signing name
// (aws.auth#sigv4 name) differs from its endpoint prefix — the ECR shape.
func TestParseModel_signingNameFromSigV4(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"smithy":"2.0","shapes":{
		"com.amazonaws.ecr#AmazonEC2ContainerRegistry_V20150921":{"type":"service","traits":{
			"aws.api#service":{"sdkId":"ECR","arnNamespace":"ecr","endpointPrefix":"api.ecr"},
			"aws.auth#sigv4":{"name":"ecr"},
			"aws.protocols#awsJson1_1":{}
		}}
	}}`)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.EndpointPrefix != "api.ecr" {
		t.Errorf("EndpointPrefix = %q, want api.ecr", m.EndpointPrefix)
	}
	if m.SigningName != "ecr" {
		t.Errorf("SigningName = %q, want ecr", m.SigningName)
	}
}

// TestParseModel_signingNameFallsBackToEndpointPrefix covers a service with no
// aws.auth#sigv4 trait: SigningName defaults to the endpoint prefix (the common
// case where the two coincide, e.g. s3).
func TestParseModel_signingNameFallsBackToEndpointPrefix(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.SigningName != "s3" {
		t.Errorf("SigningName = %q, want s3 (fallback to endpoint prefix)", m.SigningName)
	}
}

func TestPrefixFromRuleset_invalidJSON(t *testing.T) {
	t.Parallel()
	if got := prefixFromRuleset(json.RawMessage(`not-json`)); got != "" {
		t.Errorf("prefixFromRuleset(invalid) = %q, want %q", got, "")
	}
}

func TestParseModel_sdkID(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "smithy_models", "s3-min.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := ParseModel(data)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.SDKID != "S3" {
		t.Errorf("SDKID = %q, want %q", m.SDKID, "S3")
	}
}

func TestParseModel_populatesEndpointPrefixFromRuleset(t *testing.T) {
	t.Parallel()
	// Trait omits endpointPrefix; ruleset carries the host prefix.
	raw := []byte(`{"smithy":"2.0","shapes":{
		"com.x#Svc":{"type":"service","traits":{
			"aws.api#service":{"sdkId":"Access Analyzer","arnNamespace":"access-analyzer"},
			"aws.protocols#restJson1":{},
			"smithy.rules#endpointRuleSet":{"rules":[{"endpoint":{"url":"https://access-analyzer.{Region}.amazonaws.com"}}]}
		}}
	}}`)
	m, err := ParseModel(raw)
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.EndpointPrefix != "access-analyzer" {
		t.Errorf("EndpointPrefix = %q, want access-analyzer", m.EndpointPrefix)
	}
}
