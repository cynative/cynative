package aws_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/aws"
)

func docModel(t *testing.T, file string) *aws.DocModel {
	t.Helper()
	raw, err := os.ReadFile("testdata/smithy_docs/" + file)
	if err != nil {
		t.Fatal(err)
	}
	m, err := aws.ParseDocModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func inputNamed(ref *apiref.Reference, name string) (apiref.Input, bool) {
	for _, in := range ref.Inputs {
		if in.Name == name {
			return in, true
		}
	}
	return apiref.Input{}, false
}

// exModel builds service "ex" (endpoint prefix ex) speaking protocol (a trait name such as
// "aws.protocols#restJson1") with one operation Op at uri, the given input and output member lists (JSON object
// bodies without braces) and fixed helper shapes.
func exModel(protocol, uri, inMembers, outMembers string) string {
	return `{"smithy":"2.0","shapes":{
	"ex#Svc":{"type":"service","version":"2020-01-01","traits":{
		"aws.api#service":{"sdkId":"Ex","endpointPrefix":"ex"},"` + protocol + `":{}}},
	"ex#Op":{"type":"operation","input":{"target":"ex#OpIn"},"output":{"target":"ex#OpOut"},
		"traits":{"smithy.api#http":{"method":"POST","uri":"` + uri + `"}}},
	"ex#OpIn":{"type":"structure","members":{` + inMembers + `}},
	"ex#OpOut":{"type":"structure","members":{` + outMembers + `}},
	"ex#IdList":{"type":"list","member":{"target":"smithy.api#String"}},
	"ex#Flat":{"type":"list","member":{"target":"smithy.api#String"}},
	"ex#Str":{"type":"string"},
	"ex#Stream":{"type":"string","traits":{"smithy.api#streaming":{}}},
	"ex#Blob":{"type":"blob","traits":{"smithy.api#streaming":{}}}}}`
}

func restJSONModel(inMembers, outMembers string) string {
	return exModel("aws.protocols#restJson1", "/op", inMembers, outMembers)
}

func restXMLModel(inMembers string) string {
	return exModel("aws.protocols#restXml", "/op", inMembers, "")
}

func exRef(t *testing.T, model string) *apiref.Reference {
	t.Helper()
	m, err := aws.ParseDocModel([]byte(model))
	if err != nil {
		t.Fatal(err)
	}
	return m.Reference("ex", "ex", "Op")
}

func TestDocReference_Route53ListHostedZones(t *testing.T) {
	t.Parallel()

	m := docModel(t, "route-53.json")
	if m.Protocol() != aws.ProtocolRestXML || !m.HasOperation("ListHostedZones") || m.HasOperation("Nope") {
		t.Fatalf("protocol %v, ops %v", m.Protocol(), m.HasOperation("ListHostedZones"))
	}
	if names := m.OperationNames(); !slices.IsSorted(names) || !slices.Contains(names, "ListHostedZones") {
		t.Errorf("names = %v", names)
	}
	ref := m.Reference("route53", "route-53", "ListHostedZones")
	checks := map[string][2]string{
		"protocol": {ref.Protocol, "restXml"},
		"method":   {ref.Method, "GET"},
		"path":     {ref.PathTemplate, "/2013-04-01/hostedzone"},
		"version":  {ref.APIVersion, "2013-04-01"},
		"endpoint": {ref.Endpoint, "https://route53.amazonaws.com"},
		"auth":     {ref.AuthArgs["service"], "route53"},
		"field":    {ref.AuthField, "aws_auth"},
		"body":     {string(ref.BodyEncoding), "none"},
		"encoding": {ref.Response.Encoding, "xml"},
		"page.in":  {ref.Pagination.InputToken, "Marker"},
		"page.out": {ref.Pagination.OutputToken, "NextMarker"},
		"items":    {ref.Pagination.Items, "HostedZones"},
	}
	for k, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", k, v[0], v[1])
		}
	}
	in, ok := inputNamed(ref, "MaxItems")
	if !ok || in.Location != apiref.LocationQuery || in.WireName != "maxitems" || in.Required {
		t.Errorf("MaxItems input = %+v", in)
	}
	for _, want := range []string{
		"xml.parse(response.body)", "IsTruncated === 'true'",
		"HostedZones.HostedZone", "x == null ? [] : [].concat(x)", "ListHostedZonesResponse",
	} {
		if !strings.Contains(ref.Response.Parse, want) {
			t.Errorf("parse guidance missing %q: %s", want, ref.Response.Parse)
		}
	}
	if apiref.OutcomeOf(ref) != apiref.OutcomeFound {
		t.Errorf("gaps: %q", ref.Gaps)
	}
	if ref.Summary == "" || strings.Contains(ref.Summary, "<") {
		t.Errorf("summary = %q", ref.Summary)
	}
}

func TestDocReference_IAMListRoles(t *testing.T) {
	t.Parallel()

	ref := docModel(t, "iam.json").Reference("iam", "iam", "ListRoles")
	if ref.Protocol != "awsQuery" || ref.Method != http.MethodPost || ref.PathTemplate != "/" {
		t.Fatalf("shape = %s %s %s", ref.Protocol, ref.Method, ref.PathTemplate)
	}
	if ref.Endpoint != "https://iam.amazonaws.com" || ref.BodyEncoding != apiref.BodyForm {
		t.Errorf("endpoint %q body %q", ref.Endpoint, ref.BodyEncoding)
	}
	wantForm := []apiref.Param{{Key: "Action", Value: "ListRoles"}, {Key: "Version", Value: "2010-05-08"}}
	if !slices.Equal(ref.FixedForm, wantForm) {
		t.Errorf("form = %+v", ref.FixedForm)
	}
	wantHdr := []apiref.Param{{Key: "Content-Type", Value: "application/x-www-form-urlencoded; charset=utf-8"}}
	if !slices.Equal(ref.FixedHeaders, wantHdr) {
		t.Errorf("headers = %+v", ref.FixedHeaders)
	}
	for _, want := range []string{"ListRolesResponse.ListRolesResult", "Roles.member", "IsTruncated === 'true'"} {
		if !strings.Contains(ref.Response.Parse, want) {
			t.Errorf("parse guidance missing %q: %s", want, ref.Response.Parse)
		}
	}
	if ref.Pagination.InputToken != "Marker" || ref.Pagination.Items != "Roles" {
		t.Errorf("pagination = %+v", ref.Pagination)
	}
}

func TestDocReference_IAMDeleteRoleEnvelope(t *testing.T) {
	t.Parallel()

	ref := docModel(t, "iam.json").Reference("iam", "iam", "DeleteRole")
	in, ok := inputNamed(ref, "RoleName")
	if !ok || !in.Required || !in.Renderable || in.Location != apiref.LocationBody {
		t.Errorf("RoleName = %+v", in)
	}
	if !strings.Contains(ref.Response.Parse, "DeleteRoleResponse") ||
		!strings.Contains(ref.Response.Parse, "ResponseMetadata") {
		t.Errorf("envelope guidance = %q", ref.Response.Parse)
	}
	if ref.Pagination.Style != apiref.PaginationUnspecified {
		t.Errorf("pagination = %+v", ref.Pagination)
	}
}

func TestDocReference_DynamoDBDescribeTable(t *testing.T) {
	t.Parallel()

	ref := docModel(t, "dynamodb.json").Reference("dynamodb", "dynamodb", "DescribeTable")
	if ref.Protocol != "awsJson1_0" || ref.BodyEncoding != apiref.BodyJSON {
		t.Fatalf("protocol %q body %q", ref.Protocol, ref.BodyEncoding)
	}
	if !slices.Contains(
		ref.FixedHeaders,
		apiref.Param{Key: "X-Amz-Target", Value: "DynamoDB_20120810.DescribeTable"},
	) ||
		!slices.Contains(ref.FixedHeaders, apiref.Param{Key: "Content-Type", Value: "application/x-amz-json-1.0"}) {
		t.Errorf("headers = %+v", ref.FixedHeaders)
	}
	if !strings.HasPrefix(ref.Endpoint, "https://dynamodb.") {
		t.Errorf("endpoint = %q", ref.Endpoint)
	}
	if ref.Response.Encoding != "json" {
		t.Errorf("encoding = %q", ref.Response.Encoding)
	}
}

func TestDocReference_RegionalEndpointLimitation(t *testing.T) {
	t.Parallel()

	// dynamodb has no literal https://dynamodb.amazonaws.com URL in its ruleset.
	ref := docModel(t, "dynamodb.json").Reference("dynamodb", "dynamodb", "ListTables")
	if ref.Endpoint != "https://dynamodb.<region>.amazonaws.com" {
		t.Errorf("endpoint = %q", ref.Endpoint)
	}
	if !slices.ContainsFunc(ref.Limitations, func(s string) bool { return strings.Contains(s, "FIPS") }) {
		t.Errorf("limitations = %q", ref.Limitations)
	}
}

func TestDocReference_IncompleteCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		model   string
		wantGap string
	}{
		{
			"required list input",
			restJSONModel(`"Ids":{"target":"ex#IdList","traits":{"smithy.api#required":{}}}`, ""), "Ids",
		},
		{
			"required timestamp input",
			restJSONModel(`"At":{"target":"smithy.api#Timestamp","traits":{"smithy.api#required":{}}}`, ""), "At",
		},
		{
			"required payload input",
			restJSONModel(`"Doc":{"target":"smithy.api#String","traits":{"smithy.api#required":{},`+
				`"smithy.api#httpPayload":{}}}`, ""), "Doc",
		},
		{
			"raw payload output",
			restJSONModel("", `"Body":{"target":"ex#Blob","traits":{"smithy.api#httpPayload":{}}}`), "raw payload",
		},
		{
			"streaming without httpPayload",
			restJSONModel("", `"Body":{"target":"ex#Stream"}`), "raw payload",
		},
		{
			"restXml body member",
			restXMLModel(`"Name":{"target":"smithy.api#String","traits":{"smithy.api#required":{}}}`), "Name",
		},
		{
			"unknown member type",
			restJSONModel(`"X":{"target":"ex#Missing","traits":{"smithy.api#required":{}}}`, ""), "X",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ref := exRef(t, c.model)
			if apiref.OutcomeOf(ref) != apiref.OutcomeIncomplete ||
				!slices.ContainsFunc(ref.Gaps, func(g string) bool { return strings.Contains(g, c.wantGap) }) {
				t.Errorf("gaps = %q", ref.Gaps)
			}
		})
	}
}

func optionalMembers(n int) string {
	parts := make([]string, 0, n)
	for i := range n {
		parts = append(parts, fmt.Sprintf(`"O%02d":{"target":"smithy.api#String"}`, i))
	}
	return strings.Join(parts, ",")
}

func TestDocReference_RequestRendering(t *testing.T) {
	t.Parallel()

	param := func(k, v string) apiref.Param { return apiref.Param{Key: k, Value: v} }
	cases := []struct {
		name  string
		model string
		check func(t *testing.T, ref *apiref.Reference)
	}{
		{
			"restJson1 scalar body with jsonName",
			restJSONModel(`"Name":{"target":"smithy.api#String","traits":{"smithy.api#required":{},`+
				`"smithy.api#jsonName":"name"}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "Name")
				if in.WireName != "name" || in.Location != apiref.LocationBody || !in.Renderable ||
					ref.BodyEncoding != apiref.BodyJSON ||
					!slices.Contains(ref.FixedHeaders, param("Content-Type", "application/json")) ||
					apiref.OutcomeOf(ref) != apiref.OutcomeFound {
					t.Errorf("ref = %+v", ref)
				}
			},
		},
		{
			"awsJson1_1",
			exModel("aws.protocols#awsJson1_1", "/", "", ""),
			func(t *testing.T, ref *apiref.Reference) {
				if !slices.Contains(ref.FixedHeaders, param("Content-Type", "application/x-amz-json-1.1")) ||
					!slices.Contains(ref.FixedHeaders, param("X-Amz-Target", "Svc.Op")) {
					t.Errorf("headers = %+v", ref.FixedHeaders)
				}
			},
		},
		{
			"required header input",
			restJSONModel(`"Tok":{"target":"smithy.api#String","traits":{"smithy.api#required":{},`+
				`"smithy.api#httpHeader":"x-tok"}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "Tok")
				if in.Location != apiref.LocationHeader || in.WireName != "x-tok" {
					t.Errorf("Tok = %+v", in)
				}
			},
		},
		{
			"path label",
			exModel("aws.protocols#restJson1", "/op/{Id}", `"Id":{"target":"smithy.api#String","traits":`+
				`{"smithy.api#required":{},"smithy.api#httpLabel":{}}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "Id")
				if in.Location != apiref.LocationPath || ref.PathTemplate != "/op/{Id}" {
					t.Errorf("Id = %+v, path %q", in, ref.PathTemplate)
				}
			},
		},
		{
			"fixed URI query",
			exModel("aws.protocols#restJson1", "/op?list-type=2&x-id=Op&flag&", "", ""),
			func(t *testing.T, ref *apiref.Reference) {
				want := []apiref.Param{param("list-type", "2"), param("flag", "")}
				if !slices.Equal(ref.FixedQuery, want) || ref.PathTemplate != "/op" {
					t.Errorf("query %+v path %q", ref.FixedQuery, ref.PathTemplate)
				}
			},
		},
		{
			"awsQuery xmlName",
			exModel("aws.protocols#awsQuery", "/", `"Name":{"target":"smithy.api#String","traits":`+
				`{"smithy.api#required":{},"smithy.api#xmlName":"RoleName"}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "Name")
				if in.WireName != "RoleName" {
					t.Errorf("Name = %+v", in)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			c.check(t, exRef(t, c.model))
		})
	}
}

func TestDocReference_InputTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		model string
		check func(t *testing.T, ref *apiref.Reference)
	}{
		{
			"optional input cap",
			restJSONModel(optionalMembers(30), ""),
			func(t *testing.T, ref *apiref.Reference) {
				if len(ref.Inputs) != apiref.MaxOptionalInputs || !ref.InputsTruncated {
					t.Errorf("inputs %d truncated %v", len(ref.Inputs), ref.InputsTruncated)
				}
			},
		},
		{
			"primitive prelude",
			restJSONModel(`"N":{"target":"smithy.api#PrimitiveInteger","traits":{"smithy.api#required":{}}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "N")
				if in.Type != "integer" || !in.Renderable {
					t.Errorf("N = %+v", in)
				}
			},
		},
		{
			"unknown member type is unrenderable",
			restJSONModel(`"X":{"target":"ex#Missing","traits":{"smithy.api#required":{}}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "X")
				if in.Type != "unknown" || in.Renderable {
					t.Errorf("X = %+v", in)
				}
			},
		},
		{
			"query-bound input uses its wire name and a defined shape type",
			restJSONModel(`"Q":{"target":"ex#Str","traits":{"smithy.api#httpQuery":"q"}}`, ""),
			func(t *testing.T, ref *apiref.Reference) {
				in, _ := inputNamed(ref, "Q")
				if in.Location != apiref.LocationQuery || in.WireName != "q" || in.Type != "string" || !in.Renderable {
					t.Errorf("Q = %+v", in)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			c.check(t, exRef(t, c.model))
		})
	}
}

func TestDocReference_ResponseRendering(t *testing.T) {
	t.Parallel()

	unitOut := strings.Replace(restJSONModel("", ""), `"output":{"target":"ex#OpOut"}`,
		`"output":{"target":"smithy.api#Unit"}`, 1)
	cases := []struct {
		name  string
		model string
		check func(t *testing.T, ref *apiref.Reference)
	}{
		{
			"flattened XML list",
			exModel("aws.protocols#restXml", "/op", "", `"Items":{"target":"ex#Flat","traits":`+
				`{"smithy.api#xmlFlattened":{}}}`),
			func(t *testing.T, ref *apiref.Reference) {
				if !strings.Contains(ref.Response.Parse, "List Items: Items;") ||
					strings.Contains(ref.Response.Parse, ".member") {
					t.Errorf("parse = %q", ref.Response.Parse)
				}
			},
		},
		{
			"XML scalar output is not a list",
			exModel("aws.protocols#restXml", "/op", "", `"Name":{"target":"ex#Str"}`),
			func(t *testing.T, ref *apiref.Reference) {
				if ref.Response.Encoding != "xml" || strings.Contains(ref.Response.Parse, "List ") ||
					!strings.Contains(ref.Response.Parse, "Result element: OpOut.") {
					t.Errorf("response = %+v", ref.Response)
				}
			},
		},
		{
			"XML output xmlName root",
			strings.Replace(
				exModel("aws.protocols#restXml", "/op", "", `"Name":{"target":"ex#Str"}`),
				`"ex#OpOut":{"type":"structure",`,
				`"ex#OpOut":{"type":"structure","traits":{"smithy.api#xmlName":"Custom"},`,
				1,
			),
			func(t *testing.T, ref *apiref.Reference) {
				if !strings.Contains(ref.Response.Parse, "Result element: Custom.") {
					t.Errorf("parse = %q", ref.Response.Parse)
				}
			},
		},
		{
			"no-body REST response",
			restJSONModel("", `"ETag":{"target":"smithy.api#String","traits":{"smithy.api#httpHeader":"ETag"}}`),
			func(t *testing.T, ref *apiref.Reference) {
				if ref.Response.Encoding != "none" {
					t.Errorf("response = %+v", ref.Response)
				}
			},
		},
		{
			"Unit output",
			unitOut,
			func(t *testing.T, ref *apiref.Reference) {
				if ref.Response.Encoding != "none" {
					t.Errorf("response = %+v", ref.Response)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			c.check(t, exRef(t, c.model))
		})
	}
}

func pageModel(svcTrait, opTrait string) string {
	svc, op := "", ""
	if svcTrait != "" {
		svc = `,"smithy.api#paginated":` + svcTrait
	}
	if opTrait != "" {
		op = `,"smithy.api#paginated":` + opTrait
	}
	return `{"smithy":"2.0","shapes":{
	"ex#Svc":{"type":"service","version":"2020-01-01","traits":{
		"aws.api#service":{"sdkId":"Ex","endpointPrefix":"ex"},"aws.protocols#restJson1":{}` + svc + `}},
	"ex#Op":{"type":"operation","input":{"target":"ex#OpIn"},"output":{"target":"ex#OpOut"},
		"traits":{"smithy.api#http":{"method":"GET","uri":"/op"}` + op + `}},
	"ex#OpIn":{"type":"structure","members":{}},
	"ex#OpOut":{"type":"structure","members":{}},
	"ex#IdList":{"type":"list","member":{"target":"smithy.api#String"}},
	"ex#Str":{"type":"string"}}}`
}

func TestDocReference_PaginationMerge(t *testing.T) {
	t.Parallel()

	svc := `{"inputToken":"NextToken","outputToken":"NextToken","pageSize":"MaxResults"}`
	cases := []struct {
		name  string
		model string
		want  apiref.Pagination
	}{
		{
			"items from the operation",
			pageModel(svc, `{"items":"Things"}`),
			apiref.Pagination{
				Style:       "token",
				InputToken:  "NextToken",
				OutputToken: "NextToken",
				Items:       "Things",
				PageSize:    "MaxResults",
			},
		},
		{
			"no trait is unspecified", pageModel(svc, ""),
			apiref.Pagination{Style: apiref.PaginationUnspecified},
		},
		{
			"operation overrides the input token", pageModel(svc, `{"inputToken":"Cursor"}`),
			apiref.Pagination{
				Style: "token", InputToken: "Cursor", OutputToken: "NextToken", PageSize: "MaxResults",
			},
		},
		{
			"no service trait", pageModel("", `{"inputToken":"A","outputToken":"B"}`),
			apiref.Pagination{Style: "token", InputToken: "A", OutputToken: "B"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got := exRef(t, c.model).Pagination; got != c.want {
				t.Errorf("pagination = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParseDocModel_Errors(t *testing.T) {
	t.Parallel()

	svc := func(extra string) string {
		return `{"smithy":"2.0","shapes":{"ex#Svc":{"type":"service","traits":{` + extra + `}}}}`
	}
	cases := map[string]string{
		"invalid json":     `{`,
		"old smithy":       `{"smithy":"1.0","shapes":{}}`,
		"no service":       `{"smithy":"2.0","shapes":{}}`,
		"shape not object": `{"smithy":"2.0","shapes":{"ex#X":3}}`,
		"bad service":      svc(`"aws.api#service":"x"`),
		"no prefix":        svc(`"aws.protocols#restJson1":{}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := aws.ParseDocModel([]byte(raw))
			if !errors.Is(err, aws.ErrSmithyUnavailable) || m != nil {
				t.Errorf("model %v, err %v", m, err)
			}
		})
	}
}

func TestProtocolNameAndDocSupported(t *testing.T) {
	t.Parallel()

	cases := []struct {
		p         aws.Protocol
		name      string
		supported bool
	}{
		{aws.ProtocolRestXML, "restXml", true},
		{aws.ProtocolRestJSON1, "restJson1", true},
		{aws.ProtocolAWSJSON10, "awsJson1_0", true},
		{aws.ProtocolAWSJSON11, "awsJson1_1", true},
		{aws.ProtocolAWSQuery, "awsQuery", true},
		{aws.ProtocolEC2Query, "ec2Query", false},
		{aws.ProtocolUnknown, "unknown", false},
		{aws.Protocol(99), "unknown", false},
	}
	for _, c := range cases {
		if got := aws.ProtocolName(c.p); got != c.name {
			t.Errorf("ProtocolName(%d) = %q, want %q", c.p, got, c.name)
		}
		if got := aws.DocSupported(c.p); got != c.supported {
			t.Errorf("DocSupported(%d) = %v, want %v", c.p, got, c.supported)
		}
	}
}

func withDistShapes(model string) string {
	return strings.Replace(model, `"ex#Str":`, distShapes+`,"ex#Str":`, 1)
}

const distShapes = `"ex#DistList":{"type":"structure","members":{"Items":{"target":"ex#ItemList"}}},` +
	`"ex#ItemList":{"type":"list","member":{"target":"smithy.api#String","traits":{"smithy.api#xmlName":"Item"}}},` +
	`"ex#Doc":{"type":"document"}`

func TestDocReference_Payloads(t *testing.T) {
	t.Parallel()

	payload := func(target string) string {
		return `"Dist":{"target":"` + target + `","traits":{"smithy.api#httpPayload":{}}}`
	}
	cases := []struct {
		name         string
		model        string
		wantEncoding string
		wantParse    []string
		wantFound    bool
	}{
		{
			"restXml structure payload",
			withDistShapes(exModel("aws.protocols#restXml", "/op", "", payload("ex#DistList"))),
			"xml",
			[]string{"Result element: DistList.", "List Items: Items.Item"},
			true,
		},
		{
			"restXml payload member xmlName wins",
			withDistShapes(exModel("aws.protocols#restXml", "/op", "", strings.Replace(payload("ex#DistList"),
				`"traits":{`, `"traits":{"smithy.api#xmlName":"Root",`, 1))),
			"xml",
			[]string{"Result element: Root."},
			true,
		},
		{
			"restXml target xmlName",
			strings.Replace(withDistShapes(exModel("aws.protocols#restXml", "/op", "", payload("ex#DistList"))),
				`"ex#DistList":{"type":"structure",`,
				`"ex#DistList":{"type":"structure","traits":{"smithy.api#xmlName":"Dist"},`, 1),
			"xml",
			[]string{"Result element: Dist."},
			true,
		},
		{
			"restJson1 structure payload",
			withDistShapes(exModel("aws.protocols#restJson1", "/op", "", payload("ex#DistList"))),
			"json",
			[]string{"JSON.parse(response.body)"},
			true,
		},
		{
			"string payload is raw",
			restJSONModel("", payload("ex#Str")),
			"raw", nil, false,
		},
		{
			"document payload is raw",
			withDistShapes(restJSONModel("", payload("ex#Doc"))),
			"raw", nil, false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ref := exRef(t, c.model)
			if ref.Response.Encoding != c.wantEncoding ||
				(apiref.OutcomeOf(ref) == apiref.OutcomeFound) != c.wantFound {
				t.Fatalf("response %+v gaps %q", ref.Response, ref.Gaps)
			}
			for _, want := range c.wantParse {
				if !strings.Contains(ref.Response.Parse, want) {
					t.Errorf("parse missing %q: %s", want, ref.Response.Parse)
				}
			}
		})
	}
}

func TestDocReference_BoundMaps(t *testing.T) {
	t.Parallel()

	ref := exRef(t, restJSONModel(`"Q":{"target":"ex#Str","traits":{"smithy.api#required":{},`+
		`"smithy.api#httpQueryParams":{}}},"H":{"target":"ex#Str","traits":{"smithy.api#required":{},`+
		`"smithy.api#httpPrefixHeaders":"x-meta-"}}`, ""))
	q, _ := inputNamed(ref, "Q")
	h, _ := inputNamed(ref, "H")
	if q.Location != apiref.LocationQuery || q.Renderable || h.Location != apiref.LocationHeader || h.Renderable {
		t.Errorf("Q = %+v, H = %+v", q, h)
	}
	if ref.BodyEncoding != apiref.BodyNone || len(ref.FixedHeaders) != 0 {
		t.Errorf("body %q headers %+v", ref.BodyEncoding, ref.FixedHeaders)
	}
}

func TestDocReference_IntEnumInput(t *testing.T) {
	t.Parallel()

	model := strings.Replace(restJSONModel(`"E":{"target":"ex#Level","traits":{"smithy.api#required":{}}}`, ""),
		`"ex#Str":`, `"ex#Level":{"type":"intEnum"},"ex#Str":`, 1)
	in, _ := inputNamed(exRef(t, model), "E")
	if in.Type != "intEnum" || !in.Renderable {
		t.Errorf("E = %+v", in)
	}
}

func TestDocReference_UnsupportedProtocolHasNoWireForm(t *testing.T) {
	t.Parallel()

	// Reference is only called for supported protocols; an unsupported one must still yield no wire form
	// rather than a guessed one.
	ref := exRef(t, exModel("aws.protocols#ec2Query", "/", "", ""))
	if ref.Method != "" || ref.PathTemplate != "" || ref.BodyEncoding != apiref.BodyNone || len(ref.FixedHeaders) != 0 {
		t.Errorf("ref = %+v", ref)
	}
}

// endpointModel is service "ex" whose ruleset carries the given URLs and whose operation carries opTraits
// (extra JSON members of the operation traits, with a leading comma).
func endpointModel(urls []string, opTraits, inMembers string) string {
	var rules []string
	for _, u := range urls {
		rules = append(rules, `{"endpoint":{"url":"`+u+`"}}`)
	}
	return `{"smithy":"2.0","shapes":{
	"ex#Svc":{"type":"service","version":"2020-01-01","traits":{
		"aws.api#service":{"sdkId":"Ex","endpointPrefix":"ex"},"aws.protocols#restXml":{},
		"smithy.rules#endpointRuleSet":{"rules":[` + strings.Join(rules, ",") + `]}}},
	"ex#Op":{"type":"operation","input":{"target":"ex#OpIn"},"output":{"target":"ex#OpOut"},
		"traits":{"smithy.api#http":{"method":"GET","uri":"/op"}` + opTraits + `}},
	"ex#OpIn":{"type":"structure","members":{` + inMembers + `}},
	"ex#OpOut":{"type":"structure","members":{}},
	"ex#IdList":{"type":"list","member":{"target":"smithy.api#String"}},
	"ex#Str":{"type":"string"}}}`
}

func TestDocReference_EndpointPrefersRegionalTemplate(t *testing.T) {
	t.Parallel()

	both := []string{"https://ex.amazonaws.com", "https://ex.{Region}.{PartitionResult#dnsSuffix}"}
	ref := exRef(t, endpointModel(both, "", ""))
	if ref.Endpoint != "https://ex.<region>.amazonaws.com" {
		t.Errorf("endpoint = %q", ref.Endpoint)
	}
	if !slices.ContainsFunc(ref.Limitations, func(s string) bool { return strings.Contains(s, "FIPS") }) {
		t.Errorf("limitations = %q", ref.Limitations)
	}

	global := exRef(t, endpointModel([]string{"https://ex.amazonaws.com"}, "", ""))
	if global.Endpoint != "https://ex.amazonaws.com" || len(global.Limitations) != 0 {
		t.Errorf("global = %q %q", global.Endpoint, global.Limitations)
	}
}

func TestDocReference_HostPrefix(t *testing.T) {
	t.Parallel()

	urls := []string{"https://ex.{Region}.amazonaws.com"}
	acct := `"AccountId":{"target":"ex#Str","traits":{"smithy.api#hostLabel":{},"smithy.api#required":{},` +
		`"smithy.api#httpHeader":"x-amz-account-id"}}`
	cases := []struct {
		name, traits, members, want string
	}{
		{"none", "", acct, "https://ex.<region>.amazonaws.com"},
		{
			"rendered", `,"smithy.api#endpoint":{"hostPrefix":"{AccountId}."}`, acct,
			"https://<AccountId>.ex.<region>.amazonaws.com",
		},
		{
			"unrendered", `,"smithy.api#endpoint":{"hostPrefix":"{AccountId}."}`,
			`"AccountId":{"target":"ex#IdList","traits":{"smithy.api#hostLabel":{}}}`,
			"https://<AccountId:unrendered>.ex.<region>.amazonaws.com",
		},
		{
			"undeclared label and literal", `,"smithy.api#endpoint":{"hostPrefix":"pre-{Nope}.x"}`, "",
			"https://pre-<Nope:unrendered>.xex.<region>.amazonaws.com",
		},
		{
			"unclosed brace", `,"smithy.api#endpoint":{"hostPrefix":"a{b"}`, "",
			"https://a{bex.<region>.amazonaws.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ref := exRef(t, endpointModel(urls, tc.traits, tc.members))
			if ref.Endpoint != tc.want {
				t.Errorf("endpoint = %q, want %q", ref.Endpoint, tc.want)
			}
		})
	}

	ref := exRef(t, endpointModel(urls, `,"smithy.api#endpoint":{"hostPrefix":"{AccountId}."}`, acct))
	if in, ok := inputNamed(ref, "AccountId"); !ok || in.Location != apiref.LocationHeader {
		t.Errorf("AccountId input = %+v, %v", in, ok)
	}
}
