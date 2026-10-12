package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

const renderCommon = `{"parameters":{
	"ApiVersionParameter":{"name":"api-version","in":"query","required":true,"type":"string"},
	"SubscriptionIdParameter":{"name":"subscriptionId","in":"path","required":true,"type":"string"}}}`

// commonRef is the ref from testOpFile to the common-types parameters.
const commonRef = "../../../../../../common-types/resource-management/v5/types.json#/parameters/"

// renderOne renders the operation at method and key of a fixture file whose paths, x-ms-paths, parameters and
// definitions are the given JSON members.
func renderOne(t *testing.T, version, members, method, key string, xms bool) *apiref.Reference {
	t.Helper()
	ref, err := renderFixture(t, version, members, method, key, xms, NewBudget(1<<20))
	if err != nil {
		t.Fatalf("renderOperation: %v", err)
	}

	return ref
}

func renderFixture(
	t *testing.T, version, members, method, key string, xms bool, b *Budget,
) (*apiref.Reference, error) {
	t.Helper()
	body := `{"info":{"version":"` + version + `"},` + members + `}`
	doc, err := decodeSwagger([]byte(body))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	files := newSpecFakeFiles(map[string]string{commonFile: renderCommon})
	r := newRefResolver(files, refIndex(testOpFile, commonFile), b)

	return renderOperation(context.Background(), renderInput{
		Doc: doc, File: IndexFile{Path: testOpFile, Blob: fmt.Sprintf("%040x", 1)},
		Dir: IndexDir{Kind: kindStable, Name: "2024-01-01"}, Group: "test/Test",
		Op: OpSummary{ID: "Op_Id", Method: method, Path: key, XMs: xms}, Commit: specTestSHA,
		Endpoint: "https://management.azure.com", Service: "Microsoft.Test", SHA256: "feed",
		Selector: "test/Test@stable/2024-01-01", Resolver: r,
	})
}

// op builds one operation member: {"<key>":{"<method>":{"operationId":"Op_Id",<extra>,"parameters":[<params>]}}}.
func op(key, method, extra string, params ...string) string {
	if extra != "" {
		extra += ","
	}

	return fmt.Sprintf(`{%q:{%q:{"operationId":"Op_Id",%s"parameters":[%s]}}}`, key, method, extra,
		strings.Join(params, ","))
}

const (
	pSub      = `{"$ref":"` + commonRef + `SubscriptionIdParameter"}`
	pVersion  = `{"$ref":"` + commonRef + `ApiVersionParameter"}`
	thingsKey = "/subscriptions/{subscriptionId}/providers/Microsoft.Test/things"
)

func fixed(ref *apiref.Reference) string { return fmt.Sprint(ref.FixedQuery) }

func hasLimitation(ref *apiref.Reference, part string) bool {
	return slices.ContainsFunc(ref.Limitations, func(l string) bool { return strings.Contains(l, part) })
}

func hasGap(ref *apiref.Reference, part string) bool {
	return slices.ContainsFunc(ref.Gaps, func(g string) bool { return strings.Contains(g, part) })
}

func TestRenderOperation_Basics(t *testing.T) {
	t.Parallel()
	ref := renderOne(t, "2024-01-01", `"paths":`+op(thingsKey, "get",
		`"summary":"<b>List</b> things","x-ms-pageable":{"nextLinkName":"nextLink"}`, pSub, pVersion), "GET",
		thingsKey, false)
	want := apiref.Reference{
		Connector: "azure", Service: "Microsoft.Test", Model: "test/Test@stable/2024-01-01", Operation: "Op_Id",
		Protocol: "rest-json", Method: "GET", PathTemplate: thingsKey, APIVersion: "2024-01-01",
		Summary: "List things", Endpoint: "https://management.azure.com", BodyEncoding: apiref.BodyNone,
	}
	if ref.Connector != want.Connector || ref.Service != want.Service || ref.Model != want.Model ||
		ref.Operation != want.Operation || ref.Protocol != want.Protocol || ref.Method != want.Method ||
		ref.PathTemplate != want.PathTemplate || ref.APIVersion != want.APIVersion || ref.Summary != want.Summary ||
		ref.Endpoint != want.Endpoint || ref.BodyEncoding != want.BodyEncoding {
		t.Fatalf("reference = %+v", ref)
	}
	if fixed(ref) != "[{api-version 2024-01-01}]" || ref.AuthField != "azure_auth" ||
		ref.AuthArgs["service"] != "Microsoft.Test" {
		t.Errorf("fixed %s, auth %s %v", fixed(ref), ref.AuthField, ref.AuthArgs)
	}
	if ref.Source != (apiref.Source{
		Name:     "Azure/azure-rest-api-specs",
		Document: testOpFile + " (info.version 2024-01-01)", Version: specTestSHA, SHA256: "feed",
	}) {
		t.Errorf("source = %+v", ref.Source)
	}
	if ref.Pagination != (apiref.Pagination{Style: "next-link", OutputToken: "nextLink", Items: "value"}) ||
		!hasLimitation(ref, "nextLink URL") || !hasLimitation(ref, "published in Azure/azure-rest-api-specs") {
		t.Errorf("pagination %+v, limitations %q", ref.Pagination, ref.Limitations)
	}
	if len(ref.Inputs) != 1 || ref.Inputs[0].Name != "subscriptionId" || !ref.Inputs[0].Required ||
		ref.Inputs[0].Location != apiref.LocationPath || len(ref.Gaps) != 0 {
		t.Errorf("inputs %+v, gaps %q", ref.Inputs, ref.Gaps)
	}
	if ref.Response != (apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}) {
		t.Errorf("response = %+v", ref.Response)
	}
}

func TestRenderOperation_APIVersion(t *testing.T) {
	t.Parallel()
	enum1 := `{"name":"api-version","in":"query","required":true,"type":"string","enum":["2015-11-01"]}`
	inline := `{"name":"api-version","in":"query","required":true,"type":"string","description":"The API version."}`
	multiHit := `{"name":"api-version","in":"query","required":true,"type":"string","enum":["2023-01-01","2024-01-01"]}`
	multiMiss := `{"name":"api-version","in":"query","required":true,"type":"string","enum":["2020-01-01","2021-01-01"]}`
	cases := []struct {
		name, version, param, fixed, apiVersion, limitation string
		input                                               bool
	}{
		{"shared uses info.version", "2024-01-01", pVersion, "[{api-version 2024-01-01}]", "2024-01-01", "", false},
		{"shared falls back to the dir", "1.0", pVersion, "[{api-version 2024-01-01}]", "2024-01-01", "", false},
		{"single enum sends its value", "2026-05-15", enum1, "[{api-version 2015-11-01}]", "2015-11-01", "", false},
		{
			"multi enum with the doc version",
			"2024-01-01",
			multiHit,
			"[{api-version 2024-01-01}]",
			"2024-01-01",
			"",
			false,
		},
		{"multi enum without it", "2024-01-01", multiMiss, "[]", "", "generic operation", true},
		{"inline without enum", "2024-01-01", inline, "[]", "", "generic operation", true},
		{
			"no parameter",
			"2024-01-01",
			"",
			"[{api-version 2024-01-01}]",
			"2024-01-01",
			"declares no api-version",
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			params := []string{pSub}
			if c.param != "" {
				params = append(params, c.param)
			}
			ref := renderOne(t, c.version, `"paths":`+op(thingsKey, "get", "", params...), "GET", thingsKey, false)
			gotInput := slices.ContainsFunc(ref.Inputs, func(in apiref.Input) bool { return in.Name == "api-version" })
			if fixed(ref) != c.fixed || ref.APIVersion != c.apiVersion || gotInput != c.input ||
				(c.limitation != "" && !hasLimitation(ref, c.limitation)) {
				t.Fatalf("fixed %s, api_version %q, input %v, limitations %q", fixed(ref), ref.APIVersion, gotInput,
					ref.Limitations)
			}
			// The file's own version survives in the provenance even when the template sends another.
			if !strings.HasSuffix(ref.Source.Document, "(info.version "+c.version+")") {
				t.Fatalf("source document %q lost info.version %s", ref.Source.Document, c.version)
			}
		})
	}
}

// TestEnumValue pins both wire forms of an enum value: a JSON string's text, and any other JSON value as written.
func TestEnumValue(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{`"on"`: "on", `1`: "1", `true`: "true"} {
		if got := enumValue(json.RawMessage(raw)); got != want {
			t.Errorf("enumValue(%s) = %q, want %q", raw, got, want)
		}
	}
}

// TestSourceDocument pins the provenance with and without a declared version.
func TestSourceDocument(t *testing.T) {
	t.Parallel()
	in := renderInput{Doc: &swaggerDoc{}, File: IndexFile{Path: "p.json"}}
	if got := sourceDocument(in); got != "p.json" {
		t.Errorf("no info.version = %q", got)
	}
	in.Doc.Info.Version = "2026-05-15"
	if got := sourceDocument(in); got != "p.json (info.version 2026-05-15)" {
		t.Errorf("with info.version = %q", got)
	}
}

func TestRenderOperation_PathRules(t *testing.T) {
	t.Parallel()
	roleKey := "/{roleId}?disambiguation_dummy"
	roleID := `{"name":"roleId","in":"path","required":true,"type":"string","x-ms-skip-url-encoding":true}`
	ref := renderOne(t, "2024-01-01", `"x-ms-paths":`+op(roleKey, "get", "", roleID, pVersion), "GET", roleKey, true)
	if ref.PathTemplate != "/{roleId+}" || fixed(ref) != "[{api-version 2024-01-01}]" ||
		ref.AuthArgs["service"] != "<Namespace>" || !hasLimitation(ref, "after the last /providers/") ||
		!hasLimitation(ref, "drop its leading '/'") {
		t.Fatalf("role: path %q fixed %s auth %v limitations %q", ref.PathTemplate, fixed(ref), ref.AuthArgs,
			ref.Limitations)
	}

	kustoKey := "/subscriptions/{subscriptionId}/providers/Microsoft.Test/ops?operationResultResponseType=Location&$expand=x&bare"
	expand := `{"name":"$expand","in":"query","required":true,"type":"string","enum":["Properties"]}`
	ref = renderOne(t, "2024-01-01", `"x-ms-paths":`+op(kustoKey, "get", "", pSub, pVersion, expand), "GET",
		kustoKey, true)
	if fixed(ref) != "[{operationResultResponseType Location} {api-version 2024-01-01} {$expand Properties}]" {
		t.Errorf("kusto fixed = %s", fixed(ref))
	}

	genericKey := "/subscriptions/{subscriptionId}/resourcegroups/{rg}/providers/{resourceProviderNamespace}/" +
		"{parentResourcePath}/{resourceType}/{name}"
	parent := `{"name":"parentResourcePath","in":"path","required":true,"type":"string","x-ms-skip-url-encoding":true}`
	fixedType := `{"name":"resourceType","in":"path","required":true,"type":"string","enum":["vaults"]}`
	ref = renderOne(t, "2024-01-01", `"paths":`+op(genericKey, "get", "", pSub, parent, fixedType, pVersion), "GET",
		genericKey, false)
	if ref.PathTemplate != "/subscriptions/{subscriptionId}/resourcegroups/{rg}/providers/"+
		"{resourceProviderNamespace}/{parentResourcePath+}/vaults/{name}" {
		t.Fatalf("generic path = %q", ref.PathTemplate)
	}
	names := make([]string, 0, len(ref.Inputs))
	for _, in := range ref.Inputs {
		names = append(names, in.Name+":"+in.Description)
	}
	if fmt.Sprint(names) != "[subscriptionId: parentResourcePath: rg:a path segment "+
		"resourceProviderNamespace:a path segment name:a path segment]" {
		t.Errorf("inputs = %v", names)
	}
	if ref.AuthArgs["service"] != "<Namespace>" || !hasLimitation(ref, "leave no empty segment (//) when "+
		"parentResourcePath is empty") {
		t.Errorf("generic auth %v limitations %q", ref.AuthArgs, ref.Limitations)
	}
}

func TestRenderOperation_Service(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]string{
		"/subscriptions/{subscriptionId}/resourcegroups":                       "Microsoft.Resources",
		"/subscriptions/{subscriptionId}/providers/Microsoft.Test":             "Microsoft.Resources",
		"/{scope+}/providers/Microsoft.Authorization/roleAssignments":          "Microsoft.Authorization",
		"/subscriptions/{subscriptionId}/providers/Microsoft.Other/things/{x}": "Microsoft.Other",
		"/subscriptions/{s}/providers/{ns}/things":                             "",
		"/subscriptions/{s}/providers/Microsoft.Test/things/{rest+}":           "",
		"/{id+}": "",
	} {
		got, ok := derivedService(key)
		if (want == "") == ok || got != want {
			t.Errorf("derivedService(%q) = %q, %v, want %q", key, got, ok, want)
		}
	}
	key := "/subscriptions/{subscriptionId}/providers/Microsoft.Other/things"
	ref := renderOne(t, "2024-01-01", `"paths":`+op(key, "get", "", pSub, pVersion), "GET", key, false)
	if ref.AuthArgs["service"] != "Microsoft.Other" || ref.Service != "Microsoft.Other" ||
		!hasLimitation(ref, "azure_auth.service must be Microsoft.Other") {
		t.Errorf("other: %v %q %q", ref.AuthArgs, ref.Service, ref.Limitations)
	}
}

// TestQueryEscape pins the one escaping a fixed query pair gets: '&', '#', '=', '+', '%' and a space never survive
// raw, '$' does, and the result parses back to the original through net/url, as the server reads it.
func TestQueryEscape(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"a&b c#d": "a%26b%20c%23d",
		"$filter": "$filter",
		"x=y+z%":  "x%3Dy%2Bz%25",
		"resourceType eq 'Microsoft.KeyVault/vaults'": "resourceType%20eq%20%27Microsoft.KeyVault%2Fvaults%27",
	} {
		got := queryEscape(in)
		if got != want {
			t.Errorf("queryEscape(%q) = %q, want %q", in, got, want)
		}
		if back, err := url.QueryUnescape(got); err != nil || back != in {
			t.Errorf("QueryUnescape(%q) = %q, %v; want %q", got, back, err, in)
		}
	}
}

//nolint:gocognit // tests many input combinations in one table.
func TestRenderOperation_Inputs(t *testing.T) {
	t.Parallel()
	params := []string{
		pSub, pVersion,
		`{"name":"$filter","in":"query","required":true,"type":"string","enum":["resourceType eq 'x'"]}`,
		`{"name":"x-ms-fixed","in":"header","required":true,"type":"string","enum":["on"]}`,
		`{"name":"tags","in":"query","required":true,"type":"array","collectionFormat":"csv","description":"tag list"}`,
		`{"name":"ids","in":"query","required":true,"type":"array","collectionFormat":"multi"}`,
		`{"name":"opt","in":"query","type":"array","collectionFormat":"pipes"}`,
		`{"name":"x-ms-client-request-id","in":"header","type":"string"}`,
		`{"name":"weird","in":"cookie","required":true,"type":"string"}`,
		`{"name":"quiet","in":"cookie","type":"string"}`,
		`{"$ref":"#/parameters/Missing"}`,
	}
	ref := renderOne(t, "2024-01-01", `"paths":`+op(thingsKey, "get", "", params...), "GET", thingsKey, false)
	if !strings.Contains(fixed(ref), "{$filter resourceType%20eq%20%27x%27}") ||
		fmt.Sprint(ref.FixedHeaders) != "[{x-ms-fixed on}]" {
		t.Fatalf("fixed %s headers %v", fixed(ref), ref.FixedHeaders)
	}
	// The URL the tool emits, through the builder it uses, carries the value escaped exactly once.
	if u := apiref.TemplateURL(ref); !strings.Contains(u, "&$filter=resourceType%20eq%20%27x%27") &&
		!strings.Contains(u, "?$filter=resourceType%20eq%20%27x%27") {
		t.Fatalf("template URL = %s", u)
	}
	byName := map[string]apiref.Input{}
	for _, in := range ref.Inputs {
		byName[in.Name] = in
	}
	if in := byName["tags"]; !in.Renderable || in.Description != "(comma-separated) tag list" {
		t.Errorf("tags = %+v", in)
	}
	if in := byName["ids"]; in.Renderable || in.Type != "array, collectionFormat multi" {
		t.Errorf("ids = %+v", in)
	}
	if _, listed := byName["opt"]; listed || !hasLimitation(ref, "optional input opt (collectionFormat pipes)") {
		t.Errorf("opt listed %v, limitations %q", listed, ref.Limitations)
	}
	if in := byName["x-ms-client-request-id"]; in.Required || in.Location != apiref.LocationHeader {
		t.Errorf("request id = %+v", in)
	}
	if !hasGap(ref, "required input ids (array, collectionFormat multi in query) cannot be rendered") ||
		!hasGap(ref, "required input weird (in cookie) cannot be rendered") ||
		!hasGap(ref, "a parameter could not be resolved") {
		t.Errorf("gaps = %q", ref.Gaps)
	}
	if _, listed := byName["quiet"]; listed {
		t.Errorf("an optional input in an unknown location is listed")
	}
	if !ref.Inputs[0].Required || ref.Inputs[len(ref.Inputs)-1].Required {
		t.Errorf("required inputs do not come first: %+v", ref.Inputs)
	}

	many := []string{pSub, pVersion}
	for i := range apiref.MaxOptionalInputs + 1 {
		many = append(many, fmt.Sprintf(`{"name":"o%02d","in":"query","type":"string"}`, i))
	}
	ref = renderOne(t, "2024-01-01", `"paths":`+op(thingsKey, "get", "", many...), "GET", thingsKey, false)
	if !ref.InputsTruncated || len(ref.Inputs) != apiref.MaxOptionalInputs+1 {
		t.Errorf("truncated %v with %d inputs", ref.InputsTruncated, len(ref.Inputs))
	}
}

func TestRenderOperation_Body(t *testing.T) {
	t.Parallel()
	defs := `"definitions":{
		"VM":{"allOf":[{"$ref":"#/definitions/Tracked"}],"required":["properties","id","count"],
			"properties":{"properties":{"type":"object"},"id":{"type":"string","readOnly":true},
			"count":{"type":"integer","description":"how many"}}},
		"Tracked":{"required":["location"],"properties":{"location":{"type":"string"}}},
		"Str":{"type":"string"}}`
	key := thingsKey + "/{name}"
	name := `{"name":"name","in":"path","required":true,"type":"string"}`
	body := func(schema string, required bool) string {
		return fmt.Sprintf(`{"name":"p","in":"body","required":%v,"schema":%s}`, required, schema)
	}
	ref := renderOne(t, "2024-01-01", `"paths":`+op(key, "put", "", pSub, name, pVersion,
		body(`{"$ref":"#/definitions/VM"}`, true))+","+defs, "PUT", key, false)
	if ref.BodyEncoding != apiref.BodyJSON || fmt.Sprint(ref.FixedHeaders) != "[{Content-Type application/json}]" {
		t.Fatalf("encoding %s headers %v", ref.BodyEncoding, ref.FixedHeaders)
	}
	var bodyInputs []string
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationBody {
			bodyInputs = append(bodyInputs, fmt.Sprintf("%s:%s:%v", in.Name, in.Type, in.Renderable))
		}
	}
	if fmt.Sprint(bodyInputs) != "[count:integer:true location:string:true properties:object:false]" ||
		!hasGap(ref, "required input properties (object in body) cannot be rendered") {
		t.Errorf("body inputs %v gaps %q", bodyInputs, ref.Gaps)
	}

	for _, c := range []struct {
		name, param, gap, limitation string
	}{
		{"optional", body(`{"$ref":"#/definitions/VM"}`, false), "", "optional request body is not rendered"},
		{"not an object", body(`{"$ref":"#/definitions/Str"}`, true), "request body is not a JSON object", ""},
		{"unresolvable", body(`{"$ref":"#/definitions/None"}`, true), "request body is not a JSON object", ""},
		{
			"form data", `{"name":"f","in":"formData","required":true,"type":"file"}`,
			"request body is not a JSON object", "",
		},
	} {
		r := renderOne(t, "2024-01-01", `"paths":`+op(key, "put", "", pSub, name, pVersion, c.param)+","+defs,
			"PUT", key, false)
		if (c.gap != "" && !hasGap(r, c.gap)) || (c.limitation != "" && !hasLimitation(r, c.limitation)) {
			t.Errorf("%s: gaps %q limitations %q", c.name, r.Gaps, r.Limitations)
		}
	}
}

func TestRenderOperation_ResponseExtensions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		extra, style, token, items, limitation string
	}{
		{`"x-ms-pageable":{}`, "next-link", "nextLink", "value", "nextLink URL"},
		{
			`"x-ms-pageable":{"nextLinkName":"@odata.nextLink","itemName":"items"}`, "next-link", "@odata.nextLink",
			"items", "nextLink URL",
		},
		{`"x-ms-pageable":{"nextLinkName":null}`, "unspecified", "", "", ""},
		{`"x-ms-pageable":{"nextLinkName":7}`, "unspecified", "", "", "x-ms-pageable extension is malformed"},
		{`"x-ms-pageable":[]`, "unspecified", "", "", "x-ms-pageable extension is malformed"},
		{`"x-ms-long-running-operation":true`, "unspecified", "", "", "Azure-AsyncOperation"},
	} {
		ref := renderOne(t, "2024-01-01", `"paths":`+op(thingsKey, "get", c.extra, pSub, pVersion), "GET",
			thingsKey, false)
		want := apiref.Pagination{Style: c.style, OutputToken: c.token, Items: c.items}
		if ref.Pagination != want || (c.limitation != "" && !hasLimitation(ref, c.limitation)) {
			t.Errorf("%s: pagination %+v limitations %q", c.extra, ref.Pagination, ref.Limitations)
		}
	}
}

func TestRenderOperation_Errors(t *testing.T) {
	t.Parallel()
	if _, err := renderFixture(t, "2024-01-01", `"paths":`+op(thingsKey, "get", "", pSub, pVersion), "PUT",
		thingsKey, false, NewBudget(1<<20)); !errors.Is(err, ErrSpecsRejected) {
		t.Errorf("missing operation error = %v, want ErrSpecsRejected", err)
	}
	if _, err := renderFixture(t, "2024-01-01", `"paths":`+op(thingsKey, "get", "", pSub, pVersion), "GET",
		thingsKey, false, NewBudget(8)); !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("budget error = %v, want ErrBudgetExceeded", err)
	}
	full := newRefResolver(newSpecFakeFiles(nil), refIndex(testOpFile), NewBudget(1<<20))
	for i := range maxRefFiles {
		if err := full.add(fmt.Sprintf("specification/x/f%02d.json", i), &swaggerDoc{}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	doc, _ := decodeSwagger([]byte(`{"info":{"version":"2024-01-01"},"paths":` + op(thingsKey, "get", "", pSub,
		pVersion) + `}`))
	if _, err := renderOperation(context.Background(), renderInput{
		Doc: doc, File: IndexFile{Path: testOpFile, Blob: fmt.Sprintf("%040x", 1)},
		Dir: IndexDir{Kind: kindStable, Name: "2024-01-01"}, Group: "test/Test",
		Op: OpSummary{ID: "Op_Id", Method: "GET", Path: thingsKey}, Commit: specTestSHA,
		Endpoint: "https://management.azure.com", Service: "Microsoft.Test", Resolver: full,
	}); !errors.Is(err, errRefLimit) {
		t.Errorf("an operation file past the per-lookup file bound: err = %v, want errRefLimit", err)
	}
	key := thingsKey + "/{name}"
	body := `{"name":"p","in":"body","required":true,"schema":{"$ref":"` + commonRef[:len(commonRef)-len("parameters/")] +
		`definitions/X"}}`
	if _, err := renderFixture(t, "2024-01-01", `"paths":`+op(key, "put", "", body), "PUT", key, false,
		NewBudget(8)); !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("body budget error = %v, want ErrBudgetExceeded", err)
	}
}

// TestRenderOperation_ParameterReplacement verifies that an operation parameter replaces a path item parameter.
func TestRenderOperation_ParameterReplacement(t *testing.T) {
	t.Parallel()
	// Path item has subscriptionId, operation overrides it (though this is unusual, it's valid OpenAPI).
	pathItem := `{"parameters":[` + pSub + `],"get":{"operationId":"Op_Id","parameters":[` + pSub + `,` + pVersion + `]}}`
	body := `{"info":{"version":"2024-01-01"},"paths":{` + fmt.Sprintf("%q", thingsKey) + `:` + pathItem + `}}`
	doc, err := decodeSwagger([]byte(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	files := newSpecFakeFiles(map[string]string{commonFile: renderCommon})
	r := newRefResolver(files, refIndex(testOpFile, commonFile), NewBudget(1<<20))
	ref, err := renderOperation(context.Background(), renderInput{
		Doc: doc, File: IndexFile{Path: testOpFile, Blob: fmt.Sprintf("%040x", 1)},
		Dir: IndexDir{Kind: kindStable, Name: "2024-01-01"}, Group: "test/Test",
		Op: OpSummary{ID: "Op_Id", Method: "GET", Path: thingsKey}, Commit: specTestSHA,
		Endpoint: "https://management.azure.com", Service: "Microsoft.Test", SHA256: "feed",
		Selector: "test/Test@stable/2024-01-01", Resolver: r,
	})
	if err != nil {
		t.Fatalf("renderOperation: %v", err)
	}
	// Should have exactly one subscriptionId input, not two.
	count := 0
	for _, in := range ref.Inputs {
		if in.Name == "subscriptionId" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("subscriptionId appears %d times, want 1", count)
	}
}

// TestRenderOperation_UnknownBodyProperty covers the case where a required field is not in properties.
func TestRenderOperation_UnknownBodyProperty(t *testing.T) {
	t.Parallel()
	// A required field "missing" is not in properties (malformed but possible).
	defs := `"definitions":{"Thing":{"type":"object","required":["missing","present"],"properties":{"present":{"type":"string"}}}}`
	key := thingsKey + "/{name}"
	name := `{"name":"name","in":"path","required":true,"type":"string"}`
	body := `{"name":"p","in":"body","required":true,"schema":{"$ref":"#/definitions/Thing"}}`
	ref := renderOne(
		t,
		"2024-01-01",
		`"paths":`+op(key, "put", "", pSub, name, pVersion, body)+","+defs,
		"PUT",
		key,
		false,
	)
	// Should have present as a body input.
	hasPresent := slices.ContainsFunc(ref.Inputs, func(in apiref.Input) bool {
		return in.Name == "present" && in.Location == apiref.LocationBody
	})
	// Should have missing as an unrenderable body input (type "unknown").
	hasMissing := slices.ContainsFunc(ref.Inputs, func(in apiref.Input) bool {
		return in.Name == "missing" && in.Location == apiref.LocationBody && in.Type == "unknown"
	})
	if !hasPresent || !hasMissing {
		t.Errorf("body inputs: hasPresent=%v hasMissing=%v; inputs=%+v", hasPresent, hasMissing, ref.Inputs)
	}
}
