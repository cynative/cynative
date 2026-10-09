package k8s

import (
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

const testEndpoint = "https://10.0.0.1:6443"

func fixtureDocument(t *testing.T, file, model string) *Document {
	t.Helper()
	body, err := os.ReadFile("testdata/openapi/" + file)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseAPIVersion(model)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDocument(t.Context(), body, v)
	if err != nil {
		t.Fatalf("ParseDocument(%s): %v", file, err)
	}

	return d
}

func lookup(d *Document, id string) apiref.Result {
	return d.Lookup(Lookup{
		Operation: id, Endpoint: testEndpoint, ClusterRole: "view",
		Source: apiref.Source{Name: "cluster /openapi/v3", Document: "/openapi/v3/" + d.APIVersion.Key},
	})
}

func found(t *testing.T, d *Document, id string, want apiref.Outcome) *apiref.Reference {
	t.Helper()
	res := lookup(d, id)
	if res.Outcome != want || res.Reference == nil {
		t.Fatalf("%s: %+v, want %s", id, res, want)
	}

	return res.Reference
}

func hasLimitation(ref *apiref.Reference, prefix string) bool {
	return slices.ContainsFunc(ref.Limitations, func(l string) bool { return strings.HasPrefix(l, prefix) })
}

func TestReference_ListIsPagedAndWatchable(t *testing.T) {
	t.Parallel()
	d := fixtureDocument(t, "api_v1.json", "v1")
	ref := found(t, d, "listCoreV1NamespacedPod", apiref.OutcomeFound)
	if ref.Connector != "kubernetes" || ref.Protocol != "kubernetes" || ref.Model != "v1" || ref.APIVersion != "v1" ||
		ref.Method != http.MethodGet || ref.PathTemplate != "/api/v1/namespaces/{namespace}/pods" ||
		ref.Endpoint != testEndpoint || ref.Summary != "list or watch objects of kind Pod" {
		t.Errorf("reference = %+v", ref)
	}
	want := apiref.Pagination{
		Style: "continue-token", InputToken: "continue", OutputToken: "metadata.continue", Items: "items",
		PageSize: "limit",
	}
	if ref.Pagination != want || !hasLimitation(ref, "pass limit; while metadata.continue") {
		t.Errorf("pagination = %+v, limitations %q", ref.Pagination, ref.Limitations)
	}
	if !hasLimitation(ref, "with watch=true the response is a stream") ||
		!hasLimitation(ref, "read from this cluster's /openapi/v3 document as served now") ||
		!slices.Contains(ref.Limitations, `a description, not a permission: the gate allows only what the configured `+
			`ClusterRole "view" permits`) {
		t.Errorf("limitations = %q", ref.Limitations)
	}
	if ref.Response != (apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body) is a PodList"}) {
		t.Errorf("response = %+v", ref.Response)
	}
	if ns := ref.Inputs[0]; ns.Name != "namespace" || ns.Location != apiref.LocationPath || !ns.Required ||
		ns.Type != "string" {
		t.Errorf("first input = %+v", ns)
	}
	if ref.Source.Document != "/openapi/v3/api/v1" || ref.Source.Version != "" {
		t.Errorf("source = %+v", ref.Source)
	}
}

func TestReference_Bodies(t *testing.T) {
	t.Parallel()
	core := fixtureDocument(t, "api_v1.json", "v1")
	crd := fixtureDocument(t, "apis_stable.example.com_v1.json", "stable.example.com/v1")
	cases := []struct {
		d       *Document
		id, gap string
		types   string
	}{
		{
			core, "createCoreV1NamespacedPod", "request body is a whole Pod object, which the template does not render",
			"application/json",
		},
		{
			core,
			"replaceCoreV1NamespacedPod",
			"request body is a whole Pod object, which the template does not render",
			"application/json",
		},
		{
			core, "patchCoreV1NamespacedPod", "request body is a patch of Pod, which the template does not render",
			"application/apply-patch+yaml, application/json-patch+json, application/merge-patch+json, " +
				"application/strategic-merge-patch+json",
		},
		{crd, "createStableExampleComV1NamespacedCronTab", "request body is a whole CronTab object, which the " +
			"template does not render", "application/json, application/yaml"},
		{crd, "replaceStableExampleComV1NamespacedCronTab", "request body is a whole CronTab object, which the " +
			"template does not render", "application/json"},
		{crd, "patchStableExampleComV1NamespacedCronTab", "request body is a patch of Kubernetes object, which the " +
			"template does not render", "application/apply-patch+yaml, application/json-patch+json, " +
			"application/merge-patch+json, text/a, text/b, text/c"},
	}
	for _, tc := range cases {
		ref := found(t, tc.d, tc.id, apiref.OutcomeIncomplete)
		if !slices.Contains(ref.Gaps, tc.gap) || ref.BodyEncoding != apiref.BodyNone || len(ref.FixedHeaders) != 0 ||
			!slices.Contains(ref.Limitations, "send Content-Type as one of: "+tc.types) {
			t.Errorf("%s: gaps %q encoding %q headers %+v limitations %q", tc.id, ref.Gaps, ref.BodyEncoding,
				ref.FixedHeaders, ref.Limitations)
		}
	}
	ref := found(t, core, "deleteCoreV1NamespacedPod", apiref.OutcomeFound)
	if !slices.Contains(ref.Limitations, "optional request body is not rendered") ||
		!slices.Contains(ref.Limitations, "send Content-Type as one of: application/json") {
		t.Errorf("optional body: %q", ref.Limitations)
	}
	if read := found(
		t,
		core,
		"readCoreV1NamespacedPod",
		apiref.OutcomeFound,
	); hasLimitation(
		read,
		"send Content-Type",
	) {
		t.Errorf("a body-less operation lists content types: %q", read.Limitations)
	}
}

func TestReference_PerOperationRules(t *testing.T) {
	t.Parallel()
	core := fixtureDocument(t, "api_v1.json", "v1")
	logRef := found(t, core, "readCoreV1NamespacedPodLog", apiref.OutcomeFound)
	if logRef.Response != (apiref.Response{Encoding: "text/plain", Parse: "the body is the log text, not JSON"}) ||
		!hasLimitation(logRef, "leave follow unset") {
		t.Errorf("log: %+v %q", logRef.Response, logRef.Limitations)
	}
	exec := found(t, core, "connectCoreV1GetNamespacedPodExec", apiref.OutcomeIncomplete)
	if !slices.Contains(exec.Gaps, "exec needs a WebSocket or SPDY upgrade, which http_request does not perform") ||
		exec.Response != (apiref.Response{Encoding: "raw", Parse: "read Content-Type before parsing response.body"}) {
		t.Errorf("exec: %q %+v", exec.Gaps, exec.Response)
	}
	proxy := found(t, core, "connectCoreV1GetNamespacedPodProxyWithPath", apiref.OutcomeFound)
	if proxy.PathTemplate != "/api/v1/namespaces/{namespace}/pods/{name}/proxy/{path+}" ||
		!slices.Contains(proxy.Limitations, "the response is whatever the proxied pod, service or node returns") {
		t.Errorf("proxy: %s %q", proxy.PathTemplate, proxy.Limitations)
	}
	watch := found(t, core, "watchCoreV1NamespacedPodList", apiref.OutcomeFound)
	if watch.Response.Encoding != "json-stream" || watch.Pagination.Style != apiref.PaginationUnspecified ||
		!slices.Contains(watch.Limitations, "deprecated path; use the list operation with watch=true") ||
		hasLimitation(watch, "pass limit") || hasLimitation(watch, "with watch=true") {
		t.Errorf("deprecated watch: %+v %+v %q", watch.Response, watch.Pagination, watch.Limitations)
	}
	resources := found(t, core, "getCoreV1APIResources", apiref.OutcomeFound)
	if resources.Response.Parse != "JSON.parse(response.body) is a APIResourceList" {
		t.Errorf("api resources response: %+v", resources.Response)
	}
	crd := fixtureDocument(t, "apis_stable.example.com_v1.json", "stable.example.com/v1")
	ready := found(t, crd, "readStableExampleComV1NamespacedCronTabReady", apiref.OutcomeFound)
	if ready.Response != (apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body)"}) {
		t.Errorf("a bare JSON string response: %+v", ready.Response)
	}
	list := found(t, crd, "listStableExampleComV1NamespacedCronTab", apiref.OutcomeFound)
	if list.Summary != "list objects of kind CronTab & more" || list.Endpoint != testEndpoint {
		t.Errorf("crd list: summary %q endpoint %q", list.Summary, list.Endpoint)
	}
	metrics := fixtureDocument(t, "apis_metrics.k8s.io_v1beta1.json", "metrics.k8s.io/v1beta1")
	if ref := found(t, metrics, "listMetricsV1beta1NodeMetrics", apiref.OutcomeFound); ref.Response.Parse !=
		"JSON.parse(response.body) is a NodeMetricsList" {
		t.Errorf("metrics response: %+v", ref.Response)
	}
}

func TestRequestTypes(t *testing.T) {
	t.Parallel()
	got := requestTypes([]string{
		"*/*", "application/json", "a/" + strings.Repeat("b", 65), "x", "a/b/c", "a b/c", "text/plain", "c/d", "e/f",
		"g/h", "i/j",
	})
	if want := []string{"application/json", "c/d", "e/f", "g/h", "i/j", "text/plain"}; !slices.Equal(got, want) {
		t.Errorf("requestTypes = %q, want %q", got, want)
	}
	if none := requestTypes(nil); none != nil {
		t.Errorf("no types: %q", none)
	}
}

func TestValidKind(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"Pod", "A", "x-1", "A" + strings.Repeat("b", 62)} {
		if !validKind(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"", "1Pod", "Pod-", "Cron Tab", "A" + strings.Repeat("b", 63), "a.b", "<b>"} {
		if validKind(k) {
			t.Errorf("%q accepted", k)
		}
	}
}

// lookupDoc is a document whose index exercises every rule of the lookup by id.
const lookupDoc = `{"paths":{
"/apis/apps/v1/a":{"get":{"operationId":"listThings"},"put":{"operationId":"dupThing"},
	"post":{"operationId":"listthings"},"patch":{"operationId":"readThing"},"delete":{}},
"/apis/apps/v1/b":{"get":{"operationId":"dupThing"},"put":{"operationId":"Mixed"},"post":{"operationId":"x-y"}},
"/apis/apps/v1/c/..":{"get":{"operationId":"badThing"},"put":{"operationId":"dupThing"},"post":{"operationId":"mixed"}},
"/apis/apps/v1/d":{"get":{"operationId":"readThings"},"put":{"operationId":"readThingStatus"}}}}`

func TestLookup_Rules(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	d, err := ParseDocument(t.Context(), []byte(lookupDoc), v)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id      string
		outcome apiref.Outcome
		reason  string
		choices []string
	}{
		{"listThings", apiref.OutcomeFound, "", nil},
		{"dupThing", apiref.OutcomeAmbiguous, `the cluster's document lists operation "dupThing" more than once; ` +
			`this tool does not pick one`, []string{"GET /apis/apps/v1/b", "PUT /apis/apps/v1/a"}},
		{"DUPTHING", apiref.OutcomeAmbiguous, `the cluster's document lists operation "dupThing" more than once; ` +
			`this tool does not pick one`, []string{"GET /apis/apps/v1/b", "PUT /apis/apps/v1/a"}},
		{"badThing", apiref.OutcomeUnsupported, `operation "badThing" cannot be described: its path is outside the ` +
			`form this tool renders`, nil},
		{"BADthing", apiref.OutcomeUnsupported, `operation "badThing" cannot be described: its path is outside the ` +
			`form this tool renders`, nil},
		{"MIXED", apiref.OutcomeAmbiguous, "several operations differ only by case", []string{"Mixed", "mixed"}},
		{
			"LISTTHINGS", apiref.OutcomeAmbiguous, "several operations differ only by case",
			[]string{"listThings", "listthings"},
		},
		{"readthing", apiref.OutcomeFound, "", nil},
		{"readThingz", apiref.OutcomeNotFound, `no operation "readThingz" in apps/v1 as this cluster serves it; ` +
			`operation ids look like listAppsV1NamespacedDeployment; the document also lists 2 operations this tool ` +
			`cannot look up`, []string{"readThing", "readThingStatus", "readThings"}},
		{
			"zzz", apiref.OutcomeNotFound, `no operation "zzz" in apps/v1 as this cluster serves it; operation ids ` +
				`look like listAppsV1NamespacedDeployment; the document also lists 2 operations this tool cannot look up`,
			nil,
		},
		{
			"list", apiref.OutcomeNotFound, `no operation "list" in apps/v1 as this cluster serves it; operation ids ` +
				`look like listAppsV1NamespacedDeployment; the document also lists 2 operations this tool cannot look up`,
			[]string{"listThings", "listthings"},
		},
	}
	for _, tc := range cases {
		res := lookup(d, tc.id)
		if res.Outcome != tc.outcome || (tc.reason != "" && res.Reason != tc.reason) ||
			(tc.outcome != apiref.OutcomeFound && !slices.Equal(res.Choices, tc.choices)) {
			t.Errorf("%s: %+v", tc.id, res)
		}
	}
	if res := lookup(d, "readThing"); res.Reference == nil || res.Reference.Operation != "readThing" {
		t.Errorf("exact id: %+v", res)
	}
}

func TestLookup_ExactIDNeverFolds(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	d, err := ParseDocument(t.Context(), []byte(`{"paths":{"/apis/apps/v1/a":{"get":{"operationId":"readA"},
	"put":{"operationId":"reada"}}}}`), v)
	if err != nil {
		t.Fatal(err)
	}
	if res := lookup(d, "reada"); res.Outcome != apiref.OutcomeFound || res.Reference.Method != http.MethodPut {
		t.Errorf("exact id: %+v", res)
	}
}

func TestLookup_NotFoundWithoutExcluded(t *testing.T) {
	t.Parallel()
	d := fixtureDocument(t, "apis_metrics.k8s.io_v1beta1.json", "metrics.k8s.io/v1beta1")
	res := lookup(d, "listMetricsV1beta1PodMetrics")
	if res.Outcome != apiref.OutcomeNotFound || strings.Contains(res.Reason, "cannot look up") ||
		!slices.Equal(res.Choices, []string{"listMetricsV1beta1NodeMetrics"}) {
		t.Errorf("res = %+v", res)
	}
}

func TestParseDocument_Refusals(t *testing.T) {
	t.Parallel()
	v, _ := ParseAPIVersion("apps/v1")
	cases := map[string]error{
		`{"paths":{"/apis/apps/v1":{"get":{"operationId":"a","summary":5}}}}`:             ErrShape,
		`{"paths":{"/apis/apps/v1":{"get":{"operationId":"a"},"put":{"operationId":7}}}}`: ErrShape,
		`{"paths":{"/apis/apps/v1":{"get":{"operationId":"a","servers":"x"}}}}`:           ErrShape,
		`{"paths":{}}`: ErrDocument,
		`not json`:     ErrScanRefused,
	}
	for body, want := range cases {
		if _, err := ParseDocument(t.Context(), []byte(body), v); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", body, err, want)
		}
	}
	if _, err := ParseDocument(t.Context(), []byte(`{"paths":{"/apis/apps/v1":{"get":{"operationId":"a",`+
		`"summary":5}}}}`), v); err.Error() != "the document does not decode into the OpenAPI shape this tool reads" {
		t.Errorf("shape reason = %v", err)
	}
}

func TestDocument_Size(t *testing.T) {
	t.Parallel()
	d := fixtureDocument(t, "api_v1.json", "v1")
	full := d.Size(1 << 30)
	if full <= len(d.Docs.Ops)*sizeOverhead {
		t.Fatalf("Size = %d for %d operations", full, len(d.Docs.Ops))
	}
	// A limit inside the index loop, and one inside the operations loop, stop the walk early.
	for _, limit := range []int{1, full / 2} {
		if got := d.Size(limit); got <= limit || got >= full {
			t.Errorf("Size(%d) = %d, want a stop between the limit and %d", limit, got, full)
		}
	}
}

// TestReference_UnmarkedWriteBodiesAreGaps pins the shape of clusters whose document marks no request body required:
// a create, replace or patch still needs its object, so its body is a gap, while a delete's optional options body
// is left out.
func TestReference_UnmarkedWriteBodiesAreGaps(t *testing.T) {
	t.Parallel()
	body := func(kind string) string {
		return `"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/x"}}}},` +
			`"x-kubernetes-group-version-kind":{"group":"apps","version":"v1","kind":"` + kind + `"}`
	}
	v, err := ParseAPIVersion("apps/v1")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDocument(t.Context(), []byte(`{"paths":{`+
		`"/apis/apps/v1/namespaces/{namespace}/deployments":{"parameters":[`+nsParam+`],`+
		`"post":{"operationId":"create",`+body("Deployment")+`}},`+
		`"/apis/apps/v1/namespaces/{namespace}/deployments/{name}":{"parameters":[`+nsParam+`,`+
		`{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],`+
		`"put":{"operationId":"replace",`+body("Deployment")+`},`+
		`"patch":{"operationId":"patch",`+body("Deployment")+`},`+
		`"delete":{"operationId":"remove",`+body("DeleteOptions")+`}}}}`), v)
	if err != nil {
		t.Fatal(err)
	}
	for id, gap := range map[string]string{
		"create":  "request body is a whole Deployment object, which the template does not render",
		"replace": "request body is a whole Deployment object, which the template does not render",
		"patch":   "request body is a patch of Deployment, which the template does not render",
	} {
		if ref := found(t, d, id, apiref.OutcomeIncomplete); !slices.Contains(ref.Gaps, gap) ||
			slices.Contains(ref.Limitations, "optional request body is not rendered") {
			t.Errorf("%s: gaps %q limitations %q, want the gap %q", id, ref.Gaps, ref.Limitations, gap)
		}
	}
	if ref := found(t, d, "remove", apiref.OutcomeFound); len(ref.Gaps) != 0 ||
		!slices.Contains(ref.Limitations, "optional request body is not rendered") {
		t.Errorf("remove: gaps %q limitations %q", ref.Gaps, ref.Limitations)
	}
}
