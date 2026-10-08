package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

const (
	refHash  = "AAB28BA8462DC5830123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	refHash2 = "BBB28BA8462DC5830123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	metricsK = "apis/metrics.k8s.io/v1beta1"
	metricsP = "/openapi/v3/" + metricsK
	listOp   = "listMetricsV1beta1NodeMetrics"
)

// refProvider is a kubernetes provider on a non-443 port with a fixed clock.
func refProvider() *kubernetesProvider {
	p := newKubernetesProvider(resolvedCluster{host: "10.0.0.1", authority: "10.0.0.1:6443", port: "6443"})
	p.now = func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.FixedZone("x", 3600)) }

	return p
}

func metricsDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("k8s/testdata/openapi/apis_metrics.k8s.io_v1beta1.json")
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

// rootWith is a root listing metrics.k8s.io/v1beta1 and v1 under the given serverRelativeURL, plus other keys.
func rootWith(url string) string {
	return `{"paths":{"` + metricsK + `":{"serverRelativeURL":"` + url + `"},` +
		`"apis/metrics.k8s.io/v1":{"serverRelativeURL":"/openapi/v3/apis/metrics.k8s.io/v1"},` +
		`"apis/apps/v1":{},"version":{},"api":{}}}`
}

func hashedRoot(h string) string { return rootWith(metricsP + "?hash=" + h) }

const versionBody = `{"major":"1","minor":"34","gitVersion":"v1.34.7"}`

type scripted struct {
	resp MetadataResponse
	err  error
	// before runs before the response is returned, as a read in progress would.
	before func()
}

func ok(body string) scripted {
	return scripted{resp: MetadataResponse{Status: http.StatusOK, Body: body}}
}

func status(code int) scripted { return scripted{resp: MetadataResponse{Status: code}} }

// scriptReader answers each read path from its own queue and records every read.
type scriptReader struct {
	mu     sync.Mutex
	t      *testing.T
	script map[string][]scripted
	reads  []MetadataRead
	gate   func(MetadataRead)
}

func (s *scriptReader) Read(_ context.Context, r MetadataRead) (MetadataResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, r)
	if s.gate != nil {
		s.gate(r)
	}
	q := s.script[r.Path]
	if len(q) == 0 {
		s.t.Errorf("unscripted read %s", r.Path)
		return MetadataResponse{}, errors.New("unscripted")
	}
	s.script[r.Path] = q[1:]
	if q[0].before != nil {
		q[0].before()
	}

	return q[0].resp, q[0].err
}

func (s *scriptReader) paths() []string {
	out := make([]string, 0, len(s.reads))
	for _, r := range s.reads {
		out = append(out, r.Path)
	}

	return out
}

func prepared(t *testing.T, p *kubernetesProvider, model, op string) TargetLookup {
	t.Helper()
	l, err := p.PrepareLookup(apiref.Query{Connector: "kubernetes", Model: model, Operation: op}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("PrepareLookup: %v", err)
	}

	return l
}

func runLookup(ctx context.Context, t *testing.T, p *kubernetesProvider, rd *scriptReader, op string) apiref.Result {
	t.Helper()
	l := prepared(t, p, "metrics.k8s.io/v1beta1", op)
	tgt, err := l.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}

	return l.Answer(ctx, tgt, rd)
}

func TestKubernetesPrepareLookup_Validation(t *testing.T) {
	t.Parallel()
	p := refProvider()
	cases := []struct {
		q     apiref.Query
		block string
		want  string
	}{
		{
			apiref.Query{Model: "v1", Operation: "a"},
			`5`,
			"kubernetes_auth must be a JSON object; pass {} as in http_request",
		},
		{
			apiref.Query{Model: "v1", Operation: "a"},
			`[]`,
			"kubernetes_auth must be a JSON object; pass {} as in http_request",
		},
		{
			apiref.Query{Service: "apps", Model: "v1", Operation: "a"},
			`{}`,
			`service must be empty for kubernetes: the ` +
				`group goes in model, as in "apps/v1"`,
		},
		{
			apiref.Query{Model: " v1", Operation: "a"},
			`{}`,
			`kubernetes: model must be an apiVersion: a version such as ` +
				`"v1" for the core group, or <group>/<version> such as "apps/v1"`,
		},
		{apiref.Query{Model: "", Operation: "a"}, `{}`, `kubernetes: model must be an apiVersion: a version such as ` +
			`"v1" for the core group, or <group>/<version> such as "apps/v1"`},
		{
			apiref.Query{Model: "v1", Operation: "list pods"},
			`{}`,
			"operation must be an OpenAPI operationId: a letter, " +
				"then letters, digits or underscores, at most 200 characters, such as listAppsV1NamespacedDeployment",
		},
	}
	for _, tc := range cases {
		if _, err := p.PrepareLookup(tc.q, json.RawMessage(tc.block)); err == nil || err.Error() != tc.want {
			t.Errorf("%+v %s: err = %v, want %q", tc.q, tc.block, err, tc.want)
		}
	}
	l, err := p.PrepareLookup(apiref.Query{Model: "v1", Operation: "a"}, json.RawMessage(`{"cluster":"other"}`))
	if err != nil || string(l.Block()) != `{}` {
		t.Fatalf("a member is dropped by the canonical form: %v %s", err, l.Block())
	}
}

func TestKubernetesLookup_StateIsTheLookupsOwn(t *testing.T) {
	t.Parallel()
	p := refProvider()
	raw := json.RawMessage(`{}`)
	q := apiref.Query{Model: "apps/v1", Operation: "listAppsV1NamespacedDeployment"}
	l, err := p.PrepareLookup(q, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0], q.Model = '[', "batch/v1"
	b := l.Block()
	b[0] = 'X'
	tgt, _ := l.Resolve(t.Context())
	if string(l.Block()) != `{}` || !l.Admit(tgt, MetadataRead{Path: "/openapi/v3/apis/apps/v1"}) ||
		l.Admit(tgt, MetadataRead{Path: "/openapi/v3/apis/batch/v1"}) {
		t.Errorf("the lookup changed with its inputs: block %s", l.Block())
	}
}

func TestKubernetesLookup_Admit(t *testing.T) {
	t.Parallel()
	p := refProvider()
	l := prepared(t, p, "metrics.k8s.io/v1beta1", listOp)
	tgt, err := l.Resolve(t.Context())
	if err != nil || tgt != (Target{Endpoint: "https://10.0.0.1:6443", Identity: "kubernetes/10.0.0.1:6443"}) {
		t.Fatalf("Resolve = %+v, %v", tgt, err)
	}
	for path, want := range map[string]bool{
		"/version":                    true,
		"/openapi/v3":                 true,
		metricsP:                      true,
		metricsP + "?hash=" + refHash: true,
		metricsP + "?hash=" + strings.ToLower(refHash): false,
		metricsP + "?hash=" + refHash[:127]:            false,
		metricsP + "?hash=" + refHash + "&x=1":         false,
		metricsP + "/":                                 false,
		"/openapi/v3/apis/apps/v1":                     false,
		"/openapi/v3/":                                 false,
		"/openapi/v2":                                  false,
		"/api/v1/pods":                                 false,
		"/version?x":                                   false,
	} {
		if got := l.Admit(tgt, MetadataRead{Path: path}); got != want {
			t.Errorf("Admit(%q) = %v, want %v", path, got, want)
		}
	}
	if l.Admit(tgt, MetadataRead{Path: "/version", Block: json.RawMessage(`{}`)}) {
		t.Error("a read with its own block was admitted")
	}
}

func TestKubernetesLookup_ConcurrentLookupsAdmitOnlyTheirOwnKey(t *testing.T) {
	t.Parallel()
	p := refProvider()
	var wg sync.WaitGroup
	for _, model := range []string{"apps/v1", "batch/v1", "v1", "metrics.k8s.io/v1beta1"} {
		wg.Go(func() {
			l, err := p.PrepareLookup(apiref.Query{Model: model, Operation: "a"}, json.RawMessage(`{}`))
			if err != nil {
				t.Error(err)
				return
			}
			v, _ := k8sauthz.ParseAPIVersion(model)
			for _, other := range []string{"apis/apps/v1", "apis/batch/v1", "api/v1", metricsK} {
				if got := l.Admit(Target{}, MetadataRead{Path: "/openapi/v3/" + other}); got != (other == v.Key) {
					t.Errorf("%s admitted %s: %v", model, other, got)
				}
			}
		})
	}
	wg.Wait()
}

func TestKubernetesRecipe_MissThenHit(t *testing.T) {
	t.Parallel()
	p := refProvider()
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3":                 {ok(hashedRoot(refHash)), ok(hashedRoot(refHash))},
		metricsP + "?hash=" + refHash: {ok(metricsDoc(t))},
		"/version":                    {ok(versionBody)},
	}}
	res := runLookup(t.Context(), t, p, rd, listOp)
	if res.Outcome != apiref.OutcomeFound {
		t.Fatalf("miss: %+v", res)
	}
	src := res.Reference.Source
	if !slices.Equal(rd.paths(), []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/version"}) ||
		src.Name != "cluster /openapi/v3" || src.Document != metricsP || src.Version != "v1.34.7" ||
		src.Target != "kubernetes/10.0.0.1:6443" || src.ServerHash != refHash ||
		src.ObservedAt != "2026-10-08T11:00:00Z" || len(src.SHA256) != 64 {
		t.Errorf("miss: reads %q source %+v", rd.paths(), src)
	}
	want := MetadataRead{Path: metricsP + "?hash=" + refHash, MaxBytes: 10 << 20, Timeout: 60 * time.Second}
	if r := rd.reads[0]; r.Path != "/openapi/v3" || r.MaxBytes != 2<<20 || r.Timeout != 20*time.Second ||
		rd.reads[1].Path != want.Path || rd.reads[1].MaxBytes != want.MaxBytes || rd.reads[1].Timeout != want.Timeout ||
		rd.reads[2].MaxBytes != 64<<10 || rd.reads[2].Timeout != 10*time.Second {
		t.Errorf("read bounds: %+v", rd.reads)
	}
	rd.reads = nil
	hit := runLookup(t.Context(), t, p, rd, "readMetricsV1beta1NodeMetrics")
	if hit.Outcome != apiref.OutcomeFound || !slices.Equal(rd.paths(), []string{"/openapi/v3"}) ||
		hit.Reference.Source != (apiref.Source{
			Name: src.Name, Document: src.Document, Version: src.Version, SHA256: src.SHA256, Target: src.Target,
			ServerHash: src.ServerHash, ObservedAt: src.ObservedAt,
		}) {
		t.Errorf("hit: reads %q result %+v", rd.paths(), hit)
	}
}

func TestKubernetesRecipe_StaleHash(t *testing.T) {
	t.Parallel()
	moved := status(http.StatusMovedPermanently)
	cases := []struct {
		name    string
		script  map[string][]scripted
		reads   []string
		outcome apiref.Outcome
		cached  string
		limit   string
	}{
		{
			name: "a new hash",
			script: map[string][]scripted{
				"/openapi/v3":                  {ok(hashedRoot(refHash)), ok(hashedRoot(refHash2))},
				metricsP + "?hash=" + refHash:  {moved},
				metricsP + "?hash=" + refHash2: {ok("")},
			},
			reads: []string{
				"/openapi/v3",
				metricsP + "?hash=" + refHash,
				"/openapi/v3",
				metricsP + "?hash=" + refHash2,
			},
			outcome: apiref.OutcomeUnavailable,
		},
		{
			name: "a new hash that answers",
			script: map[string][]scripted{
				"/openapi/v3":                  {ok(hashedRoot(refHash)), ok(hashedRoot(refHash2))},
				metricsP + "?hash=" + refHash:  {moved},
				metricsP + "?hash=" + refHash2: {ok("DOC")},
				"/version":                     {ok(versionBody)},
			},
			reads: []string{
				"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3", metricsP + "?hash=" + refHash2, "/version",
			},
			outcome: apiref.OutcomeFound, cached: refHash2,
		},
		{
			name: "the hash repeated",
			script: map[string][]scripted{
				"/openapi/v3":                 {ok(hashedRoot(refHash)), ok(hashedRoot(refHash))},
				metricsP + "?hash=" + refHash: {moved},
				metricsP:                      {ok("DOC")},
				"/version":                    {ok(versionBody)},
			},
			reads:   []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3", metricsP, "/version"},
			outcome: apiref.OutcomeFound, limit: limitChanged,
		},
		{
			name: "no usable hash after the 301",
			script: map[string][]scripted{
				"/openapi/v3":                 {ok(hashedRoot(refHash)), ok(rootWith(metricsP))},
				metricsP + "?hash=" + refHash: {moved},
				metricsP:                      {ok("DOC")},
				"/version":                    {ok(versionBody)},
			},
			reads:   []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3", metricsP, "/version"},
			outcome: apiref.OutcomeFound, limit: limitChanged,
		},
		{
			name: "two 301s",
			script: map[string][]scripted{
				"/openapi/v3":                  {ok(hashedRoot(refHash)), ok(hashedRoot(refHash2))},
				metricsP + "?hash=" + refHash:  {moved},
				metricsP + "?hash=" + refHash2: {moved},
				metricsP:                       {ok("DOC")},
				"/version":                     {ok(versionBody)},
			},
			reads: []string{
				"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3", metricsP + "?hash=" + refHash2, metricsP,
				"/version",
			},
			outcome: apiref.OutcomeFound, limit: limitChanged,
		},
		{
			name: "the key gone after the 301",
			script: map[string][]scripted{
				"/openapi/v3":                 {ok(hashedRoot(refHash)), ok(`{"paths":{}}`)},
				metricsP + "?hash=" + refHash: {moved},
			},
			reads:   []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3"},
			outcome: apiref.OutcomeNotFound,
		},
		{
			name: "the second root fails",
			script: map[string][]scripted{
				"/openapi/v3":                 {ok(hashedRoot(refHash)), status(http.StatusServiceUnavailable)},
				metricsP + "?hash=" + refHash: {moved},
			},
			reads:   []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3"},
			outcome: apiref.OutcomeUnavailable,
		},
		{
			name: "the second document fails",
			script: map[string][]scripted{
				"/openapi/v3":                  {ok(hashedRoot(refHash)), ok(hashedRoot(refHash2))},
				metricsP + "?hash=" + refHash:  {moved},
				metricsP + "?hash=" + refHash2: {status(http.StatusInternalServerError)},
			},
			reads: []string{
				"/openapi/v3",
				metricsP + "?hash=" + refHash,
				"/openapi/v3",
				metricsP + "?hash=" + refHash2,
			},
			outcome: apiref.OutcomeUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkStale(t, tc.script, tc.reads, tc.outcome, tc.cached, tc.limit)
		})
	}
}

// checkStale runs one stale-hash script and checks the answer, the reads in order, and which hash was cached.
func checkStale(
	t *testing.T, script map[string][]scripted, reads []string, outcome apiref.Outcome, cached, limit string,
) {
	t.Helper()
	p := refProvider()
	for path, q := range script {
		for i := range q {
			if q[i].resp.Body == "DOC" {
				q[i].resp.Body = metricsDoc(t)
			}
		}
		script[path] = q
	}
	rd := &scriptReader{t: t, script: script}
	res := runLookup(t.Context(), t, p, rd, listOp)
	if res.Outcome != outcome || !slices.Equal(rd.paths(), reads) {
		t.Errorf("result %+v reads %q", res, rd.paths())
	}
	if limit != "" && !slices.Contains(res.Reference.Limitations, limit) {
		t.Errorf("limitations %q lack %q", res.Reference.Limitations, limit)
	}
	for _, h := range []string{refHash, refHash2} {
		if _, hit := p.refs.get("https://10.0.0.1:6443", metricsK, h); hit != (h == cached) {
			t.Errorf("cache under %s...: %v", h[:4], hit)
		}
	}
}

func TestKubernetesRecipe_ReadFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		script map[string][]scripted
		reason string
	}{
		{"root 404", map[string][]scripted{"/openapi/v3": {status(http.StatusNotFound)}}, reasonNoV3},
		{
			"root 403",
			map[string][]scripted{"/openapi/v3": {status(http.StatusForbidden)}},
			"GET /openapi/v3 answered 403",
		},
		{
			"root not JSON",
			map[string][]scripted{"/openapi/v3": {ok("<html>")}},
			"the /openapi/v3 root was refused by the streaming pass: not JSON",
		},
		{
			"root without paths",
			map[string][]scripted{"/openapi/v3": {ok(`{"x":{}}`)}},
			"the /openapi/v3 root is not a JSON object with a paths object",
		},
		{
			"root truncated",
			map[string][]scripted{"/openapi/v3": {{resp: MetadataResponse{Status: 200, Truncated: true}}}},
			"GET /openapi/v3 exceeded 2097152 bytes",
		},
		{"transport error", map[string][]scripted{"/openapi/v3": {{err: errors.New("dial tcp 10.0.0.1:6443: refused " +
			strings.Repeat("x", 600))}}}, "GET /openapi/v3 failed: dial tcp 10.0.0.1:6443: refused " +
			strings.Repeat("x", 500-len("dial tcp 10.0.0.1:6443: refused ")-3) + "..."},
		{
			"gate denial",
			map[string][]scripted{"/openapi/v3": {{err: errors.New(`cluster_role="view": k8s_hardening: ` +
				`request not permitted by the configured ClusterRole policy: non-resource get /openapi/v3`)}}},
			`GET /openapi/v3 failed: cluster_role="view": k8s_hardening: request not permitted by the configured ` +
				`ClusterRole policy: non-resource get /openapi/v3`,
		},
		{"document empty", map[string][]scripted{
			"/openapi/v3": {ok(hashedRoot(refHash))}, metricsP + "?hash=" + refHash: {ok("")},
		}, "the root lists metrics.k8s.io/v1beta1 but GET " + metricsP + " answered an empty body; the cluster " +
			"published that document's URL in the canonical form"},
		{"document 404 published elsewhere", map[string][]scripted{
			"/openapi/v3": {ok(rootWith("https://elsewhere.example/doc"))}, metricsP: {status(http.StatusNotFound)},
		}, "the root lists metrics.k8s.io/v1beta1 but GET " + metricsP + " answered 404; the cluster published that " +
			"document's URL outside " + metricsP + ", which this tool does not follow"},
		{"document truncated", map[string][]scripted{
			"/openapi/v3":                 {ok(hashedRoot(refHash))},
			metricsP + "?hash=" + refHash: {{resp: MetadataResponse{Status: 200, Body: "{", Truncated: true}}},
		}, "GET " + metricsP + "?hash=" + refHash + " exceeded 10485760 bytes"},
		{"document not JSON", map[string][]scripted{
			"/openapi/v3": {ok(hashedRoot(refHash))}, metricsP + "?hash=" + refHash: {ok("{")},
		}, "the metrics.k8s.io/v1beta1 document was refused by the streaming pass: not JSON"},
		{
			"document shape",
			map[string][]scripted{
				"/openapi/v3": {ok(hashedRoot(refHash))},
				metricsP + "?hash=" + refHash: {
					ok(`{"paths":{"/apis/metrics.k8s.io/v1beta1":{"get":{"operationId":"a","summary":5}}}}`),
				},
			},
			"the metrics.k8s.io/v1beta1 document does not decode into the OpenAPI shape this tool reads",
		},
		{"a 301 to a read without a hash", map[string][]scripted{
			"/openapi/v3": {ok(rootWith(metricsP))}, metricsP: {status(http.StatusMovedPermanently)},
		}, "GET " + metricsP + " answered 301"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := runLookup(t.Context(), t, refProvider(), &scriptReader{t: t, script: tc.script}, listOp)
			if res.Outcome != apiref.OutcomeUnavailable || res.Reason != tc.reason {
				t.Errorf("got %+v\nwant reason %q", res, tc.reason)
			}
		})
	}
}

func TestKubernetesRecipe_NotListed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		model, reason string
		choices       []string
	}{
		{"metrics.k8s.io/v2", "metrics.k8s.io/v2 is not listed in this cluster's /openapi/v3; it lists " +
			"metrics.k8s.io/v1, metrics.k8s.io/v1beta1; " + reasonLeftOut, []string{"metrics.k8s.io/v1", "metrics.k8s.io/v1beta1"}},
		{
			"core/v1",
			"core/v1 is not listed in this cluster's /openapi/v3; " + reasonLeftOut + "; " + reasonCoreGroup,
			nil,
		},
		{
			"api/v1",
			"api/v1 is not listed in this cluster's /openapi/v3; " + reasonLeftOut + "; " + reasonCoreGroup,
			nil,
		},
	}
	for _, tc := range cases {
		rd := &scriptReader{t: t, script: map[string][]scripted{"/openapi/v3": {ok(hashedRoot(refHash))}}}
		l := prepared(t, refProvider(), tc.model, listOp)
		tgt, _ := l.Resolve(t.Context())
		res := l.Answer(t.Context(), tgt, rd)
		if res.Outcome != apiref.OutcomeNotFound || res.Reason != tc.reason || !slices.Equal(res.Choices, tc.choices) {
			t.Errorf("%s: %+v", tc.model, res)
		}
	}
}

func TestKubernetesRecipe_NoUsableHashIsReadFreshAndNotCached(t *testing.T) {
	t.Parallel()
	for _, root := range []string{rootWith(metricsP), hashedRoot(strings.ToLower(refHash)), rootWith(metricsP + "?hash=")} {
		p := refProvider()
		rd := &scriptReader{t: t, script: map[string][]scripted{
			"/openapi/v3": {ok(root)}, metricsP: {ok(metricsDoc(t))}, "/version": {ok(versionBody)},
		}}
		res := runLookup(t.Context(), t, p, rd, listOp)
		if res.Outcome != apiref.OutcomeFound || !slices.Contains(res.Reference.Limitations, limitNoHash) ||
			res.Reference.Source.ServerHash != "" || len(p.refs.entries) != 0 ||
			!slices.Equal(rd.paths(), []string{"/openapi/v3", metricsP, "/version"}) {
			t.Errorf("%s: %+v reads %q", root, res, rd.paths())
		}
	}
}

func TestKubernetesRecipe_Version(t *testing.T) {
	t.Parallel()
	cases := []struct {
		read scripted
		want string
	}{
		{ok(versionBody), "v1.34.7"},
		{ok(`{"gitVersion":"v1.35.8-gke.1380001"}`), "v1.35.8-gke.1380001"},
		{ok(`{"gitVersion":"v1.2.3` + strings.Repeat("a", 59) + `"}`), ""},
		{ok(`{"gitVersion":"1.34.7"}`), ""},
		{ok(`{"gitVersion":"v1.34"}`), ""},
		{ok(`{"gitVersion":"v1.34.7 <b>"}`), ""},
		{ok(`{"gitVersion":5}`), ""},
		{ok(`[]`), ""},
		{status(http.StatusNotFound), ""},
		{scripted{resp: MetadataResponse{Status: 200, Body: versionBody, Truncated: true}}, ""},
		{scripted{err: errors.New("boom")}, ""},
	}
	for _, tc := range cases {
		rd := &scriptReader{t: t, script: map[string][]scripted{
			"/openapi/v3": {ok(hashedRoot(refHash))}, metricsP + "?hash=" + refHash: {ok(metricsDoc(t))},
			"/version": {tc.read},
		}}
		res := runLookup(t.Context(), t, refProvider(), rd, listOp)
		ref := res.Reference
		if res.Outcome != apiref.OutcomeFound || ref.Source.Version != tc.want ||
			slices.Contains(ref.Limitations, limitNoVersion) != (tc.want == "") {
			t.Errorf("%+v: version %q limitations %q", tc.read, ref.Source.Version, ref.Limitations)
		}
	}
}

// countdownCtx reports no error for its first left calls to Err, then err: a context that ends at a chosen check.
type countdownCtx struct {
	context.Context

	mu   sync.Mutex
	left int
	err  error
}

func (c *countdownCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.left > 0 {
		c.left--
		return nil
	}

	return c.err
}

// TestKubernetesRecipe_ContextChecks ends the context at each check of a miss in turn: after the root read, after
// the root's parse, after the document read, inside the pre-pass and the core, after distillation and after the
// /version read. Each answers unavailable, and the reads stop at the check that saw it.
func TestKubernetesRecipe_ContextChecks(t *testing.T) {
	t.Parallel()
	doc := metricsDoc(t)
	all := []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/version"}
	for n, reads := range map[int]int{0: 1, 1: 1, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 3} {
		for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
			p := refProvider()
			rd := &scriptReader{t: t, script: map[string][]scripted{
				"/openapi/v3": {ok(hashedRoot(refHash))}, metricsP + "?hash=" + refHash: {ok(doc)},
				"/version": {ok(versionBody)},
			}}
			ctx := &countdownCtx{Context: t.Context(), left: n, err: err}
			res := runLookup(ctx, t, p, rd, listOp)
			want := "the lookup was interrupted"
			if errors.Is(err, context.DeadlineExceeded) {
				want = "the lookup timed out after 120s"
			}
			if res.Outcome != apiref.OutcomeUnavailable || res.Reason != want || len(p.refs.entries) != 0 ||
				!slices.Equal(rd.paths(), all[:reads]) {
				t.Errorf("ended after %d checks (%v): %+v, reads %q, cached %d", n, err, res, rd.paths(),
					len(p.refs.entries))
			}
		}
	}
	p := refProvider()
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {
			ok(hashedRoot(refHash)),
		},
		metricsP + "?hash=" + refHash: {ok(doc)},
		"/version":                    {ok(versionBody)},
	}}
	if res := runLookup(
		&countdownCtx{Context: t.Context(), left: 9, err: context.Canceled},
		t,
		p,
		rd,
		listOp,
	); res.Outcome !=
		apiref.OutcomeFound {
		t.Errorf("nine checks pass: %+v", res)
	}
}

// TestKubernetesLookup_NeverBootstraps seeds the view policy the way registration does, then runs a miss whose
// every read passes the provider's own AuthorizeAction, as the transport runs it: the gate is served from the
// seeded cache and no read triggers a ClusterRole fetch. If that cache ever gains an expiry, this fails.
func TestKubernetesLookup_NeverBootstraps(t *testing.T) {
	t.Parallel()
	p := refProvider()
	p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
		return viewPolicyAllowingPods(), nil
	}
	if err := p.probeAndSeedView(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
		t.Error("a lookup read triggered a ClusterRole fetch")
		return nil, errors.New("no fetch")
	}
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {ok(hashedRoot(refHash))}, metricsP + "?hash=" + refHash: {ok(metricsDoc(t))},
		"/version": {ok(versionBody)},
	}}
	rd.gate = func(r MetadataRead) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://10.0.0.1:6443"+r.Path, nil)
		if err != nil {
			t.Fatal(err)
		}
		args := authreq.NewProviderArgs(json.RawMessage(`{"kubernetes_auth":{}}`), "kubernetes")
		if aerr := p.AuthorizeAction(t.Context(), authreq.NewView(req, ""), args); aerr != nil {
			t.Errorf("gate refused %s: %v", r.Path, aerr)
		}
	}
	if res := runLookup(t.Context(), t, p, rd, listOp); res.Outcome != apiref.OutcomeFound || len(rd.reads) != 3 {
		t.Errorf("result %+v after %d reads", res, len(rd.reads))
	}
}

// staticReader answers every read from a fixed table, safely for concurrent lookups.
type staticReader map[string]string

func (s staticReader) Read(_ context.Context, r MetadataRead) (MetadataResponse, error) {
	return MetadataResponse{Status: http.StatusOK, Body: s[r.Path]}, nil
}

func TestKubernetesLookup_ConcurrentLookupsShareTheCache(t *testing.T) {
	t.Parallel()
	p := refProvider()
	rd := staticReader{
		"/openapi/v3": hashedRoot(refHash), metricsP + "?hash=" + refHash: metricsDoc(t), "/version": versionBody,
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			op := listOp
			if i%2 == 1 {
				op = "readMetricsV1beta1NodeMetrics"
			}
			l := prepared(t, p, "metrics.k8s.io/v1beta1", op)
			tgt, _ := l.Resolve(t.Context())
			if res := l.Answer(
				t.Context(),
				tgt,
				rd,
			); res.Outcome != apiref.OutcomeFound ||
				res.Reference.Operation != op {
				t.Errorf("lookup %d: %+v", i, res)
			}
		})
	}
	wg.Wait()
	if len(p.refs.entries) != 1 {
		t.Errorf("%d entries, want one", len(p.refs.entries))
	}
}

func TestKubernetesLookup_AnAnswerNeverAltersTheCachedDocument(t *testing.T) {
	t.Parallel()
	p := refProvider()
	rd := staticReader{
		"/openapi/v3": hashedRoot(refHash), metricsP + "?hash=" + refHash: metricsDoc(t), "/version": versionBody,
	}
	first := runLookup(t.Context(), t, p, &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {ok(rd["/openapi/v3"])}, metricsP + "?hash=" + refHash: {ok(rd[metricsP+"?hash="+refHash])},
		"/version": {ok(versionBody)},
	}}, listOp)
	want, _ := json.Marshal(first)
	ref := first.Reference
	ref.Summary, ref.Inputs[0].Description, ref.Limitations[0], ref.Gaps = "X", "X", "X", append(ref.Gaps, "X")
	ref.Inputs = ref.Inputs[:1]
	again := runLookup(t.Context(), t, p, &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {ok(rd["/openapi/v3"])},
	}}, listOp)
	if got, _ := json.Marshal(again); string(got) != string(want) {
		t.Errorf("the cached answer changed:\n%s\nwant\n%s", got, want)
	}
}

// sizedDocument is a distilled document whose Size is about n bytes.
func sizedDocument(n int) *k8sauthz.Document {
	return &k8sauthz.Document{
		Index: map[string]k8sauthz.IndexEntry{"a": {Reason: strings.Repeat("x", n)}},
		Docs:  &openapidoc.OperationDocs{},
	}
}

func TestKubeRefCache_Bounds(t *testing.T) {
	t.Parallel()
	c := &kubeRefCache{}
	for i := range kubeCacheEntries + 1 {
		c.put("e", fmt.Sprintf("k%d", i), kubeRefEntry{doc: sizedDocument(10), hash: refHash})
	}
	if _, hit := c.get("e", "k0", refHash); hit || len(c.entries) != kubeCacheEntries {
		t.Errorf("entry bound: %d entries, oldest kept %v", len(c.entries), hit)
	}
	c.put("e", "k16", kubeRefEntry{doc: sizedDocument(20), hash: refHash})
	if len(c.entries) != kubeCacheEntries || c.entries[len(c.entries)-1].size < 20 {
		t.Errorf("replacing a key duplicated it: %d entries", len(c.entries))
	}
	big := &kubeRefCache{}
	for i := range 3 {
		big.put("e", fmt.Sprintf("k%d", i), kubeRefEntry{doc: sizedDocument(6 << 20), hash: refHash})
	}
	if _, hit := big.get("e", "k0", refHash); hit || len(big.entries) != 2 || big.bytes > kubeCacheBytes {
		t.Errorf("byte bound: %d entries, %d bytes", len(big.entries), big.bytes)
	}
	big.put("e", "huge", kubeRefEntry{doc: sizedDocument(kubeCacheMaxEntry), hash: refHash})
	if _, hit := big.get("e", "huge", refHash); hit || len(big.entries) != 2 {
		t.Errorf("an entry over %d bytes was stored", kubeCacheMaxEntry)
	}
	if _, hit := big.get("e", "k1", ""); hit {
		t.Error("a lookup without a hash hit")
	}
}

func TestKubernetesProvider_DescriptionNamesTheLookup(t *testing.T) {
	t.Parallel()
	if d := refProvider().Description(); !strings.Contains(d, `call api_reference with connector "kubernetes", `+
		`kubernetes_auth {}, model set to the apiVersion and the operationId.`) {
		t.Errorf("description = %q", d)
	}
}

func TestKubernetesRecipe_TheNewHashHitsTheCache(t *testing.T) {
	t.Parallel()
	p := refProvider()
	seed := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {ok(hashedRoot(refHash2))}, metricsP + "?hash=" + refHash2: {ok(metricsDoc(t))},
		"/version": {ok(versionBody)},
	}}
	if res := runLookup(t.Context(), t, p, seed, listOp); res.Outcome != apiref.OutcomeFound {
		t.Fatalf("seed: %+v", res)
	}
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3":                 {ok(hashedRoot(refHash)), ok(hashedRoot(refHash2))},
		metricsP + "?hash=" + refHash: {status(http.StatusMovedPermanently)},
	}}
	res := runLookup(t.Context(), t, p, rd, listOp)
	if res.Outcome != apiref.OutcomeFound || res.Reference.Source.ServerHash != refHash2 ||
		!slices.Equal(rd.paths(), []string{"/openapi/v3", metricsP + "?hash=" + refHash, "/openapi/v3"}) {
		t.Errorf("result %+v reads %q", res, rd.paths())
	}
}

func TestKubernetesRecipe_AnUnknownOperationAddsNothing(t *testing.T) {
	t.Parallel()
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3": {ok(rootWith(metricsP))}, metricsP: {ok(metricsDoc(t))}, "/version": {ok(`{}`)},
	}}
	res := runLookup(t.Context(), t, refProvider(), rd, "listMetricsV1beta1PodMetrics")
	if res.Outcome != apiref.OutcomeNotFound || res.Reference != nil ||
		!slices.Equal(res.Choices, []string{listOp}) {
		t.Errorf("result %+v", res)
	}
}

// TestKubeRefCache_EvictionReleasesTheDocument pins retention, not only accounting: once evicted, a document must
// be unreachable, or the cache's backing array would keep it alive past the byte bound.
func TestKubeRefCache_EvictionReleasesTheDocument(t *testing.T) {
	t.Parallel()
	c := &kubeRefCache{}
	evicted := func() weak.Pointer[k8sauthz.Document] {
		d := sizedDocument(10)
		c.put("e", "k0", kubeRefEntry{doc: d, hash: refHash})

		return weak.Make(d)
	}()
	for i := 1; i <= kubeCacheEntries; i++ {
		c.put("e", fmt.Sprintf("k%d", i), kubeRefEntry{doc: sizedDocument(10), hash: refHash})
	}
	if _, hit := c.get("e", "k0", refHash); hit {
		t.Fatal("the oldest entry was not evicted")
	}
	runtime.GC()
	if evicted.Value() != nil {
		t.Error("the evicted document is still reachable")
	}
	runtime.KeepAlive(c)
}
