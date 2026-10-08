package tools_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/transport"
)

// named is a provider with no reference support under any name.
type named struct {
	authtest.FailingProvider

	name string
}

func (p *named) Name() string { return p.name }

// fakeLookup is a TargetLookup whose recipe is a function.
type fakeLookup struct {
	block   json.RawMessage
	target  auth.Target
	resolve func(ctx context.Context) error
	admit   func(r auth.MetadataRead) bool
	answer  func(ctx context.Context, rd auth.MetadataReader) apiref.Result
}

func (l *fakeLookup) Block() json.RawMessage { return slices.Clone(l.block) }

func (l *fakeLookup) Resolve(ctx context.Context) (auth.Target, error) {
	if l.resolve != nil {
		if err := l.resolve(ctx); err != nil {
			return auth.Target{}, err
		}
	}

	return l.target, nil
}

func (l *fakeLookup) Admit(_ auth.Target, r auth.MetadataRead) bool {
	if l.admit != nil {
		return l.admit(r)
	}

	return r.Block == nil
}

func (l *fakeLookup) Answer(ctx context.Context, _ auth.Target, rd auth.MetadataReader) apiref.Result {
	return l.answer(ctx, rd)
}

// targetProvider is a TargetDocumenter that canonicalizes its block to {} the way kubernetes does, and records
// the raw block and query PrepareLookup received.
type targetProvider struct {
	named

	lookup *fakeLookup
	mu     sync.Mutex
	raw    []string
	query  []apiref.Query
}

func (p *targetProvider) PrepareLookup(q apiref.Query, raw json.RawMessage) (auth.TargetLookup, error) {
	p.mu.Lock()
	p.raw, p.query = append(p.raw, string(raw)), append(p.query, q)
	p.mu.Unlock()
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil, errors.New("kubernetes_auth must be a JSON object; pass {} as in http_request")
	}
	if q.Model == "bad" {
		return nil, errors.New("model is bad")
	}
	l := *p.lookup
	l.block = json.RawMessage(`{}`)

	return &l, nil
}

// bothProvider implements both interfaces, as Azure will.
type bothProvider struct {
	*targetProvider
}

func (p *bothProvider) Reference(context.Context, apiref.Query) apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeNotFound, Reason: "public answer"}
}

func (p *bothProvider) Hint(context.Context, authreq.View, *authreq.UnmatchedRequestError) apiref.Hint {
	return apiref.Hint{}
}

const testTarget = "https://k8s.example:6443"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func foundRef() apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeFound, Reference: &apiref.Reference{
		Connector: "kubernetes", Operation: "listThings", Protocol: "kubernetes", Method: "GET",
		PathTemplate: "/apis/apps/v1/things", Endpoint: testTarget, BodyEncoding: apiref.BodyNone,
	}}
}

// readsAndAnswers is a recipe that makes the given reads, ignoring their errors as /version's are ignored, then
// answers found. It records the errors it saw.
func readsAndAnswers(paths []string, errs *[]error) func(context.Context, auth.MetadataReader) apiref.Result {
	return func(ctx context.Context, rd auth.MetadataReader) apiref.Result {
		for _, p := range paths {
			_, err := rd.Read(ctx, auth.MetadataRead{Path: p, MaxBytes: 2 << 20, Timeout: 20 * time.Second})
			if errs != nil {
				*errs = append(*errs, err)
			}
		}

		return foundRef()
	}
}

func newTarget(name string, answer func(context.Context, auth.MetadataReader) apiref.Result) *targetProvider {
	return &targetProvider{name: name, lookup: &fakeLookup{
		target: auth.Target{Endpoint: testTarget, Identity: name + "/k8s.example:6443"}, answer: answer,
	}}
}

// fakeExec is a scripted executor that records every request it gets.
type fakeExec struct {
	mu    sync.Mutex
	args  []string
	resp  func(args string) (*transport.Response, error)
	route bool
}

func (f *fakeExec) exec(ctx context.Context, args string, _ []auth.Provider) (*transport.Response, error) {
	f.mu.Lock()
	f.args = append(f.args, args)
	f.mu.Unlock()
	audit.MarkRoute(ctx, f.route)
	// A read's own failure and progress must never reach the call's recorder.
	audit.MarkFailed(ctx)
	audit.MarkProgress(ctx)
	if f.resp != nil {
		return f.resp(args)
	}

	return &transport.Response{Status: 200, Body: `{"ok":true}`}, nil
}

// refSink records every child record and can fail the nth write.
type refSink struct {
	mu     sync.Mutex
	recs   []audit.Record
	failAt int
}

func (s *refSink) Log(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec)
	if s.failAt > 0 && len(s.recs) == s.failAt {
		return fmt.Errorf("%w: disk full", audit.ErrLog)
	}

	return nil
}

type refRun struct {
	out      string
	parsed   refOut
	err      error
	decision *audit.Decision
	fail     *audit.Failure
}

func runTargeted(
	ctx context.Context, t *testing.T, providers []auth.Provider, sink audit.Sink, ex *fakeExec, args string,
) refRun {
	t.Helper()
	ctx, dec := audit.WithDecision(ctx)
	ctx, fail := audit.WithFailure(ctx)
	ctx = audit.WithScope(ctx, audit.Scope{SessionID: "S", RunID: "R", Depth: 1, CallID: "PARENT"})
	ids := 0
	tool := tools.NewAPIReferenceToolWithOpts(providers, nil, sink,
		tools.WithReferenceExecutor(ex.exec),
		tools.WithReferenceIDFunc(func() string { ids++; return fmt.Sprintf("K%d", ids) }))
	out, err := tool.Run(ctx, args)
	r := refRun{out: out, err: err, decision: dec, fail: fail}
	if err == nil {
		if uerr := json.Unmarshal([]byte(out), &r.parsed); uerr != nil {
			t.Fatalf("output is not JSON: %v\n%s", uerr, out)
		}
	}

	return r
}

const k8sArgs = `{"connector":"kubernetes","model":"apps/v1","operation":"listThings","kubernetes_auth":{}}`

func TestAPIReferenceTargeted_Routing(t *testing.T) {
	t.Parallel()
	kube := func() *targetProvider { return newTarget("kubernetes", readsAndAnswers(nil, nil)) }
	cases := []struct {
		name      string
		providers []auth.Provider
		args      string
		outcome   string
		reason    string
		prepared  int
	}{
		{"not configured", nil, k8sArgs, "unsupported", `connector "kubernetes" is not configured in this session`, 0},
		{
			"block absent",
			[]auth.Provider{kube()},
			`{"connector":"kubernetes","model":"apps/v1","operation":"listThings"}`, "not_found",
			"kubernetes_auth is required for a kubernetes lookup; pass {} as in http_request", 0,
		},
		{
			"block null",
			[]auth.Provider{kube()},
			`{"connector":"kubernetes","model":"apps/v1","operation":"listThings","kubernetes_auth":null}`, "not_found",
			"kubernetes_auth is required for a kubernetes lookup; pass {} as in http_request", 0,
		},
		{
			"a case-variant key is present",
			[]auth.Provider{kube()},
			`{"connector":"Kubernetes","model":"apps/v1","operation":"listThings","KUBERNETES_AUTH":{"x":1}}`,
			"found",
			"",
			1,
		},
		{
			"a malformed block",
			[]auth.Provider{kube()},
			`{"connector":"kubernetes","model":"apps/v1","operation":"listThings","kubernetes_auth":5}`, "not_found",
			"kubernetes_auth must be a JSON object; pass {} as in http_request", 1,
		},
		{
			"invalid targeted arguments",
			[]auth.Provider{kube()},
			`{"connector":"kubernetes","model":"bad","operation":"listThings","kubernetes_auth":{}}`, "not_found",
			"model is bad", 1,
		},
		{
			"other connectors' malformed blocks",
			[]auth.Provider{kube()},
			`{"connector":"kubernetes","model":"apps/v1","operation":"listThings","kubernetes_auth":{},` +
				`"gke_auth":5,"aws_auth":"x"}`, "found", "", 1,
		},
		{
			"eks",
			[]auth.Provider{&named{name: "eks"}},
			`{"connector":"eks","operation":"x","eks_auth":{"cluster_name":"c"}}`, "unsupported",
			"targeted lookups for this connector are not available yet", 0,
		},
		{
			"gke",
			[]auth.Provider{&named{name: "gke"}},
			`{"connector":"gke","operation":"x","gke_auth":{}}`,
			"unsupported", "targeted lookups for this connector are not available yet", 0,
		},
		{
			"aks",
			[]auth.Provider{&named{name: "aks"}},
			`{"connector":"aks","operation":"x","aks_auth":{}}`,
			"unsupported", "targeted lookups for this connector are not available yet", 0,
		},
		{
			"azure",
			[]auth.Provider{&named{name: "azure"}},
			`{"connector":"azure","operation":"x","azure_auth":{}}`,
			"unsupported", "targeted lookups for this connector are not available yet", 0,
		},
		{
			"no support, no block",
			[]auth.Provider{&named{name: "eks"}},
			`{"connector":"eks","operation":"x"}`,
			"unsupported", `connector "eks" has no API reference support`, 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ex := &fakeExec{}
			r := runTargeted(t.Context(), t, tc.providers, &refSink{}, ex, tc.args)
			if r.err != nil || r.parsed.Outcome != tc.outcome || (tc.reason != "" && r.parsed.Reason != tc.reason) {
				t.Fatalf("got %s (%v)", r.out, r.err)
			}
			prepared := 0
			if len(tc.providers) == 1 {
				if tp, ok := tc.providers[0].(*targetProvider); ok {
					prepared = len(tp.raw)
				}
			}
			if prepared != tc.prepared || len(ex.args) != 0 {
				t.Errorf("PrepareLookup ran %d times, %d reads", prepared, len(ex.args))
			}
			if r.decision.Unprompted != (tc.outcome == "found") {
				t.Errorf("unprompted = %v", r.decision.Unprompted)
			}
		})
	}
}

func TestAPIReferenceTargeted_OnlyTheOwnBlockReachesPrepareLookup(t *testing.T) {
	t.Parallel()
	p := newTarget("kubernetes", readsAndAnswers(nil, nil))
	args := `{"connector":"kubernetes","service":"","model":"apps/v1","operation":"listThings",` +
		`"aws_auth":"x","kubernetes_auth":{"a":1},"kubernetes_auth":{"b":2},"gke_auth":5}`
	if r := runTargeted(t.Context(), t, []auth.Provider{p}, nil, &fakeExec{}, args); r.parsed.Outcome != "found" {
		t.Fatalf("got %s", r.out)
	}
	want := apiref.Query{Connector: "kubernetes", Model: "apps/v1", Operation: "listThings"}
	if !slices.Equal(p.raw, []string{`{"b":2}`}) || p.query[0] != want {
		t.Errorf("PrepareLookup got %q %+v", p.raw, p.query)
	}
}

func TestAPIReferenceTargeted_PublicAnswersIgnoreEveryBlock(t *testing.T) {
	t.Parallel()
	aws := &docProvider{name: "aws", res: apiref.Result{Outcome: apiref.OutcomeNotFound, Reason: "no such op"}}
	base, _, _ := runRef(t, []auth.Provider{aws}, `{"connector":"aws","service":"iam","operation":"X"}`)
	for _, extra := range []string{
		`,"aws_auth":{"service":"iam"}`, `,"aws_auth":"x"`, `,"gke_auth":5`, `,"kubernetes_auth":{}`,
		`,"azure_auth":[1]`,
	} {
		got, _, _ := runRef(t, []auth.Provider{aws}, `{"connector":"aws","service":"iam","operation":"X"`+extra+`}`)
		if got != base {
			t.Errorf("%s changed the public answer:\n%s\nwant\n%s", extra, got, base)
		}
	}
	both := &bothProvider{targetProvider: newTarget("both", readsAndAnswers(nil, nil))}
	if r := runTargeted(t.Context(), t, []auth.Provider{both}, nil, &fakeExec{},
		`{"connector":"both","operation":"listThings"}`); r.parsed.Reason != "public answer" {
		t.Errorf("without its block: %s", r.out)
	}
}

func TestAPIReferenceTargeted_BothInterfacesGoTargetedWithTheirBlock(t *testing.T) {
	t.Parallel()
	both := &bothProvider{targetProvider: newTarget("aws", readsAndAnswers(nil, nil))}
	r := runTargeted(t.Context(), t, []auth.Provider{both}, nil, &fakeExec{},
		`{"connector":"aws","model":"m","operation":"listThings","aws_auth":{}}`)
	if r.parsed.Outcome != "found" || len(both.raw) != 1 {
		t.Errorf("with its block: %s", r.out)
	}
}

func TestAPIReferenceTargeted_ReaderRecords(t *testing.T) {
	t.Parallel()
	var errs []error
	p := newTarget("kubernetes", readsAndAnswers([]string{"/openapi/v3", "/version"}, &errs))
	sink := &refSink{}
	ex := &fakeExec{route: true, resp: func(args string) (*transport.Response, error) {
		if strings.Contains(args, "/version") {
			return nil, errors.New("http request failed: dial tcp: refused")
		}
		return &transport.Response{Status: 404, Body: "SECRET BODY"}, nil
	}}
	r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, ex,
		`{"connector":"kubernetes","model":"apps/v1","operation":"listThings","KUBERNETES_AUTH":{"x":1}}`)
	if r.err != nil || r.parsed.Outcome != "found" {
		t.Fatalf("got %s %v", r.out, r.err)
	}
	wantArgs := `{"method":"GET","url":"https://k8s.example:6443/openapi/v3","headers":[{"key":"Accept",` +
		`"value":"application/json"}],"timeout_seconds":20,"max_response_body_size":2097152,` +
		`"auth_provider":"kubernetes","kubernetes_auth":{}}`
	if len(ex.args) != 2 || ex.args[0] != wantArgs {
		t.Fatalf("read arguments:\n%q\nwant\n%s", ex.args, wantArgs)
	}
	if len(sink.recs) != 4 {
		t.Fatalf("want 4 child records, got %+v", sink.recs)
	}
	ok := `{"status":404,"bytes":11,"sha256":"` + sha256Hex("SECRET BODY") + `","truncated":false}`
	for i, want := range []struct{ phase, call, decision, outcome, result, route string }{
		{audit.PhaseAttempt, "K1", "", "", "", ""},
		{audit.PhaseResult, "K1", audit.DecisionUnprompted, audit.OutcomeError, ok, audit.RouteProxy},
		{audit.PhaseAttempt, "K2", "", "", "", ""},
		{
			audit.PhaseResult, "K2", audit.DecisionUnprompted, audit.OutcomeError, "http request failed: dial tcp: refused",
			audit.RouteProxy,
		},
	} {
		rec := sink.recs[i]
		if rec.Phase != want.phase || rec.CallID != want.call || rec.ParentCallID != "PARENT" || rec.SessionID != "S" ||
			rec.RunID != "R" || rec.Depth != 1 || rec.Tool != audit.ToolLookupRead || rec.Via != audit.ViaAPIReference ||
			!rec.RedactArgs || rec.Decision != want.decision || rec.Outcome != want.outcome || rec.Result != want.result ||
			rec.Route != want.route || string(rec.Arguments) != ex.args[i/2] {
			t.Errorf("record %d = %+v", i, rec)
		}
		if strings.Contains(rec.Result, "SECRET") {
			t.Errorf("record %d logged the body", i)
		}
	}
	if r.fail.Count() != 0 || r.fail.Progress() != 1 {
		t.Errorf("the call credited %d failures and %d progress, want 0 and 1", r.fail.Count(), r.fail.Progress())
	}
	if errs[0] != nil || errs[1] == nil {
		t.Errorf("read errors = %v", errs)
	}
}

func TestAPIReferenceTargeted_OKResultAndAnOwnBlock(t *testing.T) {
	t.Parallel()
	p := newTarget("kubernetes", func(ctx context.Context, rd auth.MetadataReader) apiref.Result {
		resp, err := rd.Read(ctx, auth.MetadataRead{
			Path: "/x", Block: json.RawMessage(`{"own":1}`), MaxBytes: 7,
			Timeout: 3 * time.Second,
		})
		if err != nil || resp != (auth.MetadataResponse{Status: 200, Body: "B", Truncated: true}) {
			return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: fmt.Sprint(resp, err)}
		}
		return foundRef()
	})
	p.lookup.admit = func(auth.MetadataRead) bool { return true }
	sink := &refSink{}
	ex := &fakeExec{resp: func(string) (*transport.Response, error) {
		return &transport.Response{Status: 200, Body: "B", Truncated: true}, nil
	}}
	r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, ex, k8sArgs)
	if r.parsed.Outcome != "found" || !strings.HasSuffix(ex.args[0], `"timeout_seconds":3,"max_response_body_size":7,`+
		`"auth_provider":"kubernetes","kubernetes_auth":{"own":1}}`) {
		t.Fatalf("got %s with %q", r.out, ex.args)
	}
	if rec := sink.recs[1]; rec.Outcome != audit.OutcomeOK || rec.Route != audit.RouteDirect ||
		rec.Result != `{"status":200,"bytes":1,"sha256":"`+sha256Hex("B")+`","truncated":true}` {
		t.Errorf("result record = %+v", rec)
	}
}

func TestAPIReferenceTargeted_BudgetAndAdmit(t *testing.T) {
	t.Parallel()
	var errs []error
	paths := []string{"/1", "/2", "/3", "/4", "/5", "/6", "/7"}
	p := newTarget("kubernetes", func(ctx context.Context, rd auth.MetadataReader) apiref.Result {
		for _, path := range paths {
			if _, err := rd.Read(ctx, auth.MetadataRead{Path: path}); err != nil {
				errs = append(errs, err)
				return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: err.Error()}
			}
		}
		return foundRef()
	})
	ex, sink := &fakeExec{}, &refSink{}
	r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, ex, k8sArgs)
	if r.parsed.Outcome != "unavailable" || r.parsed.Reason != "api_reference: the lookup's read budget is used up" ||
		len(ex.args) != 6 || len(sink.recs) != 12 {
		t.Errorf("budget: %s after %d reads and %d records", r.out, len(ex.args), len(sink.recs))
	}
	if r.fail.Count() != 1 || r.fail.Progress() != 0 {
		t.Errorf("an unavailable lookup credited %d failures, %d progress", r.fail.Count(), r.fail.Progress())
	}
	for _, read := range []auth.MetadataRead{{Path: "/other"}, {Path: "/ok", Block: json.RawMessage(`{}`)}} {
		refused := newTarget("kubernetes", func(ctx context.Context, rd auth.MetadataReader) apiref.Result {
			_, err := rd.Read(ctx, read)
			return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: fmt.Sprint(err)}
		})
		refused.lookup.admit = func(r auth.MetadataRead) bool { return r.Path == "/ok" && r.Block == nil }
		rex, rsink := &fakeExec{}, &refSink{}
		got := runTargeted(t.Context(), t, []auth.Provider{refused}, rsink, rex, k8sArgs)
		if got.parsed.Reason != "api_reference: the lookup does not admit this read" || len(rex.args) != 0 ||
			len(rsink.recs) != 0 {
			t.Errorf("%+v: %s, %d reads, %d records", read, got.out, len(rex.args), len(rsink.recs))
		}
	}
}

func TestAPIReferenceTargeted_NoSinkWritesNoRecords(t *testing.T) {
	t.Parallel()
	p := newTarget("kubernetes", readsAndAnswers([]string{"/a"}, nil))
	ex := &fakeExec{}
	if r := runTargeted(t.Context(), t, []auth.Provider{p}, nil, ex, k8sArgs); r.parsed.Outcome != "found" ||
		len(ex.args) != 1 {
		t.Errorf("got %s after %d reads", r.out, len(ex.args))
	}
}

// TestAPIReferenceTargeted_FatalAuditWrites fails each of the six child writes of a root, document and /version
// read in turn. Run returns the ErrLog error whatever the recipe answered, and no read follows the failure.
func TestAPIReferenceTargeted_FatalAuditWrites(t *testing.T) {
	t.Parallel()
	for failAt := 1; failAt <= 6; failAt++ {
		var errs []error
		p := newTarget("kubernetes", readsAndAnswers([]string{"/openapi/v3", "/openapi/v3/apis/apps/v1", "/version"},
			&errs))
		ex, sink := &fakeExec{}, &refSink{failAt: failAt}
		r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, ex, k8sArgs)
		if !errors.Is(r.err, audit.ErrLog) || r.out != "" || len(ex.args) != failAt/2 || len(sink.recs) != failAt {
			t.Errorf("write %d failed: out %q err %v, %d reads, %d records", failAt, r.out, r.err, len(ex.args),
				len(sink.recs))
		}
	}
}

func TestAPIReferenceTargeted_ResolveFailures(t *testing.T) {
	t.Parallel()
	p := newTarget("kubernetes", readsAndAnswers(nil, nil))
	p.lookup.resolve = func(context.Context) error { return errors.New("no such cluster " + strings.Repeat("x", 600)) }
	r := runTargeted(t.Context(), t, []auth.Provider{p}, nil, &fakeExec{}, k8sArgs)
	if r.parsed.Outcome != "unavailable" ||
		!strings.HasPrefix(r.parsed.Reason, "resolving the target failed: no such") ||
		len([]rune(r.parsed.Reason)) > apiref.MaxReason {
		t.Errorf("got %s", r.out)
	}
	latched := newTarget("kubernetes", readsAndAnswers(nil, nil))
	latched.lookup.resolve = func(ctx context.Context) error {
		f, _ := audit.FatalFrom(ctx)
		f.Set(fmt.Errorf("%w: resolve", audit.ErrLog))
		return errors.New("resolve failed")
	}
	if lr := runTargeted(t.Context(), t, []auth.Provider{latched}, nil, &fakeExec{}, k8sArgs); !errors.Is(lr.err,
		audit.ErrLog) {
		t.Errorf("a latch set during Resolve: %s %v", lr.out, lr.err)
	}
}

func TestAPIReferenceTargeted_DeadlineAndInterrupt(t *testing.T) {
	t.Parallel()
	waits := func(ctx context.Context, _ auth.MetadataReader) apiref.Result {
		<-ctx.Done() // ignores the context's error and answers anyway.
		return foundRef()
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if r := runTargeted(ctx, t, []auth.Provider{newTarget("kubernetes", waits)}, nil, &fakeExec{}, k8sArgs); r.parsed.
		Reason != "the lookup timed out after 120s" || r.parsed.Outcome != "unavailable" {
		t.Errorf("deadline: %s", r.out)
	}
	ictx, interrupt := context.WithCancel(t.Context())
	p := newTarget("kubernetes", func(context.Context, auth.MetadataReader) apiref.Result {
		interrupt()
		return foundRef()
	})
	if r := runTargeted(ictx, t, []auth.Provider{p}, nil, &fakeExec{}, k8sArgs); r.parsed.Reason !=
		"the lookup was interrupted" {
		t.Errorf("interrupt during Answer: %s", r.out)
	}
	rctx, stop := context.WithCancel(t.Context())
	answered := false
	early := newTarget("kubernetes", func(context.Context, auth.MetadataReader) apiref.Result {
		answered = true
		return foundRef()
	})
	early.lookup.resolve = func(context.Context) error { stop(); return nil }
	if r := runTargeted(rctx, t, []auth.Provider{early}, nil, &fakeExec{}, k8sArgs); r.parsed.Reason !=
		"the lookup was interrupted" || answered {
		t.Errorf("interrupt during Resolve: %s, answered %v", r.out, answered)
	}
	lctx, lcancel := context.WithTimeout(t.Context(), time.Second)
	defer lcancel()
	latch := newTarget("kubernetes", func(ctx context.Context, rd auth.MetadataReader) apiref.Result {
		_, _ = rd.Read(ctx, auth.MetadataRead{Path: "/a"})
		<-ctx.Done()
		return foundRef()
	})
	if r := runTargeted(lctx, t, []auth.Provider{latch}, &refSink{failAt: 1}, &fakeExec{}, k8sArgs); !errors.Is(r.err,
		audit.ErrLog) {
		t.Errorf("the latch lost to the deadline: %s %v", r.out, r.err)
	}
}

// loopTarget is a TargetDocumenter over the loopback test provider, so its reads run through the real transport.
type loopTarget struct {
	*authtest.LoopbackProvider

	lookup *fakeLookup
}

func (p *loopTarget) PrepareLookup(apiref.Query, json.RawMessage) (auth.TargetLookup, error) {
	l := *p.lookup
	l.block = json.RawMessage(`{}`)

	return &l, nil
}

// TestAPIReferenceTargeted_ReadsThroughTheTransport runs a lookup's reads through transport.Client against a TLS
// server: each arrives as a GET with the one Accept header and no body, and a 301 comes back as a status, never
// followed.
func TestAPIReferenceTargeted_ReadsThroughTheTransport(t *testing.T) {
	t.Parallel()
	type seen struct{ method, path, query, accept, auth string }
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{
			r.Method, r.URL.Path, r.URL.RawQuery, strings.Join(r.Header.Values("Accept"), ","),
			r.Header.Get("Authorization"),
		})
		mu.Unlock()
		if r.URL.RawQuery != "" {
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte(`{"paths":{}}`))
	}))
	t.Cleanup(srv.Close)
	var statuses []int
	p := &loopTarget{
		LoopbackProvider: &authtest.LoopbackProvider{
			ProviderName: "kubernetes",
			CACert:       tlsCertBase64(t, srv),
			Token:        "tok",
		},
		lookup: &fakeLookup{target: auth.Target{Endpoint: srv.URL}, answer: func(ctx context.Context,
			rd auth.MetadataReader,
		) apiref.Result {
			for _, path := range []string{"/openapi/v3", "/openapi/v3/apis/apps/v1?hash=AB"} {
				resp, err := rd.Read(ctx, auth.MetadataRead{Path: path, MaxBytes: 1 << 20, Timeout: 5 * time.Second})
				if err != nil {
					return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: err.Error()}
				}
				statuses = append(statuses, resp.Status)
			}
			return foundRef()
		}},
	}
	sink := &refSink{}
	ctx := audit.WithScope(t.Context(), audit.Scope{CallID: "PARENT"})
	out, err := tools.NewAPIReferenceTool([]auth.Provider{p}, nil, sink).Run(ctx, k8sArgs)
	if err != nil || !strings.Contains(out, `"outcome":"found"`) {
		t.Fatalf("got %s %v", out, err)
	}
	want := []seen{
		{http.MethodGet, "/openapi/v3", "", "application/json", "Bearer tok"},
		{http.MethodGet, "/openapi/v3/apis/apps/v1", "hash=AB", "application/json", "Bearer tok"},
	}
	if !slices.Equal(got, want) || !slices.Equal(statuses, []int{200, 301}) {
		t.Errorf("server saw %+v, statuses %v", got, statuses)
	}
	if len(sink.recs) != 4 || sink.recs[1].Route != audit.RouteDirect || sink.recs[3].Outcome != audit.OutcomeOK {
		t.Errorf("records %+v", sink.recs)
	}
}

// TestAPIReferenceTargeted_InstallsTheLookupDeadline checks the deadline the tool itself sets: under a parent with
// none, Resolve sees one about 120 seconds away.
func TestAPIReferenceTargeted_InstallsTheLookupDeadline(t *testing.T) {
	t.Parallel()
	var deadline time.Time
	var has bool
	p := newTarget("kubernetes", readsAndAnswers(nil, nil))
	p.lookup.resolve = func(ctx context.Context) error {
		deadline, has = ctx.Deadline()
		return nil
	}
	if _, parentHas := t.Context().Deadline(); parentHas {
		t.Fatal("the test context carries a deadline of its own")
	}
	start := time.Now()
	if r := runTargeted(t.Context(), t, []auth.Provider{p}, nil, &fakeExec{}, k8sArgs); r.parsed.Outcome != "found" {
		t.Fatalf("got %s", r.out)
	}
	end := time.Now()
	if !has || deadline.Before(start.Add(auth.TargetLookupDeadline)) ||
		deadline.After(end.Add(auth.TargetLookupDeadline)) {
		t.Errorf("Resolve saw deadline %v (set %v); want %v after the call, between %v and %v", deadline, has,
			auth.TargetLookupDeadline, start, end)
	}
}
