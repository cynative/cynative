package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// loopLookup is a targeted lookup whose recipe reads the given paths, then answers.
type loopLookup struct {
	endpoint string
	paths    []string
	answer   apiref.Outcome
}

func (l *loopLookup) Block() json.RawMessage { return json.RawMessage(`{}`) }

func (l *loopLookup) Resolve(context.Context) (auth.Target, error) {
	return auth.Target{Endpoint: l.endpoint}, nil
}

func (l *loopLookup) Admit(auth.Target, auth.MetadataRead) bool { return true }

func (l *loopLookup) Answer(ctx context.Context, _ auth.Target, rd auth.MetadataReader) apiref.Result {
	for _, p := range l.paths {
		_, _ = rd.Read(ctx, auth.MetadataRead{Path: p, MaxBytes: 1 << 20, Timeout: 5 * time.Second})
	}
	if l.answer != apiref.OutcomeFound {
		return apiref.Result{Outcome: l.answer, Reason: "GET /openapi/v3 answered 503"}
	}

	return apiref.Result{Outcome: apiref.OutcomeFound, Reference: &apiref.Reference{
		Connector: "kubernetes", Operation: "listThings", Method: http.MethodGet, PathTemplate: "/x",
		Endpoint: l.endpoint, BodyEncoding: apiref.BodyNone,
	}}
}

// loopTargetProvider is a targeted connector over the loopback test provider, so its reads run the real
// transport against an httptest TLS server.
type loopTargetProvider struct {
	*authtest.LoopbackProvider

	lookup *loopLookup
}

func (p *loopTargetProvider) PrepareLookup(apiref.Query, json.RawMessage) (auth.TargetLookup, error) {
	return p.lookup, nil
}

// lookupServer answers the root 200, a hashed document 301 and /version 404, or 503 to everything.
func lookupServer(t *testing.T, failing bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case failing:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.RawQuery != "":
			http.Redirect(w, r, r.URL.Path, http.StatusMovedPermanently)
		case r.URL.Path == "/version":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(`{"paths":{}}`))
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

func dispatchLookup(t *testing.T, failing bool, outcome apiref.Outcome) ([]audit.Record, int) {
	t.Helper()
	srv := lookupServer(t, failing)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	}))
	p := &loopTargetProvider{
		LoopbackProvider: &authtest.LoopbackProvider{ProviderName: "kubernetes", CACert: ca},
		lookup: &loopLookup{
			endpoint: srv.URL, paths: []string{"/openapi/v3", "/openapi/v3/apis/apps/v1?hash=AB", "/version"},
			answer: outcome,
		},
	}
	sink := &recordingSink{} //nolint:exhaustruct // failOn/failErr zero-init means never-fail.
	tool := tools.NewAPIReferenceTool([]auth.Provider{p}, nil, sink)
	a := auditAgent(sink, map[string]schema.InvokableTool{"api_reference": tool})
	rs := &runState{depth: 1, out: io.Discard, runID: "R"}
	_, credited, err := a.dispatch(context.Background(), rs, dispatchTC("api_reference",
		`{"connector":"kubernetes","model":"apps/v1","operation":"listThings","kubernetes_auth":{}}`))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	return sink.recs, credited
}

// TestDispatch_TargetedLookupAuditsEachRead pins the record order (the lookup's attempt, a pair per read, the
// lookup's result), the parent call ID, depth and decision of every child record, a route per child result, and
// that a found lookup after a 301 and a /version 404 credits no failure.
func TestDispatch_TargetedLookupAuditsEachRead(t *testing.T) {
	t.Parallel()
	recs, credited := dispatchLookup(t, false, apiref.OutcomeFound)
	if len(recs) != 8 {
		t.Fatalf("want 8 records, got %d: %+v", len(recs), recs)
	}
	first, last := recs[0], recs[7]
	if first.Tool != "api_reference" || first.Phase != audit.PhaseAttempt || first.CallID != "C1" ||
		last.Tool != "api_reference" || last.Phase != audit.PhaseResult || last.Decision != audit.DecisionUnprompted ||
		last.Outcome != audit.OutcomeOK || last.Route != "" {
		t.Errorf("lookup records: %+v / %+v", first, last)
	}
	wantOutcome := []string{audit.OutcomeOK, audit.OutcomeOK, audit.OutcomeError}
	for i := range 3 {
		attempt, result := recs[1+2*i], recs[2+2*i]
		for _, r := range []audit.Record{attempt, result} {
			if r.Tool != audit.ToolLookupRead || r.Via != audit.ViaAPIReference || r.ParentCallID != "C1" ||
				r.Depth != 1 || r.RunID != "R" || r.SessionID != "S" || r.CallID != attempt.CallID || r.CallID == "C1" {
				t.Errorf("read %d record %+v", i, r)
			}
		}
		if attempt.Phase != audit.PhaseAttempt || result.Phase != audit.PhaseResult ||
			result.Decision != audit.DecisionUnprompted || result.Route != audit.RouteDirect ||
			result.Outcome != wantOutcome[i] {
			t.Errorf("read %d pair %+v / %+v", i, attempt, result)
		}
	}
	if credited != 0 {
		t.Errorf("a found lookup credited %d failures", credited)
	}
}

func TestDispatch_UnavailableLookupCreditsOneFailure(t *testing.T) {
	t.Parallel()
	recs, credited := dispatchLookup(t, true, apiref.OutcomeUnavailable)
	if len(recs) != 8 || recs[7].Outcome != audit.OutcomeError || recs[7].Decision != audit.DecisionUnprompted {
		t.Fatalf("records %+v", recs)
	}
	if credited != 1 {
		t.Errorf("an unavailable lookup after three failed reads credited %d failures, want 1", credited)
	}
}
