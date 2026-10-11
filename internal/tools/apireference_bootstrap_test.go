package tools_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/tools"
)

// bootstrapStep is one control-plane call a fake resolution reports: its names and how it ends.
type bootstrapStep struct {
	connector, call, target string
	err                     error
}

// bootstrapsThen is a Resolve that reports each step to the lookup's observer as a connector's resolution would:
// it stops at the first refusal or failure, and sent records whether each step's vendor call ran.
func bootstrapsThen(steps []bootstrapStep, sent *[]bool) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		o, ok := auth.BootstrapObserverFrom(ctx)
		if !ok {
			return errors.New("no bootstrap observer on the lookup's context")
		}
		for _, s := range steps {
			end, err := o.Begin(s.connector, s.call, s.target)
			if err != nil {
				*sent = append(*sent, false)
				return err
			}
			*sent = append(*sent, true)
			end(s.err)
			if s.err != nil {
				return s.err
			}
		}

		return nil
	}
}

const eksLookup = `{"connector":"eks","model":"v1","operation":"listCoreV1Namespace","eks_auth":{"cluster_name":"c"}}`

// TestAPIReferenceTargeted_BootstrapRecords pins the record pair each control-plane call writes: a fresh call ID
// under the lookup's, its session, run and depth, the connector, call and target and nothing else as arguments,
// redacted, and on the result the unprompted decision with ok, or the error cut to 500 runes. The pairs come
// before the lookup's reads.
func TestAPIReferenceTargeted_BootstrapRecords(t *testing.T) {
	t.Parallel()
	long := errors.New(strings.Repeat("é", 600))
	var sent []bool
	p := newTarget("eks", readsAndAnswers([]string{"/openapi/v3"}, nil))
	p.lookup.resolve = bootstrapsThen([]bootstrapStep{
		{"eks", "DescribeCluster", "eks/us-east-1/c", nil},
		{"eks", "clusterrole", "eks/us-east-1/c clusterroles/view", long},
	}, &sent)
	sink := &refSink{}
	r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, &fakeExec{}, eksLookup)
	if r.err != nil || r.parsed.Outcome != "unavailable" || len(sink.recs) != 4 {
		t.Fatalf("got %s %v, %d records", r.out, r.err, len(sink.recs))
	}
	describe := `{"connector":"eks","call":"DescribeCluster","target":"eks/us-east-1/c"}`
	role := `{"connector":"eks","call":"clusterrole","target":"eks/us-east-1/c clusterroles/view"}`
	for i, want := range []struct{ call, phase, args, decision, outcome, result string }{
		{"K1", audit.PhaseAttempt, describe, "", "", ""},
		{"K1", audit.PhaseResult, describe, audit.DecisionUnprompted, audit.OutcomeOK, "ok"},
		{"K2", audit.PhaseAttempt, role, "", "", ""},
		{"K2", audit.PhaseResult, role, audit.DecisionUnprompted, audit.OutcomeError, strings.Repeat("é", 497) + "..."},
	} {
		rec := sink.recs[i]
		if rec.CallID != want.call || rec.ParentCallID != "PARENT" || rec.SessionID != "S" || rec.RunID != "R" ||
			rec.Depth != 1 || rec.Phase != want.phase || rec.Via != audit.ViaAPIReference ||
			rec.Tool != audit.ToolLookupBootstrap || string(rec.Arguments) != want.args || !rec.RedactArgs ||
			rec.Decision != want.decision || rec.Outcome != want.outcome || rec.Result != want.result ||
			rec.Route != "" {
			t.Errorf("record %d = %+v", i, rec)
		}
	}
}

// TestAPIReferenceTargeted_BootstrapThenReads pins the physical order when resolution succeeds: the bootstrap
// pairs, then each read's pair.
func TestAPIReferenceTargeted_BootstrapThenReads(t *testing.T) {
	t.Parallel()
	var sent []bool
	p := newTarget("eks", readsAndAnswers([]string{"/openapi/v3"}, nil))
	p.lookup.resolve = bootstrapsThen([]bootstrapStep{{"eks", "DescribeCluster", "eks/us-east-1/c", nil}}, &sent)
	sink := &refSink{}
	r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, &fakeExec{}, eksLookup)
	if r.err != nil || r.parsed.Outcome != "found" || len(sink.recs) != 4 {
		t.Fatalf("got %s %v, %d records", r.out, r.err, len(sink.recs))
	}
	for i, tool := range []string{
		audit.ToolLookupBootstrap, audit.ToolLookupBootstrap, audit.ToolLookupRead, audit.ToolLookupRead,
	} {
		if sink.recs[i].Tool != tool {
			t.Errorf("record %d is %s, want %s", i, sink.recs[i].Tool, tool)
		}
	}
}

// TestAPIReferenceTargeted_BootstrapWriteFailures pins that a failed attempt write refuses the call before it is
// sent and every call after it, a failed result write latches too, and either one makes the lookup's Go error
// the audit failure, whatever the recipe would have answered.
func TestAPIReferenceTargeted_BootstrapWriteFailures(t *testing.T) {
	t.Parallel()
	steps := []bootstrapStep{
		{"gke", "clusters.get", "gke/p/l/c", nil},
		{"gke", "clusterrole", "gke/p/l/c clusterroles/view", nil},
	}
	for _, tc := range []struct {
		name    string
		failAt  int
		sent    []bool
		records int
	}{
		{"the first attempt", 1, []bool{false}, 1},
		{"the first result", 2, []bool{true, false}, 2},
		{"the second attempt", 3, []bool{true, false}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var sent []bool
			p := newTarget("gke", readsAndAnswers([]string{"/openapi/v3"}, nil))
			p.lookup.resolve = bootstrapsThen(steps, &sent)
			sink := &refSink{failAt: tc.failAt}
			ex := &fakeExec{}
			r := runTargeted(t.Context(), t, []auth.Provider{p}, sink, ex,
				`{"connector":"gke","model":"v1","operation":"x","gke_auth":{}}`)
			if !errors.Is(r.err, audit.ErrLog) || r.out != "" {
				t.Errorf("Run = %q, %v; want the audit error", r.out, r.err)
			}
			if !slices.Equal(sent, tc.sent) || len(sink.recs) != tc.records || len(ex.args) != 0 {
				t.Errorf("sent %v, %d records, %d reads; want sent %v and %d records, no read", sent,
					len(sink.recs), len(ex.args), tc.sent, tc.records)
			}
		})
	}
}

// TestAPIReferenceTargeted_BootstrapWithoutSink pins that with audit disabled the observer writes nothing and
// refuses nothing.
func TestAPIReferenceTargeted_BootstrapWithoutSink(t *testing.T) {
	t.Parallel()
	var sent []bool
	p := newTarget("aks", readsAndAnswers([]string{"/openapi/v3"}, nil))
	p.lookup.resolve = bootstrapsThen([]bootstrapStep{
		{"aks", "ListClusterUserCredentials", "aks/s/rg/c", nil},
	}, &sent)
	r := runTargeted(t.Context(), t, []auth.Provider{p}, nil, &fakeExec{},
		`{"connector":"aks","model":"v1","operation":"x","aks_auth":{}}`)
	if r.err != nil || r.parsed.Outcome != "found" || len(sent) != 1 || !sent[0] {
		t.Errorf("got %s %v, sent %v", r.out, r.err, sent)
	}
}

// switchWriter accepts writes until fail is set, then fails every one.
type switchWriter struct {
	mu   sync.Mutex
	fail bool
}

func (w *switchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		return 0, errors.New("disk full")
	}

	return len(p), nil
}

func (w *switchWriter) failNow() {
	w.mu.Lock()
	w.fail = true
	w.mu.Unlock()
}

// TestAPIReferenceTargeted_ALateBootstrapResultLatchesTheLogger pins the call that outlives its lookup: the
// lookup returns while the call is still running, the call's result record is written when it ends, and a failure
// of that late write is kept by the Logger for the closer to report.
func TestAPIReferenceTargeted_ALateBootstrapResultLatchesTheLogger(t *testing.T) {
	t.Parallel()
	release, done := make(chan struct{}), make(chan struct{})
	p := newTarget("eks", func(context.Context, auth.MetadataReader) apiref.Result {
		return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "resolving the target timed out"}
	})
	p.lookup.resolve = func(ctx context.Context) error {
		o, _ := auth.BootstrapObserverFrom(ctx)
		end, err := o.Begin("eks", "DescribeCluster", "eks/us-east-1/c")
		if err != nil {
			return err
		}
		go func() {
			<-release
			end(nil)
			close(done)
		}()

		return nil
	}
	w := &switchWriter{}
	l := audit.New(w)
	r := runTargeted(t.Context(), t, []auth.Provider{p}, l, &fakeExec{}, eksLookup)
	if r.err != nil || l.Err() != nil {
		t.Fatalf("Run = %v, latched %v; want both nil while the call runs", r.err, l.Err())
	}
	w.failNow()
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the late result was never written")
	}
	if !errors.Is(l.Err(), audit.ErrLog) {
		t.Errorf("Logger.Err() = %v after the late write failed, want the audit error", l.Err())
	}
}

// TestAPIReferenceTargeted_BootstrapResultIsScrubbed pins that a failed call's error text loses the operator's
// proxy credential before it reaches the result record.
func TestAPIReferenceTargeted_BootstrapResultIsScrubbed(t *testing.T) {
	t.Parallel()
	egress, err := auth.NewEgress(func(k string) (string, bool) {
		if k == "HTTPS_PROXY" {
			return "http://user:s3cretpw@proxy.test:3128", true
		}

		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	var sent []bool
	p := newTarget("eks", readsAndAnswers(nil, nil))
	p.lookup.resolve = bootstrapsThen([]bootstrapStep{{
		"eks", "DescribeCluster", "eks/us-east-1/c",
		errors.New("proxyconnect tcp: dial http://user:s3cretpw@proxy.test:3128: refused"),
	}}, &sent)
	sink := &refSink{}
	ctx := audit.WithScope(t.Context(), audit.Scope{SessionID: "S", RunID: "R", Depth: 1, CallID: "PARENT"})
	tool := tools.NewAPIReferenceToolWithOpts([]auth.Provider{p}, egress, sink,
		tools.WithReferenceIDFunc(func() string { return "K" }))
	if _, err = tool.Run(ctx, eksLookup); err != nil {
		t.Fatal(err)
	}
	if len(sink.recs) != 2 || strings.Contains(sink.recs[1].Result, "s3cretpw") ||
		!strings.Contains(sink.recs[1].Result, "[REDACTED:proxy-credential]") {
		t.Errorf("records %+v, want the result scrubbed", sink.recs)
	}
}

// TestAPIReferenceTargeted_TheCloserWaitsForALateBootstrapResult pins the hold a control-plane call takes on the
// Logger: the run's audit closer does not return while a call that outlived its lookup is still running, and once
// the call ends its result is written before the log closes.
func TestAPIReferenceTargeted_TheCloserWaitsForALateBootstrapResult(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	p := newTarget("eks", func(context.Context, auth.MetadataReader) apiref.Result {
		return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "resolving the target timed out"}
	})
	p.lookup.resolve = func(ctx context.Context) error {
		o, _ := auth.BootstrapObserverFrom(ctx)
		end, err := o.Begin("eks", "DescribeCluster", "eks/us-east-1/c")
		if err != nil {
			return err
		}
		go func() {
			<-release
			end(nil)
		}()

		return nil
	}
	w := &switchWriter{}
	l := audit.New(w, audit.WithDrain(time.Minute))
	if r := runTargeted(t.Context(), t, []auth.Provider{p}, l, &fakeExec{}, eksLookup); r.err != nil {
		t.Fatalf("Run = %v", r.err)
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Closer(func() error { return nil })() }()
	select {
	case err := <-closed:
		t.Fatalf("the closer returned %v while the control-plane call was still running", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("closer = %v after the late result was written", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the closer never returned after the call ended")
	}
}

// TestAPIReferenceTargeted_ARefusedBootstrapReleasesItsHold pins that a call refused because its attempt record
// could not be written holds nothing, so the closer reports the latched failure at once instead of waiting.
func TestAPIReferenceTargeted_ARefusedBootstrapReleasesItsHold(t *testing.T) {
	t.Parallel()
	var sent []bool
	p := newTarget("eks", func(context.Context, auth.MetadataReader) apiref.Result {
		return apiref.Result{Outcome: apiref.OutcomeFound}
	})
	p.lookup.resolve = bootstrapsThen([]bootstrapStep{{connector: "eks", call: "DescribeCluster", target: "t"}}, &sent)
	w := &switchWriter{}
	l := audit.New(w, audit.WithDrain(time.Minute))
	w.failNow()
	_ = runTargeted(t.Context(), t, []auth.Provider{p}, l, &fakeExec{}, eksLookup)
	start := time.Now()
	err := l.Closer(func() error { return nil })()
	if !errors.Is(err, audit.ErrLog) || time.Since(start) > 10*time.Second || slices.Contains(sent, true) {
		t.Errorf("closer = %v after %s, sent %v; want the latched failure at once and no call sent", err,
			time.Since(start), sent)
	}
}

// gatedWriter accepts writes until it is armed; the next write then blocks until released, so a test can hold a
// late record mid-write and see what the closer does meanwhile.
type gatedWriter struct {
	mu      sync.Mutex
	armed   bool
	writing chan struct{}
	release chan struct{}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	armed := w.armed
	w.armed = false
	w.mu.Unlock()
	if armed {
		close(w.writing)
		<-w.release
	}

	return len(p), nil
}

// TestAPIReferenceTargeted_TheLogClosesOnlyAfterTheLateResultIsWritten pins the order inside the hold: the hold is
// released only once the late result record is written, so the writer is never closed under it.
func TestAPIReferenceTargeted_TheLogClosesOnlyAfterTheLateResultIsWritten(t *testing.T) {
	t.Parallel()
	end := make(chan struct{})
	p := newTarget("eks", func(context.Context, auth.MetadataReader) apiref.Result {
		return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "resolving the target timed out"}
	})
	p.lookup.resolve = func(ctx context.Context) error {
		o, _ := auth.BootstrapObserverFrom(ctx)
		done, err := o.Begin("eks", "DescribeCluster", "eks/us-east-1/c")
		if err != nil {
			return err
		}
		go func() {
			<-end
			done(nil)
		}()

		return nil
	}
	w := &gatedWriter{writing: make(chan struct{}), release: make(chan struct{})}
	l := audit.New(w, audit.WithDrain(time.Minute))
	if r := runTargeted(t.Context(), t, []auth.Provider{p}, l, &fakeExec{}, eksLookup); r.err != nil {
		t.Fatalf("Run = %v", r.err)
	}
	w.mu.Lock()
	w.armed = true
	w.mu.Unlock()
	closedEarly := make(chan struct{}, 1)
	closed := make(chan error, 1)
	go func() {
		closed <- l.Closer(func() error {
			select {
			case <-w.writing:
				select {
				case <-w.release:
				default:
					closedEarly <- struct{}{}
				}
			default:
			}
			return nil
		})()
	}()
	close(end)
	<-w.writing
	// The late result is mid-write now. Give a closer that does not wait for it time to reach the writer.
	time.Sleep(100 * time.Millisecond)
	close(w.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("closer = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the closer never returned")
	}
	select {
	case <-closedEarly:
		t.Error("the writer was closed while the late result record was still being written")
	default:
	}
}
