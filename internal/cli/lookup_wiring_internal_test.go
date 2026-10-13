package cli

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/schema"
)

// wiringLookup makes one read of the target's root, then answers whatever the read returned.
type wiringLookup struct{}

func (wiringLookup) Block() json.RawMessage { return json.RawMessage(`{}`) }

func (wiringLookup) Resolve(context.Context) (auth.Target, error) {
	return auth.Target{Endpoint: "https://k8s.example:6443"}, nil
}

func (wiringLookup) Admit(auth.Target, auth.MetadataRead) bool { return true }

func (wiringLookup) Answer(ctx context.Context, _ auth.Target, rd auth.MetadataReader) apiref.Result {
	_, err := rd.Read(ctx, auth.MetadataRead{Path: "/openapi/v3", MaxBytes: 1 << 10, Timeout: 2 * time.Second})
	if err == nil {
		return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "the read reached a server"}
	}

	return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: "the read failed"}
}

type wiringProvider struct{ *authtest.LoopbackProvider }

func (wiringProvider) PrepareLookup(apiref.Query, json.RawMessage) (auth.TargetLookup, error) {
	return wiringLookup{}, nil
}

type wiringSink struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (s *wiringSink) Log(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec)

	return nil
}

// TestBuildToolSet_TargetedLookupsUseTheSessionEgressAndSink pins the production wiring of api_reference: its reads
// leave through the operator's egress policy (the child result records the proxy route) and its child records go
// to the session's audit sink. The proxy is a closed loopback port, so the read fails after route selection.
func TestBuildToolSet_TargetedLookupsUseTheSessionEgressAndSink(t *testing.T) {
	t.Parallel()
	egress, err := auth.NewEgress(func(k string) (string, bool) {
		if k == "HTTPS_PROXY" {
			return "http://127.0.0.1:9", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	d := testDeps()
	d.ui = &fakeUI{} //nolint:exhaustruct // empty script
	sink := &wiringSink{}
	p := wiringProvider{&authtest.LoopbackProvider{ProviderName: "kubernetes"}}
	set, err := d.buildToolSet([]auth.Provider{p}, egress, validCfg(), researchFlags{}, io.Discard, sink)
	if err != nil {
		t.Fatal(err)
	}
	var ref schema.InvokableTool
	for _, tl := range set {
		if tl.Info().Name == "api_reference" {
			ref = tl
		}
	}
	out, err := ref.Run(t.Context(), `{"connector":"kubernetes","model":"v1","operation":"x","kubernetes_auth":{}}`)
	if err != nil {
		t.Fatalf("Run: %v %s", err, out)
	}
	if len(sink.recs) != 2 || sink.recs[0].Tool != audit.ToolLookupRead || sink.recs[1].Route != audit.RouteProxy {
		t.Fatalf("the session sink got %+v", sink.recs)
	}
}
