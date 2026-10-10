package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/transport"
)

// targetReadBudget bounds the credentialed reads one targeted lookup makes. A recipe that asks for more is a bug.
const targetReadBudget = 6

var (
	// errReadBudget refuses a read past the lookup's budget.
	errReadBudget = errors.New("api_reference: the lookup's read budget is used up")
	// errReadNotAdmitted refuses a read the lookup's own Admit rejects.
	errReadNotAdmitted = errors.New("api_reference: the lookup does not admit this read")
)

// targeted runs a lookup that reads the target's own metadata with the connector's credentials, through the
// reader and nothing else. A failed audit write latches and becomes the call's Go error, whatever the recipe
// answered.
func (t *apiReferenceTool) targeted(
	ctx context.Context, name string, td auth.TargetDocumenter, q apiref.Query, block json.RawMessage,
) (string, error) {
	lookup, err := td.PrepareLookup(q, block)
	if err != nil {
		return rejected(ctx, err.Error()), nil
	}
	// From here the call can reach the connector's credentials, so it is audited unprompted.
	audit.RecordUnprompted(ctx)
	ctx, fatal := audit.WithFatal(ctx)
	scope, _ := audit.ScopeFrom(ctx)
	ctx = auth.WithBootstrapObserver(ctx, &bootstrapRecorder{tool: t, scope: scope, fatal: fatal})
	ctx, cancel := context.WithTimeout(ctx, auth.TargetLookupDeadline)
	defer cancel()
	target, err := lookup.Resolve(ctx)
	if ferr := fatal.Err(); ferr != nil {
		return "", ferr
	}
	var res apiref.Result
	switch {
	case err != nil:
		res = apiref.Result{
			Outcome: apiref.OutcomeUnavailable,
			Reason: "resolving the target failed: " + apiref.Truncate(
				t.egress.ScrubError(err).Error(),
				apiref.MaxReason,
			),
		}
	case ctx.Err() != nil:
		res = apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: auth.ContextReason(ctx)}
	default:
		rd := &metadataReader{tool: t, name: name, lookup: lookup, target: target, fatal: fatal}
		res = lookup.Answer(ctx, target, rd)
		if ferr := fatal.Err(); ferr != nil {
			return "", ferr
		}
		if ctx.Err() != nil {
			res = apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: auth.ContextReason(ctx)}
		}
	}

	return t.answer(ctx, res), nil
}

// metadataReader is one lookup's reader: it enforces the read budget and the lookup's Admit, writes each read's
// attempt record before the read and its result record after, and latches any failed write.
type metadataReader struct {
	tool   *apiReferenceTool
	name   string
	lookup auth.TargetLookup
	target auth.Target
	fatal  *audit.Fatal

	mu    sync.Mutex
	reads int
}

// readArgs is the fixed part of a read's http_request arguments.
type readArgs struct {
	Method              string               `json:"method"`
	URL                 string               `json:"url"`
	Headers             []transport.KeyValue `json:"headers"`
	TimeoutSeconds      int                  `json:"timeout_seconds"`
	MaxResponseBodySize int                  `json:"max_response_body_size"`
	AuthProvider        string               `json:"auth_provider"`
}

// readResult is what a read's result record says about a response; the body is never logged.
type readResult struct {
	Status    int    `json:"status"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
}

// Read performs one admitted, audited, credentialed GET on the lookup's target.
func (m *metadataReader) Read(ctx context.Context, r auth.MetadataRead) (auth.MetadataResponse, error) {
	if err := m.claim(r); err != nil {
		return auth.MetadataResponse{}, err
	}
	args := m.arguments(r)
	scope, _ := audit.ScopeFrom(ctx)
	rec := audit.Record{ //nolint:exhaustruct // an attempt carries no decision, outcome or result.
		SessionID: scope.SessionID, RunID: scope.RunID, CallID: m.tool.newID(), ParentCallID: scope.CallID,
		Depth: scope.Depth, Phase: audit.PhaseAttempt, Via: audit.ViaAPIReference, Tool: audit.ToolLookupRead,
		Arguments: audit.RawArgs(args), RedactArgs: true,
	}
	if err := m.log(rec); err != nil {
		return auth.MetadataResponse{}, err
	}
	// The read's failures and progress are its own: the lookup marks the call once, by its outcome.
	rctx, _ := audit.WithFailure(ctx)
	rctx, route := audit.WithRoute(rctx)
	resp, err := m.tool.execute(rctx, args, m.tool.providers)
	rec.Phase, rec.Decision, rec.Route = audit.PhaseResult, audit.DecisionUnprompted, route.Value()
	rec.Outcome, rec.Result = readOutcome(resp, err)
	if lerr := m.log(rec); lerr != nil {
		return auth.MetadataResponse{}, lerr
	}
	if err != nil {
		return auth.MetadataResponse{}, err
	}

	return auth.MetadataResponse{Status: resp.Status, Body: resp.Body, Truncated: resp.Truncated}, nil
}

// claim refuses a read once the latch is set, past the budget, or that the lookup does not admit, before any
// record is written.
func (m *metadataReader) claim(r auth.MetadataRead) error {
	if err := m.fatal.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reads >= targetReadBudget {
		return errReadBudget
	}
	if !m.lookup.Admit(m.target, r) {
		return errReadNotAdmitted
	}
	m.reads++

	return nil
}

// arguments builds the read's http_request arguments: GET on the target's endpoint plus the admitted path, the one
// Accept header, the read's bounds, the provider's name, and the block under <name>_auth.
func (m *metadataReader) arguments(r auth.MetadataRead) string {
	block := r.Block
	if block == nil {
		block = m.lookup.Block()
	}
	// readArgs is plain strings, ints and a slice of string pairs, so json.Marshal cannot fail on it.
	fixed, _ := json.Marshal(readArgs{
		Method:              http.MethodGet,
		URL:                 m.target.Endpoint + r.Path,
		Headers:             []transport.KeyValue{{Key: "Accept", Value: "application/json"}},
		TimeoutSeconds:      int(r.Timeout / time.Second),
		MaxResponseBodySize: r.MaxBytes,
		AuthProvider:        m.name,
	})
	name, _ := json.Marshal(m.name + "_auth") // a string marshals without error.

	return string(fixed[:len(fixed)-1]) + "," + string(name) + ":" + string(block) + "}"
}

// log writes one child record when audit is enabled, latching a failed write.
func (m *metadataReader) log(rec audit.Record) error { return m.tool.logChild(m.fatal, rec) }

// logChild writes one of a lookup's child records when audit is enabled, latching a failed write on fatal.
func (t *apiReferenceTool) logChild(fatal *audit.Fatal, rec audit.Record) error {
	if t.sink == nil {
		return nil
	}
	if err := t.sink.Log(rec); err != nil {
		fatal.Set(err)
		return err
	}

	return nil
}

// bootstrapOK is a bootstrap result record's result when the call succeeded.
const bootstrapOK = "ok"

// bootstrapRecorder is one lookup's BootstrapObserver: it writes a lookup_bootstrap attempt record before each
// control-plane call its resolution triggers and a result record after, and latches any failed write.
type bootstrapRecorder struct {
	tool  *apiReferenceTool
	scope audit.Scope
	fatal *audit.Fatal
}

// bootstrapArgs is a bootstrap record's arguments. It carries no url and no auth_provider, so the release-gate
// parser never reads one as a request.
type bootstrapArgs struct {
	Connector string `json:"connector"`
	Call      string `json:"call"`
	Target    string `json:"target"`
}

// Begin refuses the call once the latch is set or when its attempt record cannot be written, so a call is never
// sent without its attempt on record. The end it returns writes the result record, possibly after the lookup has
// returned; a failure then latches in the Logger too, which the run's audit closer reports.
func (b *bootstrapRecorder) Begin(connector, call, target string) (func(error), error) {
	if err := b.fatal.Err(); err != nil {
		return nil, err
	}
	// bootstrapArgs is three strings, so json.Marshal cannot fail on it.
	args, _ := json.Marshal(bootstrapArgs{Connector: connector, Call: call, Target: target})
	rec := audit.Record{ //nolint:exhaustruct // an attempt carries no decision, outcome or result.
		SessionID: b.scope.SessionID, RunID: b.scope.RunID, CallID: b.tool.newID(), ParentCallID: b.scope.CallID,
		Depth: b.scope.Depth, Phase: audit.PhaseAttempt, Via: audit.ViaAPIReference,
		Tool: audit.ToolLookupBootstrap, Arguments: args, RedactArgs: true,
	}
	if err := b.tool.logChild(b.fatal, rec); err != nil {
		return nil, err
	}

	return func(callErr error) {
		rec.Phase, rec.Decision, rec.Outcome, rec.Result = audit.PhaseResult, audit.DecisionUnprompted,
			audit.OutcomeOK, bootstrapOK
		if callErr != nil {
			rec.Outcome = audit.OutcomeError
			rec.Result = apiref.Truncate(b.tool.egress.ScrubError(callErr).Error(), apiref.MaxReason)
		}
		// Nothing waits on this error: logChild latched it on fatal, and the Logger keeps it for the closer.
		_ = b.tool.logChild(b.fatal, rec)
	}, nil
}

// readOutcome classifies a read for its result record: ok below 400, error at 400 or more or on a transport
// error, whose text is recorded as the transport returned it.
func readOutcome(resp *transport.Response, err error) (string, string) {
	if err != nil {
		return audit.OutcomeError, err.Error()
	}
	sum := sha256.Sum256([]byte(resp.Body))
	// readResult is plain ints, a string and a bool, so json.Marshal cannot fail on it.
	b, _ := json.Marshal(readResult{
		Status: resp.Status, Bytes: len(resp.Body), SHA256: hex.EncodeToString(sum[:]), Truncated: resp.Truncated,
	})
	outcome := audit.OutcomeOK
	if resp.Status >= statusFloor {
		outcome = audit.OutcomeError
	}

	return outcome, string(b)
}
