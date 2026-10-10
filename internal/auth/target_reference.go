package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cynative/cynative/internal/apiref"
)

// TargetLookupDeadline bounds one targeted lookup, from Resolve to the end of Answer. The api_reference tool sets it.
const TargetLookupDeadline = 120 * time.Second

// ContextReason is the unavailable reason for a lookup whose context is done: its deadline passed, or the run
// was interrupted.
func ContextReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "the lookup timed out after 120s"
	}

	return "the lookup was interrupted"
}

// TargetDocumenter is implemented by connectors whose API reference depends on the target: kubernetes now, the
// managed Kubernetes connectors and azure later. The api_reference tool routes a call to it when the call carries
// the connector's own auth block.
type TargetDocumenter interface {
	// PrepareLookup decodes raw, the connector's own block exactly as the tool call sent it, into the connector's
	// typed struct, re-marshals it as the canonical block, validates q and that block with no I/O, and returns the
	// lookup, which keeps both, validated and immutable, for its whole life.
	PrepareLookup(q apiref.Query, raw json.RawMessage) (TargetLookup, error)
}

// TargetLookup is one validated lookup. It is built per call and never shared.
type TargetLookup interface {
	// Block returns a copy of the canonical block, the bytes a read with a nil Block carries.
	Block() json.RawMessage
	// Resolve returns the target the block names. A connector that must resolve its target over the network does
	// that here.
	Resolve(ctx context.Context) (Target, error)
	// Admit reports whether r, its path and its block, is a read this lookup's recipe may make on t.
	Admit(t Target, r MetadataRead) bool
	// Answer runs the recipe. Credentialed reads go only through rd. It may also read the connector's own pinned
	// public sources, without credentials, the way an OperationDocumenter does.
	Answer(ctx context.Context, t Target, rd MetadataReader) apiref.Result
}

// Target is the endpoint a lookup resolved.
type Target struct {
	// Endpoint is "https://" plus the authority the connector's host and port gates admit.
	Endpoint string
	// Identity names the target for provenance only.
	Identity string
}

// MetadataRead is one credentialed GET. Path is an absolute path with an optional query, built by the recipe from
// fixed strings and validated names. Block is the auth block the read carries, built by the recipe from validated
// values; nil means the lookup's canonical block.
type MetadataRead struct {
	Path     string
	Block    json.RawMessage
	MaxBytes int
	Timeout  time.Duration
}

// MetadataResponse is one read's outcome: the body as the transport returns it, redacted.
type MetadataResponse struct {
	Status    int
	Body      string
	Truncated bool
}

// MetadataReader performs one audited, credentialed read on the lookup's target.
type MetadataReader interface {
	Read(ctx context.Context, r MetadataRead) (MetadataResponse, error)
}

// The control-plane calls a lookup can trigger while its target resolves, as a BootstrapObserver names them.
const (
	callDescribeCluster     = "DescribeCluster"
	callClustersGet         = "clusters.get"
	callListUserCredentials = "ListClusterUserCredentials"
	callClusterRole         = "clusterrole"
	clusterRoleTargetPrefix = " clusterroles/"
)

// BootstrapObserver is told about each control-plane call a targeted lookup triggers: a managed connector's
// cluster resolution and the ClusterRole fetch. The api_reference tool attaches one to the lookup's context;
// nothing else does, so the calls an http_request triggers are not reported.
type BootstrapObserver interface {
	// Begin reports a call about to start. An error refuses the call, which then fails with that error before
	// anything is sent. end reports how the call ended, and can run after the lookup has returned.
	Begin(connector, call, target string) (end func(error), err error)
}

type bootstrapObserverKey struct{}

// WithBootstrapObserver attaches o to ctx.
func WithBootstrapObserver(ctx context.Context, o BootstrapObserver) context.Context {
	return context.WithValue(ctx, bootstrapObserverKey{}, o)
}

// observeBootstrap runs one control-plane call under the observer ctx carries, if any; target is built only then.
// It runs inside a syncCache fetch, which runs under the first caller's context values, so only the caller that
// starts a call reports it: a call served from the cache or joined in flight reports nothing.
func observeBootstrap[T any](
	ctx context.Context, connector, call string, target func() string, fetch func() (T, error),
) (T, error) {
	o, ok := ctx.Value(bootstrapObserverKey{}).(BootstrapObserver)
	if !ok {
		return fetch()
	}
	end, err := o.Begin(connector, call, target())
	if err != nil {
		var zero T

		return zero, err
	}
	v, err := fetch()
	end(err)

	return v, err
}

// TargetDocumenterFor finds the provider named name, case-insensitively, as every dispatcher does. It returns the
// provider, the provider as a TargetDocumenter or nil when it implements none, and ErrUnknownProvider when no
// provider of that name is configured.
func TargetDocumenterFor(providers []Provider, name string) (Provider, TargetDocumenter, error) {
	p, err := find(providers, name)
	if err != nil {
		return nil, nil, err
	}
	td, _ := p.(TargetDocumenter)

	return p, td, nil
}
