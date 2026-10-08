package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cynative/cynative/internal/apiref"
)

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
