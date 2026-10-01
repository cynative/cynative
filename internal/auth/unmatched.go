package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// OperationDocumenter is optionally implemented by providers that can describe
// an operation (api_reference) and suggest fixes for a request their gate
// matched to no operation. Neither method may touch credentials or the policy.
type OperationDocumenter interface {
	Reference(ctx context.Context, q apiref.Query) apiref.Result
	Hint(ctx context.Context, v authreq.View, e *authreq.UnmatchedRequestError) apiref.Hint
}

// LookupReference answers an api_reference query through the named connector.
func LookupReference(ctx context.Context, providers []Provider, q apiref.Query) apiref.Result {
	p, err := find(providers, q.Connector)
	if err != nil {
		return apiref.Result{
			Outcome: apiref.OutcomeUnsupported,
			Reason:  fmt.Sprintf("connector %q is not configured in this session", q.Connector),
		}
	}
	d, ok := p.(OperationDocumenter)
	if !ok {
		return apiref.Result{
			Outcome: apiref.OutcomeUnsupported,
			Reason:  fmt.Sprintf("connector %q has no API reference support", q.Connector),
		}
	}

	return d.Reference(ctx, q)
}

// UnmatchedExplanationError carries the explained text of a gate error that
// matched no operation; Unwrap reaches the gate's original error.
type UnmatchedExplanationError struct {
	msg string
	err error
}

func (e *UnmatchedExplanationError) Error() string { return e.msg }
func (e *UnmatchedExplanationError) Unwrap() error { return e.err }

// ExplainUnmatched rewrites only the text of a gate error that carries
// *authreq.UnmatchedRequestError, when the connector can document operations.
// Any other error is returned unchanged; the allow or deny decision is never
// altered.
func ExplainUnmatched(
	ctx context.Context, name string, v authreq.View, providers []Provider, err error,
) error {
	var um *authreq.UnmatchedRequestError
	if !errors.As(err, &um) {
		return err
	}
	p, findErr := find(providers, name)
	if findErr != nil {
		return err
	}
	d, ok := p.(OperationDocumenter)
	if !ok {
		return err
	}
	hint := d.Hint(ctx, v, um)

	return &UnmatchedExplanationError{msg: formatUnmatched(name, um.Service, v, hint, err), err: err}
}

// formatUnmatched renders the diagnostic for a request that matched no operation.
func formatUnmatched(connector, service string, v authreq.View, h apiref.Hint, err error) string {
	target := connector
	if service != "" {
		target += "/" + service
	}
	op := h.Operation
	if op == "" {
		op = "<OperationName>"
	}
	lookup := map[string]string{"connector": connector, "operation": op}
	if service != "" {
		lookup["service"] = service
	}
	var cand string
	if len(h.Candidates) > 0 {
		cand = " Candidates: " + strings.Join(h.Candidates, "; ") + "."
	}

	return fmt.Sprintf("%s %q on %s matched no operation in the cached API metadata. The gate stopped before "+
		"attaching credentials or sending anything; this says nothing about the principal's permissions. "+
		"Check the request shape against the operation reference.%s For an operation's request template "+
		"call api_reference with %s. (gate detail: %q)",
		v.Method, apiref.Truncate(v.EscapedPath, apiref.MaxPathEcho), target, cand, marshalLookup(lookup),
		apiref.Truncate(err.Error(), apiref.MaxGateDetail))
}

// marshalLookup renders the api_reference arguments as compact JSON with sorted keys.
func marshalLookup(m map[string]string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m) // A string map always encodes.

	return strings.TrimSuffix(buf.String(), "\n")
}
