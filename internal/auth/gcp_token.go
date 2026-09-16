package auth

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Token-refresh timeouts. [oauth2.TokenSource.Token] takes no context and, over
// [http.DefaultTransport], is bounded only at dial and TLS handshake: a token
// endpoint that accepts the connection, completes the handshake, then stalls the
// response header or body would otherwise block a refresh forever. The transport
// underneath comes from [Egress.Transport], which carries
// [http.DefaultTransport]'s dial / keep-alive / TLS / idle-pool /
// expect-continue defaults plus the operator's proxy selection; the
// response-header and overall timeouts below are the bounds this adds on top.
const (
	// gcpTokenRefreshResponseHeaderTimeout bounds time-to-first-response-header.
	gcpTokenRefreshResponseHeaderTimeout = 15 * time.Second
	// gcpTokenRefreshOverallTimeout is the whole-request backstop ([http.Client.Timeout],
	// which also covers a stalled body read the phase timeouts do not). It stays under
	// the syncCache k8sBootstrapFetchTimeout ceiling (35s) so a refusal surfaces first.
	gcpTokenRefreshOverallTimeout = 30 * time.Second
)

// withRefreshClient returns ctx carrying the bounded, routed refresh client
// under the [oauth2.HTTPClient] key. A token source constructed with this context
// (the long-lived ADC credentials from google.FindDefaultCredentials at
// registration, and every identity prober) issues every OAuth token refresh
// through this client, so a blackholed token endpoint cannot make an otherwise
// contextless [oauth2.TokenSource.Token] block forever, and the refresh follows
// the operator's proxy.
//
// The client's Timeout is applied per refresh request, NOT as a fixed context
// deadline, so it does not poison the retained-context source the way a
// [context.WithTimeout] would. [context.WithValue] also leaves ctx deadline-free,
// preserving the "findGCP MUST use the unbounded ctx" invariant in registerGCP.
//
// This bounds the refresh paths that would otherwise use
// [http.DefaultTransport] (service-account JSON, authorized-user/gcloud,
// external-account, impersonated). The GCE/GKE metadata server path uses its own
// client (already bounded by its own timeout) and is unaffected; it is a
// link-local hop, not the [http.DefaultTransport] case this guards.
func (e *Egress) withRefreshClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, e.refreshClient())
}

// refreshClient is the production token-refresh client.
func (e *Egress) refreshClient() *http.Client {
	return e.refreshClientWithTimeouts(gcpTokenRefreshOverallTimeout, gcpTokenRefreshResponseHeaderTimeout)
}

// refreshClientWithTimeouts builds the refresh client on the policy's transport
// with the overall and response-header timeouts made explicit so tests can
// drive small values against a stalling token endpoint.
func (e *Egress) refreshClientWithTimeouts(overall, responseHeader time.Duration) *http.Client {
	tr := e.Transport()
	tr.ResponseHeaderTimeout = responseHeader

	return &http.Client{Transport: tr, Timeout: overall}
}
