package auth

import (
	"context"
	"net"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Token-refresh transport knobs. [oauth2.TokenSource.Token] takes no context and,
// over [http.DefaultTransport], is bounded only at dial and TLS handshake: a token
// endpoint that accepts the connection, completes the handshake, then stalls the
// response header or body would otherwise block a refresh forever. The dial /
// keep-alive / TLS / idle-pool / expect-continue values mirror
// [http.DefaultTransport]'s documented defaults (the transport this replaces);
// the response-header and overall timeouts are the new bounds this fix adds.
const (
	gcpTokenRefreshDialTimeout           = 30 * time.Second
	gcpTokenRefreshDialKeepAlive         = 30 * time.Second
	gcpTokenRefreshTLSHandshakeTimeout   = 10 * time.Second
	gcpTokenRefreshMaxIdleConns          = 100
	gcpTokenRefreshIdleConnTimeout       = 90 * time.Second
	gcpTokenRefreshExpectContinueTimeout = 1 * time.Second
	// gcpTokenRefreshResponseHeaderTimeout bounds time-to-first-response-header.
	gcpTokenRefreshResponseHeaderTimeout = 15 * time.Second
	// gcpTokenRefreshOverallTimeout is the whole-request backstop ([http.Client.Timeout],
	// which also covers a stalled body read the phase timeouts do not). It stays under
	// the syncCache k8sBootstrapFetchTimeout ceiling (35s) so a refusal surfaces first.
	gcpTokenRefreshOverallTimeout = 30 * time.Second
)

// withBoundedTokenRefresh returns ctx carrying a bounded [http.Client] under the
// [oauth2.HTTPClient] key. A token source constructed with this context (e.g. the
// long-lived ADC credentials from google.FindDefaultCredentials at registration)
// issues every OAuth token refresh through this client, so a blackholed token
// endpoint cannot make an otherwise contextless [oauth2.TokenSource.Token] block
// forever.
//
// The client's Timeout is applied per refresh request, NOT as a fixed context
// deadline, so it does not poison the retained-context source the way a
// [context.WithTimeout] would. [context.WithValue] also leaves ctx deadline-free,
// preserving the "findGCP MUST use the unbounded ctx" invariant in registerGCP.
//
// This bounds the [http.DefaultTransport]-backed refresh paths (service-account
// JSON, authorized-user/gcloud, external-account, impersonated). The GCE/GKE
// metadata server path uses its own client (already bounded by its own timeout)
// and is unaffected; it is a link-local hop, not the [http.DefaultTransport] case
// this guards.
func withBoundedTokenRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, boundedTokenRefreshClient())
}

// boundedTokenRefreshClient is the production token-refresh client.
func boundedTokenRefreshClient() *http.Client {
	return boundedTokenRefreshClientWithTimeouts(gcpTokenRefreshOverallTimeout, gcpTokenRefreshResponseHeaderTimeout)
}

// boundedTokenRefreshClientWithTimeouts builds the refresh client with the overall
// and response-header timeouts made explicit so tests can drive small values
// against a stalling token endpoint; production callers go through
// boundedTokenRefreshClient. It builds a fresh transport reproducing
// [http.DefaultTransport]'s defaults rather than cloning the mutable global, but
// keeps Proxy = [http.ProxyFromEnvironment], since the [http.DefaultTransport]
// this replaces honored the egress proxy and a token refresh must still traverse
// it.
func boundedTokenRefreshClientWithTimeouts(overall, responseHeader time.Duration) *http.Client {
	tr := &http.Transport{ //nolint:exhaustruct // only proxy, HTTP/2, and the pool/phase timeouts configured.
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          gcpTokenRefreshMaxIdleConns,
		IdleConnTimeout:       gcpTokenRefreshIdleConnTimeout,
		TLSHandshakeTimeout:   gcpTokenRefreshTLSHandshakeTimeout,
		ExpectContinueTimeout: gcpTokenRefreshExpectContinueTimeout,
		ResponseHeaderTimeout: responseHeader,
		DialContext: (&net.Dialer{ //nolint:exhaustruct // only Timeout + KeepAlive configured.
			Timeout:   gcpTokenRefreshDialTimeout,
			KeepAlive: gcpTokenRefreshDialKeepAlive,
		}).DialContext,
	}

	return &http.Client{Transport: tr, Timeout: overall} //nolint:exhaustruct // only Transport + Timeout set.
}
