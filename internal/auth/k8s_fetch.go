package auth

import "time"

// k8sFetchTimeouts bounds each phase of the bootstrap ClusterRole fetch so a
// cluster endpoint that accepts the connection and then stalls cannot wedge the
// fetch even under a deadline-free context. dial/tlsHandshake/responseHeader cap
// connection setup and time-to-first-response-header; overall is the whole-request
// backstop (http.Client.Timeout, which also covers the body read the phase
// timeouts do not). The caller's context deadline (the registration probe
// timeout, or the request's clamped timeout at dispatch) is normally tighter and
// does the real bounding; these are defense-in-depth for any unbounded caller.
type k8sFetchTimeouts struct {
	dial           time.Duration
	tlsHandshake   time.Duration
	responseHeader time.Duration
	overall        time.Duration
}

// Production phase timeouts for the bootstrap ClusterRole fetch. The
// connection-setup caps mirror the request transport's, and the overall backstop
// covers the whole fetch including the body read the phase timeouts do not.
const (
	k8sFetchDialTimeout           = 10 * time.Second
	k8sFetchTLSHandshakeTimeout   = 10 * time.Second
	k8sFetchResponseHeaderTimeout = 15 * time.Second
	k8sFetchOverallTimeout        = 30 * time.Second
)

// k8sBootstrapFetchTimeout is the default whole-operation bound syncCache applies
// to each K8s bootstrap fetch (cluster resolve, token mint, ClusterRole read). It
// is deliberately the cache's OWN fixed timeout, not the per-request timeout, so
// (1) a stalled cluster endpoint cannot wedge the run even when the caller's
// context has no deadline, and (2) a short-deadline caller cannot cut short a
// concurrent, longer-budget caller coalesced onto the same singleflight fetch. It
// is a ceiling: a caller with a tighter deadline (e.g. the registration probe)
// still wins. It sits slightly above k8sFetchOverallTimeout so the pinnedHTTPClient
// phase timeouts surface a precise error before this coarse backstop fires.
const k8sBootstrapFetchTimeout = 35 * time.Second

// defaultK8sFetchTimeouts are the production phase timeouts for the bootstrap
// ClusterRole fetch.
func defaultK8sFetchTimeouts() k8sFetchTimeouts {
	return k8sFetchTimeouts{
		dial:           k8sFetchDialTimeout,
		tlsHandshake:   k8sFetchTLSHandshakeTimeout,
		responseHeader: k8sFetchResponseHeaderTimeout,
		overall:        k8sFetchOverallTimeout,
	}
}
