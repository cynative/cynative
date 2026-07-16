package auth

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// adcTokenRefreshTimeout bounds each OAuth2 token refresh minted from the
// registered Application Default Credentials source (shared by the gcp and gke
// providers for the whole session) for the token-endpoint credential forms:
// gcloud user credentials, service-account JSON keys, workload-identity /
// external-account, and impersonation. Those refresh through
// oauth2's internal.ContextClient, which dials the token endpoint with the
// [http.Client] stored at the credential-creation context's oauth2.HTTPClient
// key, defaulting to [http.DefaultClient] (no timeout). Since
// oauth2.TokenSource.Token takes no context, a token endpoint that accepts the
// connection and then stalls the response would otherwise block the refresh
// forever, uncancellable by the request or preflight context. This bound sits
// below the 35s k8sBootstrapFetchTimeout so a stalled refresh surfaces its own
// error before the GKE ClusterRole-preflight ceiling fires.
//
// The in-cluster GCE/GKE metadata-server credential form is the one exception: it
// mints through the cloud.google.com/go/compute/metadata client, not the oauth2
// refresh path, so this value is inert there. That path is bounded independently
// by the metadata client's own ~5s per-attempt timeout.
const adcTokenRefreshTimeout = 30 * time.Second

// boundedADCContext returns ctx carrying a token-refresh HTTP client (via the
// oauth2.HTTPClient context key) whose [http.Client] Timeout bounds every
// token-endpoint refresh minted from the resulting credentials source. It is
// threaded onto the credential-creation context so the bound reaches the
// contextless oauth2.TokenSource.Token refreshes the gcp and gke providers make
// for the whole session: the GKE Container API cluster resolve, GKE InjectAuth,
// and the GCP provider paths. The GCE/GKE metadata-server form is the exception
// (see adcTokenRefreshTimeout): it mints through a different client and is
// bounded independently.
//
// The bound is a per-request Client.Timeout, not a context deadline: the ctx
// itself never gains a deadline, so the long-lived registered source is never
// poisoned (every refresh gets a fresh timeout). A nil-Transport client uses
// [http.DefaultTransport], preserving its dial/TLS timeouts and proxy resolution
// (HTTP_PROXY) for the token endpoint.
func boundedADCContext(ctx context.Context, timeout time.Duration) context.Context {
	client := &http.Client{Timeout: timeout} //nolint:exhaustruct // Timeout is the only field this bound sets.

	return context.WithValue(ctx, oauth2.HTTPClient, client)
}
