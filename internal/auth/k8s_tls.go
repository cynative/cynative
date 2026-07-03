package auth

import (
	"net/http"
)

// clusterConn is the pure, assembled description of how to reach a cluster's API
// server for the bootstrap view fetch: the endpoint URL and the base64-PEM TLS
// material. The per-request auth injector is built separately (bearerInject)
// because AKS must construct it only after a conditional AAD token fetch, which
// would otherwise reorder I/O.
type clusterConn struct {
	endpoint   string
	caData     string
	clientCert string
	clientKey  string
	serverName string
}

// bearerInject builds the Authorization injector for the bootstrap view fetch.
// When conditional is true (AKS/kubernetes, whose mTLS path carries no bearer)
// an empty bearer yields a no-op — no header is set, so the client certificate
// authenticates. When conditional is false (EKS/GKE, whose token is always
// present) the header is set unconditionally. This preserves the documented
// per-provider unconditional-vs-conditional difference behind one helper.
func bearerInject(bearer string, conditional bool) func(*http.Request) error {
	return func(r *http.Request) error {
		if conditional && bearer == "" {
			return nil
		}
		r.Header.Set("Authorization", "Bearer "+bearer)

		return nil
	}
}
