package auth

import (
	"net/url"
	"strings"
)

// clusterTLS is a resolved K8s cluster's TLS facts: the API-server host and the
// base64-PEM CA cert, fetched together from one cloud-API call and cached.
type clusterTLS struct {
	host   string
	caData string
}

// hostFromEndpoint extracts the lower-cased host from a cluster endpoint, which
// may be a full URL ("https://….eks.amazonaws.com") or a bare host/IP ("34.71.1.2").
// Scheme, port, and path are stripped; an unparseable endpoint yields "".
func hostFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}

	return strings.ToLower(u.Hostname())
}
