package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// buildClusterTLSConfig assembles the cluster TLS config from base64-PEM material:
// it appends caData to pool, optionally loads a base64-PEM client cert+key for
// mTLS, and sets ServerName when non-empty. Pure; the system-root pool load and
// the HTTP transport/client build stay in the shell (pinnedHTTPClient).
func buildClusterTLSConfig(
	pool *x509.CertPool, caData, clientCert, clientKey, serverName string,
) (*tls.Config, error) {
	if caData != "" {
		rawCA, decErr := base64.StdEncoding.DecodeString(caData)
		if decErr != nil {
			return nil, fmt.Errorf("k8s_hardening: decode cluster CA: %w", decErr)
		}
		if !pool.AppendCertsFromPEM(rawCA) {
			return nil, errors.New("k8s_hardening: parse cluster CA")
		}
	}

	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12} //nolint:exhaustruct // defaults are fine.

	if serverName != "" {
		tlsCfg.ServerName = serverName
	}

	if clientCert != "" && clientKey != "" {
		rawCert, certErr := base64.StdEncoding.DecodeString(clientCert)
		if certErr != nil {
			return nil, fmt.Errorf("k8s_hardening: decode client cert: %w", certErr)
		}
		rawKey, keyErr := base64.StdEncoding.DecodeString(clientKey)
		if keyErr != nil {
			return nil, fmt.Errorf("k8s_hardening: decode client key: %w", keyErr)
		}
		pair, pairErr := tls.X509KeyPair(rawCert, rawKey)
		if pairErr != nil {
			return nil, fmt.Errorf("k8s_hardening: client key pair: %w", pairErr)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return tlsCfg, nil
}

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
