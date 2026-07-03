package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// BuildTLSConfig assembles a TLS client config from base64-PEM material. It is
// shared by the transport request path (custom CA / mTLS providers) and the
// auth bootstrap fetches (the K8s ClusterRole fetch and the GitLab probe).
//
// The config starts from systemPool's roots (falling back to an empty pool when
// the system pool is unavailable), so endpoints using publicly-trusted
// certificates (e.g. GKE DNS endpoints) keep working, while the appended custom
// caData allows connections to private endpoints (e.g. EKS/GKE cluster IPs with
// self-signed CAs). A clientCert+clientKey pair enables mTLS, serverName
// overrides SNI/verification when non-empty, and MinVersion is pinned to TLS 1.2.
func BuildTLSConfig(
	systemPool func() (*x509.CertPool, error),
	caData, clientCert, clientKey, serverName string,
) (*tls.Config, error) {
	pool, sysErr := systemPool()
	if sysErr != nil {
		pool = x509.NewCertPool()
	}

	if caData != "" {
		rawCA, decErr := base64.StdEncoding.DecodeString(caData)
		if decErr != nil {
			return nil, fmt.Errorf("failed to decode CA certificate: %w", decErr)
		}
		if !pool.AppendCertsFromPEM(rawCA) {
			return nil, errors.New("failed to parse CA certificate")
		}
	}

	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12} //nolint:exhaustruct // defaults are fine.

	if serverName != "" {
		tlsCfg.ServerName = serverName
	}

	if clientCert != "" && clientKey != "" {
		rawCert, certErr := base64.StdEncoding.DecodeString(clientCert)
		if certErr != nil {
			return nil, fmt.Errorf("failed to decode client certificate: %w", certErr)
		}
		rawKey, keyErr := base64.StdEncoding.DecodeString(clientKey)
		if keyErr != nil {
			return nil, fmt.Errorf("failed to decode client key: %w", keyErr)
		}
		pair, pairErr := tls.X509KeyPair(rawCert, rawKey)
		if pairErr != nil {
			return nil, fmt.Errorf("failed to parse client certificate key pair: %w", pairErr)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return tlsCfg, nil
}
