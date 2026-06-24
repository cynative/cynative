package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// maxViewRoleBytes caps the clusterrole response body read.
const maxViewRoleBytes = 1 << 20 // 1 MiB.

// pinnedHTTPClient builds an [http.Client] trusting the system roots plus caData
// (base64 PEM), optionally presenting a client certificate (base64 PEM cert+key)
// for mTLS clusters. It mirrors transport.tlsTransport but lives here because
// auth must not import transport. control, when non-nil, is installed as the
// [net.Dialer] ControlContext hook so the bootstrap fetch runs through the dial guard.
func pinnedHTTPClient(
	caData, clientCert, clientKey, serverName string,
	control func(ctx context.Context, network, address string, c syscall.RawConn) error,
) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	tlsCfg, err := buildClusterTLSConfig(pool, caData, clientCert, clientKey, serverName)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{ //nolint:exhaustruct // only TLS + dial control configured.
		TLSClientConfig: tlsCfg,
		DialContext: (&net.Dialer{ //nolint:exhaustruct // only ControlContext configured.
			ControlContext: control,
		}).DialContext,
	}

	return &http.Client{Transport: tr}, nil //nolint:exhaustruct // only Transport set.
}

// fetchClusterRoleRaw GETs the named cluster-scoped ClusterRole and returns the
// raw JSON body. inject sets request auth (a bearer header, or a no-op for mTLS).
func fetchClusterRoleRaw(
	ctx context.Context,
	hc *http.Client,
	endpoint, clusterRole string,
	inject func(*http.Request) error,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+clusterRolePath(clusterRole), nil)
	if err != nil {
		return nil, fmt.Errorf("k8s_hardening: build clusterrole request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err = inject(req); err != nil {
		return nil, fmt.Errorf("k8s_hardening: inject clusterrole-fetch auth: %w", err)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s_hardening: fetch clusterrole: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxViewRoleBytes))
	if err != nil {
		return nil, fmt.Errorf("k8s_hardening: read clusterrole: %w", err)
	}

	if err = clusterRoleFetchStatusError(clusterRole, resp.StatusCode); err != nil {
		return nil, err
	}

	return body, nil
}

// fetchViewPolicy fetches the named cluster ClusterRole and parses it into a
// ViewPolicy. Used by the eks/gke/aks/kubernetes providers' default fetch seams.
func fetchViewPolicy(
	ctx context.Context,
	hc *http.Client,
	endpoint, clusterRole string,
	inject func(*http.Request) error,
) (*k8sauthz.ViewPolicy, error) {
	raw, err := fetchClusterRoleRaw(ctx, hc, endpoint, clusterRole, inject)
	if err != nil {
		return nil, err
	}

	rules, err := k8sauthz.ParseClusterRoleRules(raw)
	if err != nil {
		return nil, fmt.Errorf("k8s_hardening: parse clusterrole %q: %w", clusterRole, err)
	}

	return k8sauthz.BuildViewPolicy(rules), nil
}
