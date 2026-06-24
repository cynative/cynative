package auth

import (
	"context"
	"net/netip"
	"os"

	"k8s.io/client-go/tools/clientcmd"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// defaultReadFile is the production file-reader seam (used both at registration
// for CA/cert/key files and per-request for a bearer tokenFile). Shell code
// (filesystem I/O); excluded from the coverage gate.
func defaultReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) //nolint:gosec // operator-supplied kubeconfig path, read with operator privileges.
}

// loadSelectedCluster discovers the local kubeconfig kubectl-style (KUBECONFIG
// then ~/.kube/config), reads the RAW api.Config (never ClientConfig(), so no
// exec plugin runs), runs the pure select/reject/classify pipeline, and
// materializes file-referenced CA/cert/key bytes. It returns the load error and
// the post-load (extract or resolve) error separately so kubeSkipResult can
// route them by failure type; the caller (the registration router) decides loud
// vs verbose-only. Shell I/O.
func loadSelectedCluster() (resolvedCluster, error, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()

	raw, err := rules.Load()
	if err != nil {
		return resolvedCluster{}, err, nil
	}

	sel, err := extractSelected(raw)
	if err != nil {
		return resolvedCluster{}, nil, err
	}

	rc, err := resolveSelected(sel, defaultReadFile)
	if err != nil {
		return resolvedCluster{}, nil, err
	}

	return rc, nil, nil
}

// defaultFetchView fetches the cluster's configured ClusterRole (default `view`) over a CA-pinned
// (and, for mTLS, client-cert-presenting) HTTPS connection, authenticated with
// the captured bearer token (re-read from tokenFile if set). Shell code
// (network I/O); integration-tested via fetchViewPolicy.
func (p *kubernetesProvider) defaultFetchView(
	ctx context.Context, _ *KubernetesAuthArgs,
) (*k8sauthz.ViewPolicy, error) {
	control := dialControl(func(ctx context.Context, ip netip.Addr) (bool, error) {
		return p.authorizesDialIP(ctx, ip)
	})

	conn := kubernetesClusterConn(p.cluster)

	hc, err := pinnedHTTPClient(conn.caData, conn.clientCert, conn.clientKey, conn.serverName, control)
	if err != nil {
		return nil, err
	}

	bearer, err := p.bearerToken()
	if err != nil {
		return nil, err
	}

	return fetchViewPolicy(ctx, hc, conn.endpoint, p.clusterRole, bearerInject(bearer, true))
}
