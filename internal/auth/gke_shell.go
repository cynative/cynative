package auth

import (
	"context"
	"net/netip"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// defaultFetchView fetches the GKE cluster's configured ClusterRole (default `view`) over a CA-pinned
// HTTPS connection authenticated with the GCP OAuth bearer token. Shell code
// (network I/O); integration-tested via fetchViewPolicy.
func (p *gkeProvider) defaultFetchView(ctx context.Context, args *GKEAuthArgs) (*k8sauthz.ViewPolicy, error) {
	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return nil, err
	}

	token, err := tokenWithContext(ctx, p.tokenSource)
	if err != nil {
		return nil, err
	}

	control := dialControl(func(ctx context.Context, ip netip.Addr) (bool, error) {
		return p.authorizesDialIP(ctx, ip, args)
	})

	conn := gkeClusterConn(ct.host, ct.caData)

	hc, err := pinnedHTTPClient(conn.caData, conn.clientCert, conn.clientKey, conn.serverName, control)
	if err != nil {
		return nil, err
	}

	return fetchViewPolicy(ctx, hc, conn.endpoint, p.clusterRole, bearerInject(token.AccessToken, false))
}
