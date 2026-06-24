package auth

import (
	"context"
	"fmt"
	"net/netip"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// defaultFetchView fetches the EKS cluster's configured ClusterRole (default `view`) over a CA-pinned
// HTTPS connection authenticated with the same k8s-aws-v1 bearer token used for
// normal requests. Shell code (network I/O); integration-tested via fetchViewPolicy.
func (p *eksProvider) defaultFetchView(ctx context.Context, args *EKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return nil, err
	}

	cfg := p.cfg
	cfg.Region = resolveRegion(args.Region, cfg.Region)
	if _, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("k8s_hardening: retrieve AWS credentials: %w", err)
	}

	presignURL, err := p.presign(ctx, cfg, args.ClusterName)
	if err != nil {
		return nil, fmt.Errorf("k8s_hardening: presign EKS token: %w", err)
	}

	control := dialControl(func(ctx context.Context, ip netip.Addr) (bool, error) {
		return p.authorizesDialIP(ctx, ip, args)
	})

	conn := eksClusterConn(ct.host, ct.caData)

	hc, err := pinnedHTTPClient(conn.caData, conn.clientCert, conn.clientKey, conn.serverName, control)
	if err != nil {
		return nil, err
	}

	return fetchViewPolicy(ctx, hc, conn.endpoint, p.clusterRole, bearerInject(eksBearerToken(presignURL), false))
}
