package auth

import (
	"context"
	"net/netip"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// defaultFetchView fetches the AKS cluster's configured ClusterRole (default `view`). AKS may
// authenticate via a local-account bearer token, local-account mTLS, or an
// Entra ID (AAD) bearer — mirroring InjectAuth. Shell code (network I/O);
// integration-tested via fetchViewPolicy.
func (p *aksProvider) defaultFetchView(ctx context.Context, args *AKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
	cfg, err := p.getClusterConfig(ctx, args)
	if err != nil {
		return nil, err
	}

	caData, clientCert, clientKey := aksClusterTLSMaterial(cfg)

	control := dialControl(func(ctx context.Context, ip netip.Addr) (bool, error) {
		return p.authorizesDialIP(ctx, ip, args)
	})

	conn := aksClusterConn(cfg.Host, caData, clientCert, clientKey)

	hc, err := pinnedHTTPClient(conn.caData, conn.clientCert, conn.clientKey, conn.serverName, control)
	if err != nil {
		return nil, err
	}

	bearer := cfg.BearerToken
	if aksNeedsAADToken(bearer, clientCert) {
		tok, terr := p.credential.GetToken(ctx, policy.TokenRequestOptions{ //nolint:exhaustruct // only Scopes set.
			Scopes: []string{aksAADServerScope},
		})
		if terr != nil {
			return nil, terr
		}
		bearer = tok.Token
	}

	return fetchViewPolicy(ctx, hc, conn.endpoint, p.clusterRole, bearerInject(bearer, true))
}
