package auth

import (
	"context"
	"net"
	"net/netip"
)

// defaultResolveAddrs resolves host to its IPv4 and IPv6 addresses via the
// system resolver, used to build the exact-IP pin set for FQDN-based cluster
// endpoints (EKS/AKS). Shell code (network I/O); excluded from the coverage
// gate and integration-exercised through the providers' defaultFetchView.
func defaultResolveAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
