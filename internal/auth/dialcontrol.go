package auth

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// addrResolver resolves a host to its IP addresses (both A and AAAA). It is the
// injected seam the eks/aks providers use to build the exact-IP pin set without
// touching real DNS in tests; the default lives in the excluded shell.
type addrResolver func(ctx context.Context, host string) ([]netip.Addr, error)

// contains reports whether addrs includes ip. Both sides are unmapped so an
// IPv4-mapped IPv6 form matches its plain IPv4 entry.
func contains(addrs []netip.Addr, ip netip.Addr) bool {
	want := ip.Unmap()
	for _, a := range addrs {
		if a.Unmap() == want {
			return true
		}
	}

	return false
}

// dialControl builds a [net.Dialer] ControlContext hook that enforces the dial
// policy for a host-pinned k8s endpoint: it parses the post-resolution dial
// address and delegates to authorize (the provider's authorizesDialIP, which
// applies the link-local floor and the exact-IP pin). It fails closed on any
// parse or authorize error. It is used by the bootstrap view-role fetch, which
// does not pass through AuthorizeAddr; the main request path is guarded by
// transport.dialGuard -> AuthorizeAddr -> AuthorizesAddr instead. The floor is
// not applied here: authorize already applies it, so it runs exactly once.
func dialControl(
	authorize func(ctx context.Context, ip netip.Addr) (bool, error),
) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("auth: split dial address %q: %w", address, err)
		}

		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("auth: parse dial address %q: %w", host, err)
		}

		allowed, err := authorize(ctx, ip)
		if err != nil {
			return fmt.Errorf("auth: authorize dial addr %s: %w", ip, err)
		}

		if !allowed {
			return fmt.Errorf("%w: %s", ErrAddrNotAuthorized, ip)
		}

		return nil
	}
}
