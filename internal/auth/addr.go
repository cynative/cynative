package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// AddrAuthorizer is optionally implemented by providers that need to authorize a
// request's DNS-resolved IP address at dial time (after name resolution, before
// connect). It is the chokepoint for DNS-rebinding / TOCTOU SSRF defense: a host
// that passed AuthorizesHost can still resolve to a metadata or private address.
// Providers that do not implement it inherit the default internal-range deny in
// AuthorizeAddr.
type AddrAuthorizer interface {
	AuthorizesAddr(ctx context.Context, ip netip.Addr, rawArgs json.RawMessage) (bool, error)
}

// ErrAddrNotAuthorized is returned when a request's resolved IP is rejected.
var ErrAddrNotAuthorized = errors.New("resolved address not authorized for auth_provider")

// cloudHostLocalAddrs are exact IPv4 cloud host-local metadata/platform
// addresses that fall outside link-local (169.254/16) and RFC1918, so neither the
// link-local check nor IsPrivate catches them. They are never a legitimate
// cluster endpoint, so they are denied. They are matched exactly (not by CIDR)
// because both live in shared/CGNAT space that legitimate private clusters may
// also use (e.g. EKS pod CIDRs in 100.64.0.0/10):
//   - 168.63.129.16: Azure WireServer (DNS, DHCP, health probes, VM-agent
//     signalling). Azure IMDS itself is IPv4-only at 169.254.169.254 (link-local).
//   - 100.100.100.200: Alibaba Cloud ECS instance metadata service (a documented
//     SSRF target), reachable in 100.64.0.0/10 shared address space.
//
// IPv6 cloud metadata services (AWS fd00:ec2::254, GCP fd20:ce::254, OCI
// fd00:c1::a9fe:a9fe, Alibaba fd00:100::100:200, Scaleway fd00:42::42, etc.) all
// live in ULA space (fc00::/7) and are covered wholesale by the floor's ULA-IPv6
// deny — no per-provider list is needed, because no managed cluster API endpoint
// is ever a ULA address (EKS/GKE use global-unicast IPv6 or IPv4; AKS is IPv4).
//
//nolint:gochecknoglobals // stateless, parsed-once platform-address list.
var cloudHostLocalAddrs = []netip.Addr{
	netip.MustParseAddr("168.63.129.16"),
	netip.MustParseAddr("100.100.100.200"),
}

//nolint:gochecknoglobals // stateless, parsed-once IPv4-embedding IPv6 prefixes.
var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96") // RFC 6052 well-known NAT64.
	sixToFour      = netip.MustParsePrefix("2002::/16")    // RFC 3056 6to4.
)

// extractEmbeddedIPv4 returns the IPv4 embedded in an IPv4-embedding IPv6 address
// (NAT64 well-known 64:ff9b::/96 — embedded v4 = low 32 bits; or 6to4 2002::/16 —
// embedded v4 = bytes 2..5) and whether ip was such an address. Any IPv6 zone is
// stripped first, because Prefix.Contains is zone-blind (it would otherwise return
// false for a zoned literal and let it skip the embedded check). The deprecated
// IPv4-compatible (::a.b.c.d) form and custom NAT64 prefix lengths are out of scope.
func extractEmbeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap().WithZone("")
	if !ip.Is6() {
		return netip.Addr{}, false
	}

	b := ip.As16()
	switch {
	case nat64WellKnown.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	default:
		return netip.Addr{}, false
	}
}

// AuthorizeAddr verifies the named provider permits a connection to ip. When the
// provider implements AddrAuthorizer it delegates; otherwise it applies the
// fail-safe default: deny internal ranges (loopback, link-local incl. cloud
// metadata, RFC1918, ULA, unspecified, and IPv4-mapped forms of the above) and
// allow everything else. It returns an error if name is unknown, the provider
// denies the address, or the provider errs.
func AuthorizeAddr(
	ctx context.Context,
	name string,
	ip netip.Addr,
	providers []Provider,
	rawArgs json.RawMessage,
) error {
	p, err := find(providers, name)
	if err != nil {
		return err
	}

	if aa, ok := p.(AddrAuthorizer); ok {
		allowed, addrErr := aa.AuthorizesAddr(ctx, ip, rawArgs)
		if addrErr != nil {
			return fmt.Errorf("auth: authorize addr %s for provider %s: %w", ip, name, addrErr)
		}

		if !allowed {
			return fmt.Errorf("%w: %s not allowed for provider %s", ErrAddrNotAuthorized, ip, name)
		}

		return nil
	}

	if isInternalIP(ip) {
		return fmt.Errorf("%w: %s is an internal address (provider %s)", ErrAddrNotAuthorized, ip, name)
	}

	return nil
}

// floorForbidden reports whether ip is in the range that NO provider may dial,
// even a host-pinned one: invalid, loopback, the unspecified address, link-local
// unicast (incl. 169.254.0.0/16 cloud metadata and fe80::/10), link-local /
// interface-local multicast, ALL ULA IPv6 (fc00::/7 — every cloud parks its IPv6
// metadata service in ULA space, and no managed cluster endpoint is ever ULA),
// the exact IPv4 cloud host-local addresses (cloudHostLocalAddrs), and an
// IPv4-embedding IPv6 address (NAT64 64:ff9b::/96 or 6to4 2002::/16) whose embedded
// IPv4 is itself floor-forbidden (e.g. 64:ff9b::a9fe:a9fe → 169.254.169.254). An
// embedded RFC1918 v4 is deliberately NOT floor-forbidden, so a legitimate
// NAT64-reached private cluster still reaches the per-provider exact-IP pin.
// IPv4-mapped IPv6 forms are unmapped first. It deliberately allows RFC1918 IPv4
// and global-unicast IPv6, because private K8s clusters legitimately use those —
// those are constrained by the per-provider exact-IP pin, not the floor.
func floorForbidden(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}

	ip = ip.Unmap()

	if embedded, ok := extractEmbeddedIPv4(ip); ok && floorForbidden(embedded) {
		return true
	}

	return slices.Contains(cloudHostLocalAddrs, ip) ||
		(ip.Is6() && ip.IsPrivate()) ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// isInternalIP reports whether ip is in the default-deny set for providers that
// do not implement AddrAuthorizer: the unconditional floor plus the private ranges
// (RFC1918 + fc00::/7 ULA via IsPrivate), and — for an IPv4-embedding IPv6 address
// (NAT64/6to4) — when its embedded IPv4 is itself internal (so 64:ff9b::a00:1 →
// 10.0.0.1 is denied, while 64:ff9b::<public> stays allowed so an IPv6-only/DNS64
// host can reach public APIs). Unmapping happens inside floorForbidden /
// extractEmbeddedIPv4; IsPrivate is checked on the unmapped form so a mapped
// internal address (e.g. ::ffff:10.0.0.1) is caught.
func isInternalIP(ip netip.Addr) bool {
	if floorForbidden(ip) {
		return true
	}

	u := ip.Unmap()

	if embedded, ok := extractEmbeddedIPv4(u); ok && isInternalIP(embedded) {
		return true
	}

	return u.IsPrivate()
}
