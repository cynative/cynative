package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"

	"github.com/cynative/cynative/internal/outbound"
)

// DialControl is the [net.Dialer] ControlContext hook shape: the post-resolution,
// pre-connect chokepoint every outbound client in the binary installs.
type DialControl = func(ctx context.Context, network, address string, c syscall.RawConn) error

// OutboundRoute is how one outbound client reaches one target: the proxy to
// send the request through (none by default) and the dial-time address policy
// that goes with it. The zero value dials directly with no address policy at
// all, so callers always build one through [RouteOutbound].
type OutboundRoute struct {
	proxy   *url.URL
	control DialControl
}

// RouteOutbound resolves target against the operator's proxy configuration.
//
// direct is the caller's own dial-time address policy, used unchanged when the
// request goes straight out. When a proxy applies, the connection is made to
// the proxy and not to target's host, so that policy would be judging the wrong
// address: it is replaced by a pin to the proxy endpoint itself. Everything
// above the dial is untouched — the URL, the host and action gates, the
// credential injection and the TLS verification all still address target.
//
// The proxy endpoint is operator configuration that no request argument can
// reach, which is what makes pinning to it safe; the trade is that the final
// destination address is chosen by the proxy and Cynative cannot verify it.
// See docs/project/threat-model.md.
func RouteOutbound(r outbound.Routing, target string, direct DialControl) (OutboundRoute, error) {
	proxy, err := r.ProxyFor(target)
	if err != nil {
		return OutboundRoute{}, err
	}

	if proxy == nil {
		return OutboundRoute{proxy: nil, control: direct}, nil
	}

	pin := &proxyPin{host: proxy.Hostname(), resolver: defaultResolveAddrs}

	return OutboundRoute{proxy: proxy, control: dialControl(pin.authorizesDialIP)}, nil
}

// Apply installs the route on a transport and the dialer that transport dials
// with: the dial-time control hook on the dialer, and the proxy on the
// transport (left nil for a direct route, so nothing about an unproxied build
// changes). The dialer is the caller's own, so its timeouts are preserved.
func (o OutboundRoute) Apply(tr *http.Transport, dialer *net.Dialer) {
	dialer.ControlContext = o.control
	tr.DialContext = dialer.DialContext

	if o.proxy == nil {
		return
	}

	proxy := o.proxy
	tr.Proxy = func(*http.Request) (*url.URL, error) { return proxy, nil }
}

// proxyPin authorizes dials to the operator-configured proxy endpoint and
// nothing else. It is the dial-time policy for a proxied connection, standing
// in for the per-provider address checks that apply to a direct one.
type proxyPin struct {
	host     string
	resolver addrResolver
}

// authorizesDialIP permits ip only when it is the proxy endpoint itself: the
// literal address when the endpoint host is an IP, or a member of the host's
// current resolution otherwise. The unconditional floor is applied first, minus
// loopback, because a proxy on the operator's own machine is the ordinary case
// and RFC1918 is bounded by the pin — while a proxy name that resolves to a
// cloud-metadata address is still refused. Fails closed on a resolve error.
func (p *proxyPin) authorizesDialIP(ctx context.Context, ip netip.Addr) (bool, error) {
	if floorForbidden(ip) && !ip.Unmap().IsLoopback() {
		return false, nil
	}

	if want, err := netip.ParseAddr(p.host); err == nil {
		return ip.Unmap() == want.Unmap(), nil
	}

	addrs, err := p.resolver(ctx, p.host)
	if err != nil {
		return false, fmt.Errorf("auth: resolve proxy endpoint %q: %w", p.host, err)
	}

	return contains(addrs, ip), nil
}
