package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Route is how one request leaves the host. A nil Proxy means direct.
type Route struct {
	Proxy *url.URL
}

// Proxied reports whether the route goes through a proxy.
func (r Route) Proxied() bool { return r.Proxy != nil }

// ErrProxyDialMismatch is returned when a proxied transport is asked to dial
// anything but the proxy's own authority. net/http never does that, so the
// error is a tripwire, not an expected path.
var ErrProxyDialMismatch = errors.New("proxied transport may only dial the proxy")

// dialFunc is the shape of [net.Dialer.DialContext]; tests inject fakes.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Transport knobs mirroring [http.DefaultTransport]'s documented defaults, used
// by every reusable client Egress builds.
const (
	defaultTransportDialTimeout           = 30 * time.Second
	defaultTransportDialKeepAlive         = 30 * time.Second
	defaultTransportMaxIdleConns          = 100
	defaultTransportIdleConnTimeout       = 90 * time.Second
	defaultTransportTLSHandshakeTimeout   = 10 * time.Second
	defaultTransportExpectContinueTimeout = 1 * time.Second
)

// Route selects the route for target. The selector cannot fail: its only error
// is the CGI refusal for http targets, which NewEgress never enables, so the
// error is discarded here.
func (e *Egress) Route(target *url.URL) Route {
	p, _ := e.proxyFunc(target)

	return Route{Proxy: p}
}

// RouteEndpoint selects the route for a raw endpoint string, for the shells
// that hold a cluster endpoint rather than a parsed URL.
func (e *Egress) RouteEndpoint(endpoint string) (Route, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return Route{Proxy: nil}, fmt.Errorf("egress: parse endpoint: %w", err)
	}

	return e.Route(u), nil
}

// proxyForRequest adapts Route to http.Transport.Proxy for the reusable
// transports, so guarded and reusable clients select identically.
func (e *Egress) proxyForRequest(req *http.Request) (*url.URL, error) {
	return e.Route(req.URL).Proxy, nil
}

// proxyAuthority is the address net/http hands DialContext for a proxied
// connection: host and port, with the scheme default when the URL has none.
// The host is ASCII by validation, so no IDNA conversion is involved.
func proxyAuthority(p *url.URL) string {
	port := p.Port()
	if port == "" {
		port = proxyDefaultPort(p.Scheme)
	}

	return net.JoinHostPort(p.Hostname(), port)
}

// bindRoute binds tr to route. A direct route installs directDial (the
// caller's guarded dialer) and no proxy. A proxied route installs the fixed
// proxy and a dialer that accepts only the proxy's authority and otherwise
// calls proxyDial, so nothing the transport does can reach any other address.
func bindRoute(tr *http.Transport, route Route, directDial, proxyDial dialFunc) {
	if !route.Proxied() {
		tr.Proxy = nil
		tr.DialContext = directDial

		return
	}
	want := proxyAuthority(route.Proxy)
	tr.Proxy = http.ProxyURL(route.Proxy)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != want {
			return nil, fmt.Errorf("%w: asked for %q, proxy is %q", ErrProxyDialMismatch, addr, want)
		}

		return proxyDial(ctx, network, addr)
	}
}

// configureTransport binds tr to route. direct carries the caller's timeouts
// and the dial guard in ControlContext; the proxy dialer is a copy of it with
// the guard cleared, because the operator's proxy may sit on a loopback or
// private address the guard would refuse. The route already carries the
// decision, so the policy itself is not needed here; the bootstrap clients
// call this directly.
func configureTransport(tr *http.Transport, route Route, direct *net.Dialer) {
	plain := *direct
	plain.ControlContext = nil
	plain.Control = nil
	bindRoute(tr, route, direct.DialContext, plain.DialContext)
}

// ConfigureTransport is configureTransport as a method, for callers outside
// the package (the request transport).
func (e *Egress) ConfigureTransport(tr *http.Transport, route Route, direct *net.Dialer) {
	configureTransport(tr, route, direct)
}

// Transport returns a fresh [http.Transport] with [http.DefaultTransport]'s
// documented defaults and per-request proxy selection through this policy. It
// is the base of every reusable client (SDKs, catalog fetchers, token refresh).
func (e *Egress) Transport() *http.Transport {
	return &http.Transport{
		Proxy:                 e.proxyForRequest,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultTransportMaxIdleConns,
		IdleConnTimeout:       defaultTransportIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTransportTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransportExpectContinueTimeout,
		DialContext: (&net.Dialer{
			Timeout:   defaultTransportDialTimeout,
			KeepAlive: defaultTransportDialKeepAlive,
		}).DialContext,
	}
}

// HTTPClient wraps Transport in a client with the given overall timeout (zero
// means none).
func (e *Egress) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: e.Transport(), Timeout: timeout}
}

// mustURL parses a URL constant. It panics on failure, which only a broken
// constant can cause; the test pins that path.
func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Sprintf("egress: bad URL constant %q: %v", raw, err))
	}

	return u
}
