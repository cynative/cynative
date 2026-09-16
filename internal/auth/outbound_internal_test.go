package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"testing"

	"github.com/cynative/cynative/internal/outbound"
)

// errDirect is what the stand-in direct-dial policy reports, so a test can tell
// the caller's own policy apart from the proxy pin that replaces it.
var errDirect = errors.New("direct policy ran")

// directControl is a stand-in for a caller's dial-time address policy.
func directControl(context.Context, string, string, syscall.RawConn) error {
	return errDirect
}

// routingTo builds a Routing that proxies everything to endpoint.
func routingTo(t *testing.T, endpoint, noProxy string) outbound.Routing {
	t.Helper()

	r, err := outbound.New(outbound.Config{HTTPSProxy: endpoint, NoProxy: noProxy})
	if err != nil {
		t.Fatalf("outbound.New(%q): %v", endpoint, err)
	}

	return r
}

// publicAddr is a public address no dial policy in these tests is pinned to.
const publicAddr = "93.184.216.34"

// dialPublic drives a transport's dial control hook the way [net.Dialer] would,
// returning what the installed policy decided about a public address.
func dialPublic(t *testing.T, tr *http.Transport) error {
	t.Helper()

	_, err := tr.DialContext(context.Background(), "tcp", net.JoinHostPort(publicAddr, "443"))

	return err
}

func TestRouteOutbound_NoProxyKeepsTheCallersPolicy(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(outbound.Routing{}, "https://api.example/x", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	tr := &http.Transport{}
	route.Apply(tr, &net.Dialer{})

	if tr.Proxy != nil {
		t.Error("Proxy must stay nil without a configured proxy, so the dial guard sees the real target IP")
	}
	if derr := dialPublic(t, tr); !errors.Is(derr, errDirect) {
		t.Errorf("dial policy = %v, want the caller's own direct policy", derr)
	}
}

func TestRouteOutbound_NoProxyMatchKeepsTheCallersPolicy(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(
		routingTo(t, "http://127.0.0.1:8080", "api.example"), "https://api.example/x", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	tr := &http.Transport{}
	route.Apply(tr, &net.Dialer{})

	if tr.Proxy != nil {
		t.Error("a NO_PROXY match must dial direct, not through the proxy")
	}
	if derr := dialPublic(t, tr); !errors.Is(derr, errDirect) {
		t.Errorf("dial policy = %v, want the caller's own direct policy", derr)
	}
}

func TestRouteOutbound_ProxiedPinsTheDialAndSetsTheProxy(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(
		routingTo(t, "http://127.0.0.1:8080", ""), "https://ec2.us-east-1.amazonaws.com/", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	tr := &http.Transport{}
	route.Apply(tr, &net.Dialer{})

	if tr.Proxy == nil {
		t.Fatal("Proxy = nil, want the configured endpoint")
	}

	proxy, perr := tr.Proxy(&http.Request{}) //nolint:exhaustruct // the route's Proxy ignores the request.
	if perr != nil {
		t.Fatalf("Proxy: %v", perr)
	}
	if proxy.Host != "127.0.0.1:8080" {
		t.Errorf("proxy = %q, want 127.0.0.1:8080", proxy.Host)
	}

	// The caller's direct policy is gone: the connection is to the proxy, so
	// judging it by the target's address policy would judge the wrong address.
	if derr := dialPublic(t, tr); errors.Is(derr, errDirect) {
		t.Error("a proxied dial must not run the caller's direct policy")
	}
	if derr := dialPublic(t, tr); !errors.Is(derr, ErrAddrNotAuthorized) {
		t.Errorf("dial to a non-proxy address = %v, want ErrAddrNotAuthorized", derr)
	}
}

// TestRouteOutbound_UndecidableTargetDenies pins the fail-closed path: when the
// routing cannot decide where a target goes, no client is built at all, rather
// than one that quietly bypasses the operator's proxy.
func TestRouteOutbound_UndecidableTargetDenies(t *testing.T) {
	t.Parallel()

	_, err := RouteOutbound(routingTo(t, "http://127.0.0.1:8080", ""), "://nonsense", directControl)
	if err == nil {
		t.Fatal("RouteOutbound err = nil, want the routing failure surfaced")
	}
}

// TestRouteOutbound_NonHTTPTargetIsNotProxied pins that a target the selector
// does not recognize as http(s) stays on the caller's own policy rather than
// being handed to the proxy.
func TestRouteOutbound_NonHTTPTargetIsNotProxied(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(routingTo(t, "http://127.0.0.1:8080", ""), "api.example/x", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}
	if route.proxy != nil {
		t.Errorf("proxy = %v, want nil for a target the selector does not proxy", route.proxy)
	}
}

func TestProxyPin_AuthorizesOnlyTheEndpoint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		ip   string
		want bool
	}{
		{"loopback endpoint dials itself", "127.0.0.1", "127.0.0.1", true},
		{"loopback endpoint, another address", "127.0.0.1", "127.0.0.2", false},
		{"rfc1918 endpoint dials itself", "192.168.64.3", "192.168.64.3", true},
		{"rfc1918 endpoint, another address", "192.168.64.3", "192.168.64.4", false},
		{"public endpoint dials itself", "93.184.216.34", "93.184.216.34", true},
		{"ipv4-mapped form of the endpoint", "127.0.0.1", "::ffff:127.0.0.1", true},
		{"ipv6 loopback endpoint", "::1", "::1", true},
		{"cloud metadata is refused even as the endpoint", "169.254.169.254", "169.254.169.254", false},
		{"azure wireserver is refused", "168.63.129.16", "168.63.129.16", false},
		{"ula ipv6 is refused", "fd00:ec2::254", "fd00:ec2::254", false},
		{"the unspecified address is refused", "0.0.0.0", "0.0.0.0", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			p := &proxyPin{host: c.host, resolver: nil} // an IP host never resolves.

			got, err := p.authorizesDialIP(context.Background(), netip.MustParseAddr(c.ip))
			if err != nil {
				t.Fatalf("authorizesDialIP: %v", err)
			}
			if got != c.want {
				t.Errorf("authorizesDialIP(%s) for endpoint %s = %v, want %v", c.ip, c.host, got, c.want)
			}
		})
	}
}

func TestProxyPin_NamedEndpointUsesItsResolution(t *testing.T) {
	t.Parallel()

	p := &proxyPin{
		host: "proxy.corp.example",
		resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		},
	}

	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.1.2.4", false},
	} {
		got, err := p.authorizesDialIP(context.Background(), netip.MustParseAddr(c.ip))
		if err != nil {
			t.Fatalf("authorizesDialIP(%s): %v", c.ip, err)
		}
		if got != c.want {
			t.Errorf("authorizesDialIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestProxyPin_ResolveFailureFailsClosed(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("no such host")
	p := &proxyPin{
		host:     "proxy.corp.example",
		resolver: func(context.Context, string) ([]netip.Addr, error) { return nil, wantErr },
	}

	got, err := p.authorizesDialIP(context.Background(), netip.MustParseAddr("10.1.2.3"))
	if got {
		t.Error("authorizesDialIP = true, want false when the endpoint cannot be resolved")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want the resolver's error", err)
	}
}

// TestOutboundRoute_ApplyKeepsTheDialersTimeouts pins that Apply configures the
// caller's dialer rather than replacing it, so per-client phase timeouts survive.
func TestOutboundRoute_ApplyKeepsTheDialersTimeouts(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(outbound.Routing{}, "https://api.example/x", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	dialer := &net.Dialer{Timeout: 7, KeepAlive: 9}
	tr := &http.Transport{}
	route.Apply(tr, dialer)

	if dialer.Timeout != 7 || dialer.KeepAlive != 9 {
		t.Errorf("dialer timeouts = %v/%v, want them preserved", dialer.Timeout, dialer.KeepAlive)
	}
	if tr.DialContext == nil {
		t.Error("DialContext = nil, want the route's dialer installed")
	}
	if dialer.ControlContext == nil {
		t.Error("ControlContext = nil, want the route's dial policy installed")
	}
}

// TestRouteOutbound_ProxyURLIsTheOperatorsOwn pins that the proxy handed to the
// transport is the configured endpoint itself, not something derived per
// request: no request argument can steer it.
func TestRouteOutbound_ProxyURLIsTheOperatorsOwn(t *testing.T) {
	t.Parallel()

	route, err := RouteOutbound(
		routingTo(t, "http://proxy.corp.example:3128", ""), "https://s3.amazonaws.com/b", directControl)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	want := &url.URL{Scheme: "http", Host: "proxy.corp.example:3128"}
	if route.proxy.Scheme != want.Scheme || route.proxy.Host != want.Host {
		t.Errorf("proxy = %v, want %v", route.proxy, want)
	}
}
