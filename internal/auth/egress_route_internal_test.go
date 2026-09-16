package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRoute_NoProxyMatchingFollowsHTTPProxyRules(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{
		"HTTPS_PROXY": "http://proxy.corp:3128",
		"NO_PROXY":    "internal.example,.corp.example,10.0.0.0/8,192.168.1.5,api.example.test.",
	})
	cases := []struct {
		target  string
		proxied bool
	}{
		{"https://api.github.com/user", true},
		{"https://internal.example/x", false},
		{"https://svc.internal.example/x", false},
		{"https://svc.corp.example/x", false},
		{"https://corp.example/x", true},
		{"https://10.1.2.3:6443/api", false},
		{"https://192.168.1.5:6443/api", false},
		{"https://192.168.1.6:6443/api", true},
		{"https://localhost:8443/x", false},
		{"https://LOCALHOST:8443/x", true},
		{"https://127.0.0.1:8443/x", false},
		{"https://[::1]:8443/x", false},
		{"https://api.example.test/x", true},
		{"https://api.example.test./x", false},
		{"https://internal.example./x", true},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()
			r := e.Route(mustURL(tc.target))
			if r.Proxied() != tc.proxied {
				t.Fatalf("Route(%s).Proxied() = %v, want %v", tc.target, r.Proxied(), tc.proxied)
			}
			if r.Proxied() && r.Proxy.Host != "proxy.corp:3128" {
				t.Fatalf("Route(%s).Proxy = %v, want the configured proxy", tc.target, r.Proxy)
			}
		})
	}
}

func TestRoute_WildcardDisablesTheProxy(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "*"})
	if e.Route(mustURL("https://api.github.com/")).Proxied() {
		t.Fatal("NO_PROXY=* must make every host direct")
	}
}

func TestRoute_HTTPTargetUsesHTTPProxyOnly(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://s:1", "HTTP_PROXY": "http://h:2"})
	if got := e.Route(mustURL("http://plain.example/")).Proxy.Host; got != "h:2" {
		t.Fatalf("http target routed to %q, want the HTTP_PROXY", got)
	}
	if got := e.Route(mustURL("https://tls.example/")).Proxy.Host; got != "s:1" {
		t.Fatalf("https target routed to %q, want the HTTPS_PROXY", got)
	}
}

func TestRoute_DirectPolicyNeverProxies(t *testing.T) {
	t.Parallel()

	if NoProxy().Route(mustURL("https://api.github.com/")).Proxied() {
		t.Fatal("NoProxy must route direct")
	}
}

func TestProxyForRequest_AgreesWithRoute(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "direct.example"})
	for _, target := range []string{"https://api.github.com/", "https://direct.example/"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		got, err := e.proxyForRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		want := e.Route(req.URL).Proxy
		if (got == nil) != (want == nil) || (got != nil && got.String() != want.String()) {
			t.Fatalf("proxyForRequest(%s) = %v, Route = %v", target, got, want)
		}
	}
}

func TestRouteEndpoint_ParsesOrFails(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})
	r, err := e.RouteEndpoint("https://kube.example.test:6443")
	if err != nil || !r.Proxied() {
		t.Fatalf("RouteEndpoint = %v, %v; want a proxied route", r, err)
	}
	if _, err = e.RouteEndpoint("https://bad host"); err == nil {
		t.Fatal("RouteEndpoint must fail on an unparsable endpoint")
	}
}

func TestMustURL_PanicsOnBadValue(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("mustURL must panic on an unparsable constant")
		}
	}()
	mustURL("https://bad host")
}

func TestProxyAuthority_MatchesNetHTTP(t *testing.T) {
	t.Parallel()

	// For each scheme, a real http.Transport must hand DialContext exactly the
	// authority proxyAuthority computes; the fake dial refuses so no bytes flow.
	for _, raw := range []string{
		"http://proxy.corp", "http://proxy.corp:3128", "socks5://proxy.corp",
		"socks5h://[::1]", "socks5://10.0.0.9:1081",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			p := mustURL(raw)
			var mu sync.Mutex
			var dialed []string
			tr := &http.Transport{
				Proxy: http.ProxyURL(p),
				DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
					mu.Lock()
					dialed = append(dialed, addr)
					mu.Unlock()

					return nil, errors.New("fake dial")
				},
			}
			req := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
			_, err := tr.RoundTrip(req)
			if err == nil {
				t.Fatal("expected the fake dial to fail the round trip")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(dialed) != 1 || dialed[0] != proxyAuthority(p) {
				t.Fatalf("net/http dialed %v, proxyAuthority = %q", dialed, proxyAuthority(p))
			}
		})
	}
}

func TestBindRoute_ProxiedDialAcceptsOnlyTheProxy(t *testing.T) {
	t.Parallel()

	p := mustURL("http://127.0.0.1:3128")
	var directCalls, proxyCalls int
	direct := func(context.Context, string, string) (net.Conn, error) {
		directCalls++

		return nil, errors.New("direct")
	}
	proxy := func(_ context.Context, _, addr string) (net.Conn, error) {
		proxyCalls++

		return nil, errors.New("proxy " + addr)
	}
	tr := &http.Transport{}
	bindRoute(tr, Route{Proxy: p}, direct, proxy)

	if got, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://x/", nil)); got.String() != p.String() {
		t.Fatalf("Proxy = %v, want %v", got, p)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443"); !errors.Is(err, ErrProxyDialMismatch) {
		t.Fatalf("dial to another address = %v, want ErrProxyDialMismatch", err)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:3128"); err == nil ||
		err.Error() != "proxy 127.0.0.1:3128" {
		t.Fatalf("dial to the proxy = %v, want the proxy dialer's error", err)
	}
	if directCalls != 0 || proxyCalls != 1 {
		t.Fatalf("direct %d proxy %d calls, want 0 and 1", directCalls, proxyCalls)
	}
}

func TestBindRoute_DirectKeepsTheGuardedDialer(t *testing.T) {
	t.Parallel()

	var directCalls int
	direct := func(context.Context, string, string) (net.Conn, error) {
		directCalls++

		return nil, errors.New("direct")
	}
	tr := &http.Transport{}
	bindRoute(tr, Route{Proxy: nil}, direct, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("proxy dialer must not be installed on a direct route")

		return nil, errors.New("unreachable")
	})
	if tr.Proxy != nil {
		t.Fatal("direct route must leave Proxy nil")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443"); err == nil || directCalls != 1 {
		t.Fatalf("direct dial = %v (calls %d), want the guarded dialer", err, directCalls)
	}
}

func TestConfigureTransport_ProxiedDialerDropsTheControlHook(t *testing.T) {
	t.Parallel()

	// The control hook would deny a loopback proxy; a proxied route must dial
	// the proxy without it, so the connection to a loopback proxy succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()
	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://" + ln.Addr().String()})
	denyAll := func(context.Context, string, string, syscall.RawConn) error { return errors.New("denied by guard") }
	direct := &net.Dialer{Timeout: time.Second, ControlContext: denyAll}

	tr := &http.Transport{}
	e.ConfigureTransport(tr, e.Route(mustURL("https://api.github.com/")), direct)
	c, err := tr.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("proxied dial must skip the control hook, got %v", err)
	}
	c.Close()

	tr2 := &http.Transport{}
	e.ConfigureTransport(tr2, Route{Proxy: nil}, direct)
	if _, err = tr2.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil ||
		!strings.Contains(err.Error(), "denied by guard") {
		t.Fatalf("direct dial must keep the control hook, got %v", err)
	}
}

func TestTransport_DefaultsAndPerRequestSelection(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "direct.example"})
	tr := e.Transport()
	if !tr.ForceAttemptHTTP2 || tr.MaxIdleConns != defaultTransportMaxIdleConns ||
		tr.IdleConnTimeout != defaultTransportIdleConnTimeout ||
		tr.TLSHandshakeTimeout != defaultTransportTLSHandshakeTimeout ||
		tr.ExpectContinueTimeout != defaultTransportExpectContinueTimeout || tr.DialContext == nil {
		t.Fatalf("Transport() does not carry the DefaultTransport defaults: %+v", tr)
	}
	proxied, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://api.github.com/", nil))
	direct, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://direct.example/", nil))
	if proxied == nil || direct != nil {
		t.Fatalf("per-request selection: proxied=%v direct=%v", proxied, direct)
	}
	hc := e.HTTPClient(3 * time.Second)
	if hc.Timeout != 3*time.Second || hc.Transport == nil {
		t.Fatalf("HTTPClient = %+v", hc)
	}
	if NoProxy().Transport().Proxy == nil {
		t.Fatal("NoProxy().Transport() still carries the selector (it answers nil per request)")
	}
}

// TestSOCKS5H_SendsTheNameToTheProxy proves a socks5h route hands the unresolved
// destination name to the proxy: a fake SOCKS5 server records the domain-name
// address the client sends, then refuses, so no origin is ever dialed.
func TestSOCKS5H_SendsTheNameToTheProxy(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		fail := func() { got <- "" }
		// Every SOCKS5 field is read with io.ReadFull: TCP has no message
		// boundaries, so a single Read could return a partial frame.
		hdr := make([]byte, 2) // VER, NMETHODS.
		if _, rerr := io.ReadFull(c, hdr); rerr != nil {
			fail()

			return
		}
		if _, rerr := io.ReadFull(c, make([]byte, int(hdr[1]))); rerr != nil { // METHODS.
			fail()

			return
		}
		_, _ = c.Write([]byte{5, 0}) // no authentication.
		req := make([]byte, 4)       // VER, CMD, RSV, ATYP.
		if _, rerr := io.ReadFull(c, req); rerr != nil || req[3] != 3 {
			fail()

			return
		}
		nameLen := make([]byte, 1)
		if _, rerr := io.ReadFull(c, nameLen); rerr != nil {
			fail()

			return
		}
		name := make([]byte, int(nameLen[0]))
		if _, rerr := io.ReadFull(c, name); rerr != nil {
			fail()

			return
		}
		got <- string(name)
		_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}) // reply: connection not allowed.
	}()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "socks5h://" + ln.Addr().String()})
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	e.ConfigureTransport(tr, e.Route(mustURL("https://origin.invalid/")), &net.Dialer{Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://origin.invalid/", nil).WithContext(ctx))
	if err == nil {
		t.Fatal("the fake SOCKS server refuses, so the round trip must fail")
	}
	select {
	case name := <-got:
		if name != "origin.invalid" {
			t.Fatalf("SOCKS request named %q, want origin.invalid", name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SOCKS request reached the fake proxy")
	}
}
