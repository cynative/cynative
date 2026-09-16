package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
)

// connectProxy is a loopback HTTP CONNECT proxy for the tests: it records every
// requested authority and tunnels to target (the origin fixture) or, when a
// refusal status line is set, answers it and closes.
type connectProxy struct {
	srv    *httptest.Server
	target string
	mu     sync.Mutex
	conns  []string
	refuse string // status line without the HTTP/1.1 prefix, e.g. "502 Bad Gateway".
	raw    string // when set, written verbatim instead of any status line (malformed replies).
}

func newConnectProxy(t *testing.T, target string) *connectProxy {
	t.Helper()
	p := &connectProxy{target: target}
	p.srv = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)

	return p
}

// hostPort is the proxy's host:port, the value HTTPS_PROXY carries.
func (p *connectProxy) hostPort() string { return strings.TrimPrefix(p.srv.URL, "http://") }

func (p *connectProxy) authorities() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.conns...)
}

func (p *connectProxy) setRefuse(status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuse = status
}

func (p *connectProxy) setRaw(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = line
}

func (p *connectProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)

		return
	}
	p.mu.Lock()
	p.conns = append(p.conns, r.URL.Host) // for CONNECT, URL.Host is the requested authority.
	refuse, raw := p.refuse, p.raw
	p.mu.Unlock()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)

		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if raw != "" {
		_, _ = io.WriteString(conn, raw)

		return
	}
	if refuse != "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 "+refuse+"\r\nContent-Length: 0\r\n\r\n")

		return
	}
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")

		return
	}
	defer up.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, bufio.NewReader(buf)); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// proxiedEgress builds a policy that sends everything but noProxy through p.
func proxiedEgress(t *testing.T, p *connectProxy, noProxy string) *auth.Egress {
	t.Helper()
	e, err := auth.NewEgress(func(k string) (string, bool) {
		switch k {
		case "HTTPS_PROXY":
			return "http://" + p.hostPort(), true
		case "NO_PROXY":
			return noProxy, noProxy != ""
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// originURL rewrites an httptest TLS server URL (https://127.0.0.1:port) to the
// example.com name its built-in certificate also covers, so the request is
// proxied (loopback never is) and the origin certificate still verifies.
func originURL(srv *httptest.Server) string {
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	return "https://example.com:" + port + "/"
}

func originTarget(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

// placeholder is what Egress.Scrub leaves behind in place of a credential.
const placeholder = "[REDACTED:proxy-credential]"

// denyAddrProvider authorizes every host but no address, so a direct route
// always stops at the dial guard before any connection is attempted.
type denyAddrProvider struct{}

func (denyAddrProvider) Name() string                                         { return "deny-addr" }
func (denyAddrProvider) Description() string                                  { return "denies every address" }
func (denyAddrProvider) InjectAuth(*http.Request, authreq.ProviderArgs) error { return nil }
func (denyAddrProvider) AuthorizesHost(context.Context, string, authreq.ProviderArgs) (bool, error) {
	return true, nil
}

func (denyAddrProvider) AuthorizesAddr(context.Context, netip.Addr, authreq.ProviderArgs) (bool, error) {
	return false, nil
}

// denyHostProvider authorizes no host, so every request is rejected before
// route selection.
type denyHostProvider struct{}

func (denyHostProvider) Name() string                                         { return "deny-host" }
func (denyHostProvider) Description() string                                  { return "denies every host" }
func (denyHostProvider) InjectAuth(*http.Request, authreq.ProviderArgs) error { return nil }
func (denyHostProvider) AuthorizesHost(context.Context, string, authreq.ProviderArgs) (bool, error) {
	return false, nil
}

func TestWithEgress_NilKeepsTheDirectDefault(t *testing.T) {
	t.Parallel()

	c := NewClient(WithEgress(nil))
	if c.egress == nil || c.egress.Route(mustTarget(t, "https://api.github.com/")).Proxied() {
		t.Fatal("WithEgress(nil) must keep the direct default policy")
	}
}

func mustTarget(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestExecute_ProxiedRequestTunnelsThroughCONNECT(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "via-tunnel")
	}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	ctx, rt := audit.WithRoute(context.Background())

	out, status, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).
		Execute(ctx, makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}), providers)
	if err != nil || status != http.StatusOK || !strings.Contains(out, "via-tunnel") {
		t.Fatalf("Execute = %q, %d, %v", out, status, err)
	}
	if got := proxy.authorities(); len(got) != 1 || !strings.HasPrefix(got[0], "example.com:") {
		t.Fatalf("proxy saw %v, want one CONNECT to example.com", got)
	}
	if hits.Load() != 1 || rt.Value() != audit.RouteProxy {
		t.Fatalf("origin hits %d, route %q", hits.Load(), rt.Value())
	}
}

func TestExecute_LoopbackTargetStaysDirectWithTheGuard(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	egress := proxiedEgress(t, proxy, "")

	// Positive: a provider that authorizes the loopback address reaches the
	// origin directly; the proxy never sees a CONNECT.
	ctx, rt := audit.WithRoute(context.Background())
	out, _, err := NewClient(WithEgress(egress)).Execute(ctx,
		makeArgs(t, map[string]any{"url": srv.URL + "/", "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	if err != nil || !strings.Contains(out, "direct") || rt.Value() != audit.RouteDirect {
		t.Fatalf("direct Execute = %q, %v, route %q", out, err, rt.Value())
	}
	// Negative: without an AddrAuthorizer the internal-range guard still runs.
	_, _, err = NewClient(WithEgress(egress)).Execute(context.Background(),
		makeArgs(t, map[string]any{"url": srv.URL + "/", "auth_provider": "host-only"}),
		[]auth.Provider{&hostOnlyProvider{caCert: tlsCertBase64(t, srv)}})
	if !errors.Is(err, auth.ErrAddrNotAuthorized) {
		t.Fatalf("direct route must keep the dial guard, got %v", err)
	}
	if got := proxy.authorities(); len(got) != 0 {
		t.Fatalf("a direct route must never touch the proxy, saw %v", got)
	}
}

func TestExecute_NoProxyMatchKeepsTheGuard(t *testing.T) {
	t.Parallel()

	// 192.0.2.1 (TEST-NET-1) is not loopback, so only the NO_PROXY entry makes
	// the route direct; the dial guard then refuses the address before any
	// connection is attempted, so no packet leaves and no DNS is involved.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	ctx, rt := audit.WithRoute(context.Background())

	_, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, "192.0.2.1"))).Execute(ctx,
		makeArgs(t, map[string]any{"url": "https://192.0.2.1/", "auth_provider": "deny-addr"}),
		[]auth.Provider{denyAddrProvider{}})
	if !errors.Is(err, auth.ErrAddrNotAuthorized) {
		t.Fatalf("a NO_PROXY match must go direct and keep the dial guard, got %v", err)
	}
	if len(proxy.authorities()) != 0 || rt.Value() != audit.RouteDirect {
		t.Fatalf("CONNECTs %v, route %q; want none and direct", proxy.authorities(), rt.Value())
	}
}

func TestExecute_TLSFailureInsideTheTunnel(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "should-not-reach")
	}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	ctx, rt := audit.WithRoute(context.Background())

	// No CA from the provider: the origin certificate is untrusted through the tunnel.
	_, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).Execute(ctx,
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{}})
	if err == nil || (!strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509")) {
		t.Fatalf("expected a TLS verification error through the tunnel, got %v", err)
	}
	if hits.Load() != 0 || len(proxy.authorities()) != 1 || rt.Value() != audit.RouteProxy {
		t.Fatalf("origin hits %d, CONNECTs %d, route %q", hits.Load(), len(proxy.authorities()), rt.Value())
	}
}

// TestExecute_ProxyRefusalFailsTheRequest: a refused CONNECT is the request's
// error. That no other address is dialed is proven by
// TestBindRoute_ProxiedDialAcceptsOnlyTheProxy in internal/auth, which drives
// the proxied dialer with a fake and sees it refuse everything but the proxy.
func TestExecute_ProxyRefusalFailsTheRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	proxy.setRefuse("502 Bad Gateway")
	ctx, rt := audit.WithRoute(context.Background())

	_, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).Execute(ctx,
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	// Go reports a failed CONNECT by the reason phrase alone ("Bad Gateway").
	if err == nil || !strings.Contains(err.Error(), "Bad Gateway") {
		t.Fatalf("expected the proxy refusal to fail the request, got %v", err)
	}
	if len(proxy.authorities()) != 1 || rt.Value() != audit.RouteProxy {
		t.Fatalf("CONNECTs %v, route %q; want one attempt and the proxy route", proxy.authorities(), rt.Value())
	}
}

func TestExecute_DeniedHostNeverReachesTheProxy(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	ctx, rt := audit.WithRoute(context.Background())

	_, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).Execute(ctx,
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "deny-host"}),
		[]auth.Provider{denyHostProvider{}})
	if !errors.Is(err, auth.ErrHostNotAuthorized) {
		t.Fatalf("expected the host gate to deny, got %v", err)
	}
	if len(proxy.authorities()) != 0 || rt.Value() != "" {
		t.Fatalf("a denied request must not select a route: CONNECTs %v, route %q", proxy.authorities(), rt.Value())
	}
}

func TestExecute_ProxyCredentialIsScrubbedFromErrors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	proxy.setRefuse("407 Proxy Authentication Required s3cret")
	egress, err := auth.NewEgress(func(k string) (string, bool) {
		if k == "HTTPS_PROXY" {
			return "http://alice:s3cret@" + proxy.hostPort(), true
		}

		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = NewClient(WithEgress(egress)).Execute(context.Background(),
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("the proxy credential leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), placeholder) {
		t.Fatalf("expected the placeholder in the error, got %v", err)
	}
	// ExecuteStructured takes the same path.
	_, serr := NewClient(WithEgress(egress)).ExecuteStructured(context.Background(),
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	if serr == nil || strings.Contains(serr.Error(), "s3cret") {
		t.Fatalf("ExecuteStructured leaked the credential: %v", serr)
	}
	if !strings.Contains(serr.Error(), placeholder) {
		t.Fatalf("ExecuteStructured: expected the placeholder, got %v", serr)
	}

	// A malformed reply line quotes what the proxy sent; the Basic token of
	// alice:s3cret is YWxpY2U6czNjcmV0.
	proxy.setRaw("garbage YWxpY2U6czNjcmV0\r\n\r\n")
	_, _, err = NewClient(WithEgress(egress)).Execute(context.Background(),
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	if err == nil || strings.Contains(err.Error(), "YWxpY2U6czNjcmV0") {
		t.Fatalf("a malformed proxy reply leaked the Basic token: %v", err)
	}
	if !strings.Contains(err.Error(), placeholder) {
		t.Fatalf("a malformed proxy reply must be scrubbed to the placeholder, got %v", err)
	}
}

func TestExecute_TrailerParseErrorIsScrubbed(t *testing.T) {
	t.Parallel()

	// The origin answers with a chunked body whose trailer line is malformed
	// and carries the Basic token; the body-read error raised after do()
	// must still be scrubbed on both execution APIs.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Echo\r\n\r\n"+
			"2\r\nok\r\n0\r\nX-Echo YWxpY2U6czNjcmV0\r\n\r\n")
	}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))
	egress, err := auth.NewEgress(func(k string) (string, bool) {
		if k == "HTTPS_PROXY" {
			return "http://alice:s3cret@" + proxy.hostPort(), true
		}

		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	args := makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "loopback"})

	_, _, err = NewClient(WithEgress(egress)).Execute(context.Background(), args, providers)
	if err == nil || strings.Contains(err.Error(), "YWxpY2U6czNjcmV0") || !strings.Contains(err.Error(), placeholder) {
		t.Fatalf("Execute: trailer error must be scrubbed to the placeholder, got %v", err)
	}
	_, err = NewClient(WithEgress(egress)).ExecuteStructured(context.Background(), args, providers)
	if err == nil || strings.Contains(err.Error(), "YWxpY2U6czNjcmV0") || !strings.Contains(err.Error(), placeholder) {
		t.Fatalf("ExecuteStructured: trailer error must be scrubbed to the placeholder, got %v", err)
	}
}

func TestExecute_MTLSClientCertReachesTheOriginThroughTheTunnel(t *testing.T) {
	t.Parallel()

	caCert, caPrivKey, err := authtest.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	clientCertPEM, clientKeyPEM, err := authtest.GenerateCert(caCert, caPrivKey, false)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	// No Certificates set: StartTLS installs httptest's built-in leaf, which
	// covers example.com, so the proxied name verifies against the provider CA.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			fmt.Fprint(w, "mtls-ok")

			return
		}
		fmt.Fprint(w, "missing-client-cert")
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))

	provider := authtest.NewAKSCert(tlsCertBase64(t, srv),
		base64.StdEncoding.EncodeToString(clientCertPEM), base64.StdEncoding.EncodeToString(clientKeyPEM))
	out, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).Execute(context.Background(),
		makeArgs(t, map[string]any{"url": originURL(srv), "auth_provider": "aks"}), []auth.Provider{provider})
	if err != nil || !strings.Contains(out, "mtls-ok") {
		t.Fatalf("mTLS through the tunnel: %q, %v", out, err)
	}
}

func TestExecute_ProxyAuthorizationHeaderStillRejectedWhenProxied(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	proxy := newConnectProxy(t, originTarget(srv))

	_, _, err := NewClient(WithEgress(proxiedEgress(t, proxy, ""))).Execute(context.Background(),
		makeArgs(t, map[string]any{
			"url":           originURL(srv),
			"auth_provider": "loopback",
			"headers":       []map[string]string{{"key": "Proxy-Authorization", "value": "Basic x"}},
		}),
		[]auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}})
	if !errors.Is(err, auth.ErrModelSuppliedCredential) || len(proxy.authorities()) != 0 {
		t.Fatalf("model-supplied Proxy-Authorization must be rejected before any CONNECT: %v, %v",
			err, proxy.authorities())
	}
}
