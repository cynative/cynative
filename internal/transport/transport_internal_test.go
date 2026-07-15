package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/redact"
)

// --- helpers ---

type githubTestProvider struct {
	token  string
	caCert string // base64 PEM; supplied to configureTransport when set.
}

func (p *githubTestProvider) Name() string        { return "github" }
func (p *githubTestProvider) Description() string { return "Test GitHub" }
func (p *githubTestProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	req.Header.Set("Authorization", "Bearer "+p.token)
	if req.Header.Get("X-Github-Api-Version") == "" {
		req.Header.Set("X-Github-Api-Version", "2022-11-28")
	}

	return nil
}

func (p *githubTestProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (p *githubTestProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caCert, nil
}

func (p *githubTestProvider) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return true, nil
}

// newTLSTestServer starts an HTTPS test server and returns it with a
// LoopbackProvider that authorizes any host and trusts the server's cert, so
// Client requests succeed under the host-bound, https-only transport. Use
// "auth_provider":"loopback" in the request args.
func newTLSTestServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, []auth.Provider) {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	return srv, []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
}

// --- FormatResponse tests ---

func TestFormatResponse_Truncation(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", 100)
	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.0",
		Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{},
	}

	result, err := FormatResponse(resp, 10, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "[Response truncated at 10 bytes]") {
		t.Errorf("expected truncation notice, got: %q", result)
	}
}

func TestFormatResponse_TruncationMarkerSurvivesRedaction(t *testing.T) {
	t.Parallel()

	// A large PEM key (redacts to a short placeholder) followed by filler so the
	// raw body exceeds maxBytes, but the redacted dump is short.
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("A", 4000) + "\n-----END RSA PRIVATE KEY-----"
	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.0",
		Body:   io.NopCloser(strings.NewReader(pem)),
		Header: http.Header{},
	}

	out, err := FormatResponse(resp, 200, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "[Response truncated at 200 bytes]") {
		t.Errorf("truncation marker missing after redaction shrank the body: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:pem-private-key]") {
		t.Errorf("expected the key to be redacted: %q", out)
	}
}

func TestFormatResponse_InvalidUTF8Body(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.0",
		Body: io.NopCloser(strings.NewReader("ok\x80data")), Header: http.Header{},
	}

	result, err := FormatResponse(resp, 1024, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !utf8.ValidString(result) {
		t.Errorf("result contains invalid UTF-8")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestFormatResponse_ReadError(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.0",
		Body: io.NopCloser(errReader{}), Header: http.Header{},
	}

	_, err := FormatResponse(resp, 1024, redact.New())
	if err == nil {
		t.Fatal("expected error from read failure")
	}

	if !strings.Contains(err.Error(), "failed to read response body") {
		t.Errorf("expected read error, got: %v", err)
	}
}

func TestFormatResponse_Headers(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusMovedPermanently, Status: "301 Moved Permanently", Proto: "HTTP/1.0",
		Body: io.NopCloser(strings.NewReader("")),
		Header: http.Header{
			"Content-Type": []string{"text/html"},
			"Location":     []string{"/new"},
		},
	}

	result, err := FormatResponse(resp, 1024, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "Content-Type") {
		t.Errorf("expected Content-Type header in output, got: %q", result)
	}

	if !strings.Contains(result, "Location") {
		t.Errorf("expected Location header in output, got: %q", result)
	}
}

// --- Execute tests ---

func makeArgs(t *testing.T, overrides map[string]any) string {
	t.Helper()

	base := map[string]any{
		"method": "GET", "url": "http://localhost/", "headers": []any{},
		"body": "", "timeout_seconds": 5, "max_response_body_size": 1024,
		"auth_provider": "",
		"aws_auth":      nil, "eks_auth": nil, "gke_auth": nil, "azure_auth": nil, "aks_auth": nil,
	}
	maps.Copy(base, overrides)

	data, _ := json.Marshal(base)

	return string(data)
}

func TestExecute_PostWithBody(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected default Content-Type application/json, got %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})

	args := makeArgs(t, map[string]any{
		"method":        "POST",
		"url":           srv.URL + "/echo",
		"body":          `{"key":"value"}`,
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, `{"key":"value"}`) {
		t.Errorf("expected echoed body in result, got: %q", result)
	}
}

func TestExecute_QueryParams(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "q=%s", r.URL.Query().Get("search"))
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/?search=hello",
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "q=hello") {
		t.Errorf("expected query param in result, got: %q", result)
	}
}

func TestExecute_CustomHeaders(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "custom=%s", r.Header.Get("X-Custom-Header"))
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"headers":       []any{map[string]any{"key": "X-Custom-Header", "value": "custom-value"}},
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "custom=custom-value") {
		t.Errorf("expected custom header in result, got: %q", result)
	}
}

func TestExecute_RejectsModelSuppliedAuthorization(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server must never be hit when a model-supplied credential is rejected")
	})

	// The lowercase key pins the textproto canonicalization (Header.Add turns
	// "authorization" into "Authorization") that the gate's lookup depends on.
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"headers":       []any{map[string]any{"key": "authorization", "value": "Bearer tok"}},
		"auth_provider": "loopback",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if !errors.Is(err, auth.ErrModelSuppliedCredential) {
		t.Fatalf("Execute = %v, want auth.ErrModelSuppliedCredential", err)
	}
}

func TestExecute_RejectsURLUserinfo(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("server must never be hit when URL userinfo is rejected")
	})

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	args := makeArgs(t, map[string]any{
		"url":           "https://model:smuggled@" + u.Host + "/",
		"auth_provider": "loopback",
	})

	_, _, execErr := NewClient().Execute(context.Background(), args, providers)
	if !errors.Is(execErr, auth.ErrModelSuppliedCredential) {
		t.Fatalf("Execute = %v, want auth.ErrModelSuppliedCredential", execErr)
	}
}

func TestExecute_TimeoutClamping(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	args := makeArgs(t, map[string]any{
		"url":             srv.URL + "/",
		"timeout_seconds": 0,
		"auth_provider":   "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "200") {
		t.Errorf("expected 200 status, got: %q", result)
	}
}

func TestExecute_TimeoutClampingHigh(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	args := makeArgs(t, map[string]any{
		"url":             srv.URL + "/",
		"timeout_seconds": 999,
		"auth_provider":   "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "200") {
		t.Errorf("expected 200 status, got: %q", result)
	}
}

func TestExecute_MaxBodySizeZeroDefault(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("A", defaultMaxResponseBytes+100)
	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})

	args := makeArgs(t, map[string]any{
		"url":                    srv.URL + "/",
		"max_response_body_size": 0,
		"auth_provider":          "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := fmt.Sprintf("[Response truncated at %d bytes]", defaultMaxResponseBytes)
	if !strings.Contains(result, want) {
		t.Errorf("expected truncation at default max, got: %q", result)
	}
}

func TestExecute_InvalidMethod(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&authtest.LoopbackProvider{}}
	args := makeArgs(t, map[string]any{
		"method":        "BAD METHOD",
		"url":           "https://localhost/",
		"auth_provider": "loopback",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from invalid method")
	}

	if !strings.Contains(err.Error(), "failed to create http request") {
		t.Errorf("expected request creation error, got: %v", err)
	}
}

func TestExecute_HostHeader(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s", r.Host)
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"headers":       []any{map[string]any{"key": "Host", "value": "evil.example.com"}},
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "host=evil.example.com") {
		t.Errorf("expected custom Host header via req.Host, got: %q", result)
	}
}

func TestExecute_DuplicateHeaders(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values("X-Custom")
		fmt.Fprintf(w, "count=%d", len(vals))
	})

	args := makeArgs(t, map[string]any{
		"url": srv.URL + "/",
		"headers": []any{
			map[string]any{"key": "X-Custom", "value": "val1"},
			map[string]any{"key": "X-Custom", "value": "val2"},
		},
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "count=2") {
		t.Errorf("expected 2 header values from Add(), got: %q", result)
	}
}

func TestExecute_GetWithBody(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "method=%s body=%s", r.Method, string(body))
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"body":          `{"query":"test"}`,
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, `body={"query":"test"}`) {
		t.Errorf("expected body with GET request, got: %q", result)
	}
}

func TestExecute_AcceptEncodingDropped(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")

		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte("decompressed-ok"))
		gz.Close()
		_, _ = w.Write(buf.Bytes())
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"headers":       []any{map[string]any{"key": "Accept-Encoding", "value": "gzip"}},
		"auth_provider": "loopback",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "decompressed-ok") {
		t.Errorf("expected auto-decompressed body, got: %q", result)
	}
}

// --- Auth provider integration tests ---

func TestExecute_AuthProviderInjection(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s version=%s",
			r.Header.Get("Authorization"),
			r.Header.Get("X-Github-Api-Version"))
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&githubTestProvider{token: "ghp_injected", caCert: tlsCertBase64(t, srv)}}
	args := makeArgs(t, map[string]any{"url": srv.URL + "/", "auth_provider": "github"})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "auth=Bearer ghp_injected") {
		t.Errorf("expected injected auth header, got: %q", result)
	}

	if !strings.Contains(result, "version=2022-11-28") {
		t.Errorf("expected GitHub API version header, got: %q", result)
	}
}

func TestExecute_AuthProviderCaseInsensitive(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&githubTestProvider{token: "ghp_case", caCert: tlsCertBase64(t, srv)}}
	args := makeArgs(t, map[string]any{"url": srv.URL + "/", "auth_provider": "GitHub"})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "auth=Bearer ghp_case") {
		t.Errorf("expected case-insensitive match, got: %q", result)
	}
}

func TestExecute_AuthProviderInjectError(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&authtest.FailingProvider{}}
	args := makeArgs(t, map[string]any{
		"url":           "https://api.github.com/x",
		"auth_provider": "failing",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from failing auth provider")
	}

	if !strings.Contains(err.Error(), "failed to inject auth for provider failing") {
		t.Errorf("expected inject auth error, got: %v", err)
	}
}

func TestExecute_UnknownAuthProvider(t *testing.T) {
	t.Parallel()

	args := makeArgs(t, map[string]any{
		"url":           "https://api.github.com/x",
		"auth_provider": "nonexistent",
	})

	_, _, err := NewClient().Execute(context.Background(), args, nil)
	if err == nil {
		t.Fatal("expected error for unknown auth provider")
	}

	if !strings.Contains(err.Error(), "unknown or unavailable auth_provider: nonexistent") {
		t.Errorf("expected unknown provider error, got: %v", err)
	}
}

func TestExecute_EmptyAuthProvider(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&githubTestProvider{token: "x"}}
	args := `{"method":"GET","url":"https://api.github.com/x"}` // no auth_provider.

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil || !strings.Contains(err.Error(), "auth_provider is required") {
		t.Fatalf("expected auth_provider-required error, got %v", err)
	}

	if !strings.Contains(err.Error(), "github") {
		t.Errorf("error should list available providers, got %v", err)
	}
}

func TestExecute_RejectsNonHTTPS(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&authtest.LoopbackProvider{}}
	args := `{"method":"GET","url":"http://api.github.com/x","auth_provider":"loopback"}`

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https-required error, got %v", err)
	}
}

func TestExecute_HostNotAuthorized(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&denyProvider{}}
	args := `{"method":"GET","url":"https://evil.com/x","auth_provider":"deny"}`

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if !errors.Is(err, auth.ErrHostNotAuthorized) {
		t.Fatalf("expected ErrHostNotAuthorized, got %v", err)
	}
}

type denyProvider struct{}

func (p *denyProvider) Name() string                                        { return "deny" }
func (p *denyProvider) Description() string                                 { return "denies all hosts" }
func (p *denyProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }
func (p *denyProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return false, nil
}

// --- CA Transport tests ---

// tlsCertBase64 extracts the server's leaf certificate from an [httptest.Server]
// and returns it as a base64-encoded PEM string, matching the format expected
// by [auth.CACertProvider] implementations.
func tlsCertBase64(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	certBytes := srv.Certificate().Raw
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return base64.StdEncoding.EncodeToString(pemBytes)
}

func TestExecute_CACert(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	t.Cleanup(srv.Close)

	caBase64 := tlsCertBase64(t, srv)

	// Should fail without CA cert (TLS certificate verification failure).
	// Use an authorizing provider that supplies no CA so the TLS handshake is
	// what rejects the request, not a missing auth_provider.
	argsNoCA := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "loopback",
	})

	_, _, err := NewClient().Execute(context.Background(), argsNoCA, []auth.Provider{&authtest.LoopbackProvider{}})
	if err == nil {
		t.Fatal("expected error due to unknown authority without CA cert")
	}

	if !strings.Contains(err.Error(), "certificate") &&
		!strings.Contains(err.Error(), "x509") &&
		!strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("expected TLS/certificate error, got: %v", err)
	}

	// Should succeed with valid CA cert.
	providers := []auth.Provider{authtest.NewEKSCert(caBase64)}
	argsValid := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "eks",
	})

	result, _, err := NewClient().Execute(context.Background(), argsValid, providers)
	if err != nil {
		t.Fatalf("unexpected error with valid CA cert: %v", err)
	}

	if !strings.Contains(result, "ok") {
		t.Errorf("expected 'ok', got: %q", result)
	}
}

func TestExecute_CACert_BadEncoding(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{authtest.NewEKSCert("invalid-base64!")}
	args := makeArgs(t, map[string]any{
		"url":           "https://localhost/",
		"auth_provider": "eks",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from bad base64 encoding")
	}

	if !strings.Contains(err.Error(), "failed to decode CA certificate") {
		t.Errorf("expected decode error, got: %v", err)
	}
}

func TestExecute_CACert_BadPEM(t *testing.T) {
	t.Parallel()

	caBase64 := base64.StdEncoding.EncodeToString([]byte("not-a-pem"))
	providers := []auth.Provider{authtest.NewEKSCert(caBase64)}
	args := makeArgs(t, map[string]any{
		"url":           "https://localhost/",
		"auth_provider": "eks",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from bad PEM data")
	}

	if !strings.Contains(err.Error(), "failed to parse CA certificate") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestCATransport_SystemCertPoolFailure(t *testing.T) {
	t.Parallel()

	// Pins that tlsTransport threads the injected systemCertPool seam into
	// auth.BuildTLSConfig, whose empty-pool fallback keeps the custom CA usable
	// even when the system pool is unavailable.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	t.Cleanup(srv.Close)

	c := NewClient(WithSystemCertPool(func() (*x509.CertPool, error) {
		return nil, errors.New("system pool unavailable")
	}))

	tr, err := c.tlsTransport(&http.Transport{}, tlsCertBase64(t, srv), "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tr.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set even when SystemCertPool fails")
	}
}

func TestExecute_CACert_NonHTTPTransportFallback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	t.Cleanup(srv.Close)

	caBase64 := tlsCertBase64(t, srv)
	providers := []auth.Provider{authtest.NewEKSCert(caBase64)}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "eks",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "ok") {
		t.Errorf("expected 'ok', got: %q", result)
	}
}

func TestConfigureTransport_InstallsTransportWithDialGuard(t *testing.T) {
	t.Parallel()

	client := &http.Client{}
	// name == "" short-circuits GetCACertData/GetClientCertData to ("", nil),
	// so no provider lookup happens, but the dial-guarded transport is still
	// installed (always-install contract for the SSRF dial pin).
	cleanup, err := NewClient().configureTransport(context.Background(), client, "", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cleanup() // must not panic

	if client.Transport == nil {
		t.Error("expected a dial-guarded transport to be installed even without a provider CA")
	}
}

func TestConfigureTransport_DisablesProxy(t *testing.T) {
	t.Parallel()

	// The dial-time IP guard must observe the real target IP. A cloned
	// http.DefaultTransport carries Proxy: ProxyFromEnvironment, which would make
	// Go dial the proxy instead — so the installed transport must disable Proxy.
	client := &http.Client{}
	cleanup, err := NewClient().configureTransport(context.Background(), client, "", nil, nil)
	if err != nil {
		t.Fatalf("configureTransport returned error: %v", err)
	}
	defer cleanup()

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport is %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("configureTransport must set Proxy = nil so the dial guard sees the real target IP")
	}
}

func TestConfigureTransport_NoInheritedTLSDialers(t *testing.T) {
	t.Parallel()

	// The transport must be built fresh (not cloned from the mutable global
	// http.DefaultTransport), so it carries no DialTLS/DialTLSContext that would
	// make net/http skip the guarded DialContext for HTTPS.
	client := &http.Client{}
	cleanup, err := NewClient().configureTransport(context.Background(), client, "", nil, nil)
	if err != nil {
		t.Fatalf("configureTransport returned error: %v", err)
	}
	defer cleanup()

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport is %T, want *http.Transport", client.Transport)
	}
	if tr.DialContext == nil {
		t.Error("expected the guarded DialContext to be installed")
	}
	if tr.DialTLS != nil { //nolint:staticcheck // verifying the deprecated hook is not inherited.
		t.Error("DialTLS must be nil so net/http uses the guarded DialContext for HTTPS")
	}
	if tr.DialTLSContext != nil {
		t.Error("DialTLSContext must be nil so net/http uses the guarded DialContext for HTTPS")
	}
}

// hostOnlyProvider authorizes the host and supplies a CA but deliberately does
// NOT implement AddrAuthorizer, so the default internal-IP deny applies at dial.
type hostOnlyProvider struct {
	caCert string
}

func (p *hostOnlyProvider) Name() string { return "host-only" }

func (p *hostOnlyProvider) Description() string                                 { return "authorizes host only" }
func (p *hostOnlyProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }

func (p *hostOnlyProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (p *hostOnlyProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caCert, nil
}

// addrAllowProvider authorizes ALL hosts AND all resolved addresses, supplying
// the test server's CA so TLS works. Used to prove the dial guard is consulted
// and can be overridden to reach a loopback test server.
type addrAllowProvider struct {
	caCert string
}

func (p *addrAllowProvider) Name() string { return "addr-allow" }

func (p *addrAllowProvider) Description() string                                 { return "allows hosts and addrs" }
func (p *addrAllowProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }

func (p *addrAllowProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (p *addrAllowProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caCert, nil
}

func (p *addrAllowProvider) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return true, nil
}

func TestExecute_DialGuard_BlocksInternalIPByDefault(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "should-not-reach")
	}))
	t.Cleanup(srv.Close)

	// hostOnlyProvider supplies the CA (so TLS would otherwise succeed) and
	// authorizes the host, but does NOT implement AddrAuthorizer — so the
	// default internal-IP deny must block the dial to 127.0.0.1.
	providers := []auth.Provider{&hostOnlyProvider{caCert: tlsCertBase64(t, srv)}}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "host-only",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected dial to be blocked for internal IP")
	}

	if !errors.Is(err, auth.ErrAddrNotAuthorized) {
		t.Errorf("expected ErrAddrNotAuthorized at dial, got: %v", err)
	}
}

func TestExecute_DialGuard_AllowsWhenProviderAuthorizesAddr(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "reached")
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&addrAllowProvider{caCert: tlsCertBase64(t, srv)}}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "addr-allow",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("expected request to succeed when provider allows the addr, got: %v", err)
	}

	if !strings.Contains(result, "reached") {
		t.Errorf("expected handler reached, got: %q", result)
	}
}

func TestDialGuard_ErrorBranches(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&authtest.LoopbackProvider{}}
	guard := dialGuard("loopback", providers, nil)

	// No port -> SplitHostPort fails.
	if err := guard(context.Background(), "tcp", "no-port-here", nil); err == nil ||
		!strings.Contains(err.Error(), "split dial address") {
		t.Errorf("expected split error, got %v", err)
	}

	// Non-IP host with a port -> ParseAddr fails.
	if err := guard(context.Background(), "tcp", "example.com:443", nil); err == nil ||
		!strings.Contains(err.Error(), "parse dial address") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestExecute_BadJSON(t *testing.T) {
	t.Parallel()

	_, _, err := NewClient().Execute(context.Background(), "{bad json}", nil)
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse http_request arguments") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestExecute_MaxResponseBodySizeCapped(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// Request an absurdly large response limit — it should be silently capped.
	args := fmt.Sprintf(
		`{"method":"GET","url":"%s/","headers":[],"body":"",`+
			`"timeout_seconds":5,"max_response_body_size":%d,`+
			`"auth_provider":"loopback","aws_auth":null,"eks_auth":null,"gke_auth":null,"azure_auth":null,"aks_auth":null}`,
		srv.URL, absoluteMaxResponseBytes+1,
	)

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, `{"ok":true}`) {
		t.Errorf("expected response body, got: %q", result)
	}
}

func TestExecute_CACert_GKE(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "gke-ok")
	}))
	t.Cleanup(srv.Close)

	caBase64 := tlsCertBase64(t, srv)

	providers := []auth.Provider{authtest.NewGKECert(caBase64)}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "gke",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error with GKE CA cert: %v", err)
	}

	if !strings.Contains(result, "gke-ok") {
		t.Errorf("expected 'gke-ok', got: %q", result)
	}
}

func TestExecute_CACert_ResolutionError(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{authtest.NewFailingCert()}
	args := makeArgs(t, map[string]any{
		"url":           "https://localhost/",
		"auth_provider": "ca-fail",
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from CA cert resolution failure")
	}

	if !strings.Contains(err.Error(), "CA cert resolution failed") {
		t.Errorf("expected CA cert resolution error, got: %v", err)
	}
}

func TestExecute_CACert_AKS(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "aks-ok")
	}))
	t.Cleanup(srv.Close)

	caBase64 := tlsCertBase64(t, srv)

	providers := []auth.Provider{authtest.NewAKSCert(caBase64, "", "")}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "aks",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error with AKS CA cert: %v", err)
	}

	if !strings.Contains(result, "aks-ok") {
		t.Errorf("expected 'aks-ok', got: %q", result)
	}
}

func TestExecute_CACert_AKS_mTLS(t *testing.T) {
	t.Parallel()

	// 1. Create a CA for the test server.
	caCert, caPrivKey, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// 2. Create the server cert signed by the CA.
	serverCert, serverKey, err := authtest.GenerateCert(caCert, caPrivKey, true)
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}
	serverTLSCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("failed to load server key pair: %v", err)
	}

	// 3. Create the client cert signed by the CA.
	clientCertPEM, clientKeyPEM, err := authtest.GenerateCert(caCert, caPrivKey, false)
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}
	clientCertBase64 := base64.StdEncoding.EncodeToString(clientCertPEM)
	clientKeyBase64 := base64.StdEncoding.EncodeToString(clientKeyPEM)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			fmt.Fprintf(w, "mtls-ok")
		} else {
			fmt.Fprintf(w, "missing-client-cert")
		}
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caBase64 := base64.StdEncoding.EncodeToString(caCert)

	providers := []auth.Provider{authtest.NewAKSCert(caBase64, clientCertBase64, clientKeyBase64)}

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "aks",
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error with AKS mTLS: %v", err)
	}

	if !strings.Contains(result, "mtls-ok") {
		t.Errorf("expected 'mtls-ok', got: %q", result)
	}
}

// TestExecute_CACert_ClosesIdleConnection guards the per-request mTLS/CA cleanup
// ordering: the deferred cleanup must close the connection AFTER the body is read.
// If cleanup runs first (the regression), CloseIdleConnections no-ops on the
// in-use connection and the idle TLS connection then lingers until IdleConnTimeout.
func TestExecute_CACert_ClosesIdleConnection(t *testing.T) {
	t.Parallel()

	states := make(chan http.ConnState, 64)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	// Set before StartTLS so httptest chains (not replaces) this hook.
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		select {
		case states <- state:
		default:
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caBase64 := tlsCertBase64(t, srv)
	providers := []auth.Provider{authtest.NewEKSCert(caBase64)}
	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "eks",
	})

	if _, _, err := NewClient().Execute(context.Background(), args, providers); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case st := <-states:
			if st == http.StateClosed {
				return
			}
		case <-deadline:
			t.Fatal("idle connection not closed promptly after Execute (connection leak)")
		}
	}
}

// --- ExecuteStructured tests ---

func TestExecuteStructured_ParsesResponse(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	args := fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL)

	resp, err := NewClient().ExecuteStructured(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("ExecuteStructured: %v", err)
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.Status)
	}
	if resp.StatusText != "201 Created" {
		t.Errorf("statusText = %q, want 201 Created", resp.StatusText)
	}
	if resp.Body != `{"ok":true}` {
		t.Errorf("body = %q", resp.Body)
	}
	if got := resp.Headers["Content-Type"]; len(got) == 0 || got[0] != "application/json" {
		t.Errorf("headers = %v", resp.Headers)
	}
	if resp.Truncated {
		t.Error("Truncated = true, want false for a body under the limit")
	}
}

func TestExecuteStructured_TruncatesBody(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	})

	args := fmt.Sprintf(`{"method":"GET","url":%q,"max_response_body_size":10,"auth_provider":"loopback"}`, srv.URL)

	resp, err := NewClient().ExecuteStructured(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("ExecuteStructured: %v", err)
	}
	if len(resp.Body) != 10 {
		t.Errorf("body len = %d, want 10 (truncated)", len(resp.Body))
	}
	if !resp.Truncated {
		t.Error("Truncated = false, want true for a body over the limit")
	}
}

func TestExecuteStructured_DoError(t *testing.T) {
	t.Parallel()

	_, err := NewClient().ExecuteStructured(context.Background(), "{bad json}", nil)
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse http_request arguments") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestExecuteStructured_ReadAllError(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("body"))
	})

	c := NewClient(WithReadAll(func(_ io.Reader) ([]byte, error) {
		return nil, errors.New("read all boom")
	}))

	args := fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL)

	_, err := c.ExecuteStructured(context.Background(), args, providers)
	if err == nil {
		t.Fatal("expected error from readAll failure")
	}

	if !strings.Contains(err.Error(), "transport: read response body") {
		t.Errorf("expected read body error, got: %v", err)
	}
}

type errorCertProvider struct {
	auth.Provider
}

func (p *errorCertProvider) Name() string { return "error-cert" }
func (p *errorCertProvider) ClientCertData(_ context.Context, _ json.RawMessage) (string, string, error) {
	return "", "", errors.New("client cert retrieval failed")
}

func (p *errorCertProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return "", nil
}

func TestConfigureTransport_ClientCertError(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&errorCertProvider{}}
	rawArgs := json.RawMessage(`{"auth_provider": "error-cert"}`)

	cleanup, err := NewClient().configureTransport(
		context.Background(), http.DefaultClient, "error-cert", providers, rawArgs,
	)
	if err == nil || !strings.Contains(err.Error(), "client cert retrieval failed") {
		t.Errorf("expected error from client cert data, got %v", err)
	}

	cleanup() // the error-path noop cleanup must be safe to call.
}

func TestTLSTransport_BadClientCertBase64(t *testing.T) {
	t.Parallel()
	_, err := NewClient().tlsTransport(&http.Transport{}, "", "bad!base64", "dmFsaWQtYmFzZTY0", "")
	if err == nil || !strings.Contains(err.Error(), "failed to decode client certificate") {
		t.Errorf("expected base64 decode error, got %v", err)
	}
}

func TestTLSTransport_BadClientKeyBase64(t *testing.T) {
	t.Parallel()
	_, err := NewClient().tlsTransport(&http.Transport{}, "", "dmFsaWQtYmFzZTY0", "bad!base64", "")
	if err == nil || !strings.Contains(err.Error(), "failed to decode client key") {
		t.Errorf("expected base64 decode error, got %v", err)
	}
}

func TestTLSTransport_MismatchedKeyPair(t *testing.T) {
	t.Parallel()
	// Use two different valid base64 strings that don't form a pair.
	cert := base64.StdEncoding.EncodeToString([]byte("not a cert"))
	key := base64.StdEncoding.EncodeToString([]byte("not a key"))
	_, err := NewClient().tlsTransport(&http.Transport{}, "", cert, key, "")
	if err == nil || !strings.Contains(err.Error(), "failed to parse client certificate key pair") {
		t.Errorf("expected key pair error, got %v", err)
	}
}

func TestTLSTransport_ServerName_Set(t *testing.T) {
	t.Parallel()

	base := &http.Transport{DialContext: (&net.Dialer{}).DialContext}
	tr, err := NewClient().tlsTransport(base, "", "", "", "api.internal")
	if err != nil {
		t.Fatalf("tlsTransport returned error: %v", err)
	}
	if tr.TLSClientConfig.ServerName != "api.internal" {
		t.Fatalf("ServerName = %q, want api.internal", tr.TLSClientConfig.ServerName)
	}
}

func TestTLSTransport_ServerName_Unset(t *testing.T) {
	t.Parallel()

	base := &http.Transport{DialContext: (&net.Dialer{}).DialContext}
	tr, err := NewClient().tlsTransport(base, "", "", "", "")
	if err != nil {
		t.Fatalf("tlsTransport returned error: %v", err)
	}
	if tr.TLSClientConfig.ServerName != "" {
		t.Fatalf("ServerName = %q, want empty", tr.TLSClientConfig.ServerName)
	}
}

// errServerNameProvider returns an error from ServerNameData to cover the
// configureTransport snErr branch.
type errServerNameProvider struct{}

func (p *errServerNameProvider) Name() string { return "kubernetes" }

func (p *errServerNameProvider) Description() string                             { return "err sni" }
func (p *errServerNameProvider) InjectAuth(*http.Request, json.RawMessage) error { return nil }

func (p *errServerNameProvider) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return true, nil
}

func (p *errServerNameProvider) ServerNameData(context.Context, json.RawMessage) (string, error) {
	return "", errors.New("sni boom")
}

func TestExecute_ServerNameError(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&errServerNameProvider{}}
	args := makeArgs(t, map[string]any{"url": "https://example.com/", "auth_provider": "kubernetes"})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if err == nil {
		t.Fatal("ServerNameData error must propagate from configureTransport")
	}
}

// serverNameTestProvider supplies a CA + a TLS ServerName override and allows
// the loopback dial, modeling the self-managed kubernetes connector for an
// endpoint whose cert SAN is a DNS name.
type serverNameTestProvider struct {
	caData     string
	serverName string
}

func (p *serverNameTestProvider) Name() string                                    { return "kubernetes" }
func (p *serverNameTestProvider) Description() string                             { return "test" }
func (p *serverNameTestProvider) InjectAuth(*http.Request, json.RawMessage) error { return nil }

func (p *serverNameTestProvider) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return true, nil
}

func (p *serverNameTestProvider) CACertData(context.Context, json.RawMessage) (string, error) {
	return p.caData, nil
}

func (p *serverNameTestProvider) ServerNameData(context.Context, json.RawMessage) (string, error) {
	return p.serverName, nil
}

func (p *serverNameTestProvider) AuthorizesAddr(context.Context, netip.Addr, json.RawMessage) (bool, error) {
	return true, nil // test server is loopback; allow so the handshake runs.
}

func TestExecute_ServerNameOverride(t *testing.T) {
	t.Parallel()

	caCertPEM, caKeyPEM, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Build a server cert with ONLY a DNS SAN (no IP SAN), signed by the CA, so
	// a dial to the loopback IP fails verification UNLESS ServerName overrides
	// the verified name to the DNS SAN. This makes the test load-bearing: it
	// fails if the ServerName plumbing is broken.
	serverCert, serverKey := signDNSOnlyLeaf(t, caCertPEM, caKeyPEM, "api.internal")

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "sni-ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ //nolint:exhaustruct // only the fields under test.
		{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey},
	}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&serverNameTestProvider{
		caData:     base64.StdEncoding.EncodeToString(caCertPEM),
		serverName: "api.internal",
	}}

	// srv.URL is https://127.0.0.1:PORT — an IP literal whose cert has no IP SAN.
	args := makeArgs(t, map[string]any{"url": srv.URL + "/", "auth_provider": "kubernetes"})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error (ServerName override should make the DNS-SAN cert verify): %v", err)
	}
	if !strings.Contains(result, "sni-ok") {
		t.Errorf("expected 'sni-ok', got: %q", result)
	}
}

// signDNSOnlyLeaf mints a server certificate carrying only the given DNS SAN
// (no IP SAN), signed by the PEM-encoded CA, for the ServerName-override test.
func signDNSOnlyLeaf(t *testing.T, caCertPEM, caKeyPEM []byte, dnsName string) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()

	caTLS, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("load CA key pair: %v", err)
	}
	caCert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{ //nolint:exhaustruct // only the fields the test needs.
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caTLS.PrivateKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	return leaf, leafKey
}

// orderingProvider records the sequence of AuthorizesHost, AuthorizeAction, and
// InjectAuth calls so we can assert transport.do dispatches them in the right
// order around an httptest server.
type orderingProvider struct {
	calls *[]string
}

func (p *orderingProvider) Name() string        { return "ordering" }
func (p *orderingProvider) Description() string { return "records call order" }

func (p *orderingProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	*p.calls = append(*p.calls, "host")

	return true, nil
}

func (p *orderingProvider) AuthorizeAction(_ context.Context, _ *http.Request, _ json.RawMessage) error {
	*p.calls = append(*p.calls, "action")

	return nil
}

func (p *orderingProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error {
	*p.calls = append(*p.calls, "inject")

	return nil
}

func TestExecute_DispatchesAuthorizeActionAfterHostBeforeInject(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Replace the loopback provider with an ordering provider that reuses the
	// loopback's CA cert so TLS still works.
	loopback, ok := providers[0].(*authtest.LoopbackProvider)
	if !ok {
		t.Fatalf("expected LoopbackProvider, got %T", providers[0])
	}

	var calls []string
	op := &orderingProviderWithCA{
		orderingProvider: orderingProvider{calls: &calls},
		caCert:           loopback.CACert,
	}

	args := fmt.Sprintf(
		`{"method":"GET","url":%q,"auth_provider":"ordering","headers":[],"body":""}`,
		srv.URL,
	)

	if _, _, err := NewClient().Execute(t.Context(), args, []auth.Provider{op}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	want := []string{"host", "action", "inject"}
	if !slices.Equal(calls, want) {
		t.Errorf("call order = %v, want %v", calls, want)
	}
}

// orderingProviderWithCA adds CACertData so the transport trusts the test
// server's self-signed cert.
type orderingProviderWithCA struct {
	orderingProvider

	caCert string
}

func (p *orderingProviderWithCA) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caCert, nil
}

func (p *orderingProviderWithCA) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return true, nil
}

func TestExecute_AuthorizeActionErrorAbortsBeforeInject(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	loopback, ok := providers[0].(*authtest.LoopbackProvider)
	if !ok {
		t.Fatalf("expected LoopbackProvider, got %T", providers[0])
	}

	var calls []string
	denying := &denyingActionProvider{
		caCert: loopback.CACert,
		calls:  &calls,
	}

	args := fmt.Sprintf(
		`{"method":"GET","url":%q,"auth_provider":"denying","headers":[],"body":""}`,
		srv.URL,
	)

	_, _, err := NewClient().Execute(t.Context(), args, []auth.Provider{denying})
	if err == nil {
		t.Fatalf("expected error from AuthorizeAction, got nil")
	}
	if !strings.Contains(err.Error(), "action denied") {
		t.Errorf("error should mention action denial: %v", err)
	}
	want := []string{"host", "action"}
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v (inject must not run after action denial)", calls, want)
	}
}

// denyingActionProvider passes AuthorizesHost but returns an error from
// AuthorizeAction; InjectAuth records a call only if (incorrectly) reached.
type denyingActionProvider struct {
	caCert string
	calls  *[]string
}

func (p *denyingActionProvider) Name() string        { return "denying" }
func (p *denyingActionProvider) Description() string { return "denies actions" }

func (p *denyingActionProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	*p.calls = append(*p.calls, "host")

	return true, nil
}

func (p *denyingActionProvider) AuthorizeAction(_ context.Context, _ *http.Request, _ json.RawMessage) error {
	*p.calls = append(*p.calls, "action")

	return errors.New("action denied")
}

func (p *denyingActionProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error {
	*p.calls = append(*p.calls, "inject")

	return nil
}

func (p *denyingActionProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.caCert, nil
}

func (p *denyingActionProvider) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return true, nil
}

func TestRequestArgs_ParsesGCPAuth(t *testing.T) {
	t.Parallel()

	const raw = `{"method":"GET","url":"https://compute.googleapis.com/x","auth_provider":"gcp",` +
		`"gcp_auth":{"service":"compute","location":"us-central1"}}`

	var args RequestArgs
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if args.GCPAuth == nil {
		t.Fatal("GCPAuth is nil")
	}

	if args.GCPAuth.Service != "compute" || args.GCPAuth.Location != "us-central1" {
		t.Errorf("GCPAuth = %+v, want {compute us-central1}", *args.GCPAuth)
	}
}

func TestRequestArgs_KubernetesAuthField(t *testing.T) {
	t.Parallel()

	// kubernetes_auth is optional and empty; unmarshalling a request that names
	// it must succeed and select the field.
	raw := `{"method":"GET","url":"https://h/api","headers":[],"body":"",` +
		`"timeout_seconds":5,"max_response_body_size":1024,` +
		`"auth_provider":"kubernetes","kubernetes_auth":{}}`
	var args RequestArgs
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if args.AuthProvider != "kubernetes" {
		t.Fatalf("AuthProvider = %q", args.AuthProvider)
	}
	if args.KubernetesAuth == nil {
		t.Fatal("KubernetesAuth should be non-nil when present")
	}
}

func TestExecute_RedirectNotFollowed(t *testing.T) {
	t.Parallel()

	var targetHits atomic.Int32

	// target shares httptest's testcert with srv, so if a redirect WERE
	// followed the hop would succeed and the counter would read 1 — keeping
	// the zero-assertion a live regression detector rather than a vacuous
	// TLS failure.
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	t.Cleanup(target.Close)

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	})

	args := makeArgs(t, map[string]any{"url": srv.URL + "/start", "auth_provider": "loopback"})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "302") || !strings.Contains(result, target.URL+"/elsewhere") {
		t.Errorf("expected surfaced 302 with Location %q, got: %q", target.URL+"/elsewhere", result)
	}

	if got := targetHits.Load(); got != 0 {
		t.Errorf("redirect target received %d request(s), want 0 (redirect must not be followed)", got)
	}
}

func TestExecute_SameHostRedirectNotFollowed(t *testing.T) {
	t.Parallel()

	var nextHits atomic.Int32

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			nextHits.Add(1)

			return
		}
		http.Redirect(w, r, "/next", http.StatusMovedPermanently)
	})

	args := makeArgs(t, map[string]any{"url": srv.URL + "/start", "auth_provider": "loopback"})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "301") {
		t.Errorf("expected surfaced 301, got: %q", result)
	}

	if got := nextHits.Load(); got != 0 {
		t.Errorf("same-host redirect was followed %d time(s), want 0", got)
	}
}

func TestExecuteStructured_RedirectSurfaced(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/next", http.StatusFound)
	})

	args := makeArgs(t, map[string]any{"url": srv.URL + "/start", "auth_provider": "loopback"})

	resp, err := NewClient().ExecuteStructured(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Status != http.StatusFound {
		t.Errorf("Status = %d, want %d", resp.Status, http.StatusFound)
	}

	if loc := resp.Headers["Location"]; len(loc) != 1 || loc[0] != "https://example.com/next" {
		t.Errorf("Location = %v, want [https://example.com/next]", loc)
	}
}

// pinnedHostProvider authorizes exactly one host, for exercising the
// Host-header override gate (the loopback double authorizes everything).
type pinnedHostProvider struct{ allowed string }

func (p *pinnedHostProvider) Name() string        { return "pinned" }
func (p *pinnedHostProvider) Description() string { return "authorizes a single pinned host" }
func (p *pinnedHostProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error {
	return nil
}

func (p *pinnedHostProvider) AuthorizesHost(_ context.Context, host string, _ json.RawMessage) (bool, error) {
	return host == p.allowed, nil
}

func TestExecute_HostHeaderOverrideNotAuthorized(t *testing.T) {
	t.Parallel()

	providers := []auth.Provider{&pinnedHostProvider{allowed: "api.github.com"}}
	args := makeArgs(t, map[string]any{
		"url":           "https://api.github.com/meta",
		"auth_provider": "pinned",
		"headers":       []any{map[string]any{"key": "Host", "value": "evil.example.com"}},
	})

	_, _, err := NewClient().Execute(context.Background(), args, providers)
	if !errors.Is(err, auth.ErrHostNotAuthorized) {
		t.Fatalf("expected ErrHostNotAuthorized for the Host override, got %v", err)
	}

	if err != nil && !strings.Contains(err.Error(), "evil.example.com") {
		t.Errorf("denial should name the override host, got: %v", err)
	}
}

func TestExecute_HostHeaderOverrideAuthorized(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host=" + r.Host))
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/x",
		"auth_provider": "loopback",
		"headers":       []any{map[string]any{"key": "Host", "value": "internal.example.com:8443"}},
	})

	result, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "host=internal.example.com:8443") {
		t.Errorf("expected override sent verbatim on the wire, got: %q", result)
	}
}

func TestHostnameOnly(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"example.com":      "example.com",
		"example.com:8443": "example.com",
		"[::1]":            "::1",
		"[::1]:8443":       "::1",
		"allowed.com]":     "allowed.com]",
		"[allowed.com":     "[allowed.com",
		"[[::1]]":          "[::1]",
		"a:b:c":            "a:b:c",
	}
	for in, want := range cases {
		if got := hostnameOnly(in); got != want {
			t.Errorf("hostnameOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatResponse_RedactsHeaderAndBody(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.0",
		Body: io.NopCloser(strings.NewReader(`{"access_token":"supersecretvalue"}`)),
		Header: http.Header{
			"Set-Cookie":   []string{"sid=topsecret"},
			"Content-Type": []string{"application/json"},
		},
	}

	out, err := FormatResponse(resp, 4096, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "supersecretvalue") {
		t.Errorf("body secret survived: %q", out)
	}
	if strings.Contains(out, "topsecret") {
		t.Errorf("Set-Cookie value survived: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:credential-field]") {
		t.Errorf("missing body placeholder: %q", out)
	}
}

func TestExecuteStructured_Redacts(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=topsecret")
		_, _ = w.Write([]byte(`{"access_token":"supersecretvalue"}`))
	})

	args := fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL)

	resp, err := NewClient().ExecuteStructured(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("ExecuteStructured: %v", err)
	}
	if strings.Contains(resp.Body, "supersecretvalue") {
		t.Errorf("body secret survived: %q", resp.Body)
	}
	if !strings.Contains(resp.Body, "[REDACTED:credential-field]") {
		t.Errorf("missing body placeholder: %q", resp.Body)
	}
	if got := http.Header(resp.Headers).Get("Set-Cookie"); got != "[REDACTED:header]" {
		t.Errorf("Set-Cookie = %q, want [REDACTED:header]", got)
	}
}

func TestExecuteStructured_CapsBodyAfterRedactionGrowth(t *testing.T) {
	t.Parallel()

	// Many tiny credential fields: each short value redacts to a longer placeholder,
	// so the redacted body grows past a small max_response_body_size.
	var sb strings.Builder
	sb.WriteString("{")
	for i := range 50 {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "\"password\":\"x\"")
	}
	sb.WriteString("}")
	bodyJSON := sb.String()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, bodyJSON)
	})

	const maxBytes = 256
	args := fmt.Sprintf(
		`{"method":"GET","url":%q,"max_response_body_size":%d,"auth_provider":"loopback"}`,
		srv.URL, maxBytes,
	)

	resp, err := NewClient().ExecuteStructured(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("ExecuteStructured: %v", err)
	}
	if len(resp.Body) > maxBytes {
		t.Errorf("redacted body exceeds cap: len=%d > %d", len(resp.Body), maxBytes)
	}
	if !resp.Truncated {
		t.Errorf("Truncated must be set when the redacted body is capped")
	}
}

// countingRedactor records how many times each redaction entry point fires so a
// test can prove neither response exit silently skips redaction.
type countingRedactor struct {
	redactN  int
	headerN  int
	trailerN int
}

func (c *countingRedactor) Redact(s string) string    { c.redactN++; return s }
func (c *countingRedactor) RedactHeader(http.Header)  { c.headerN++ }
func (c *countingRedactor) RedactTrailer(http.Header) { c.trailerN++ }

// TestClient_InvokesRedactorOnBothExits pins that both Execute and
// ExecuteStructured route their body and headers through the injected redactor —
// the reason WithRedactor exists.
func TestClient_InvokesRedactorOnBothExits(t *testing.T) {
	t.Parallel()

	newServer := func(t *testing.T) (*httptest.Server, []auth.Provider) {
		t.Helper()

		return newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
	}

	t.Run("execute", func(t *testing.T) {
		t.Parallel()

		srv, providers := newServer(t)
		fake := &countingRedactor{}
		args := fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL)

		c := NewClient(WithRedactor(fake))
		if _, _, err := c.Execute(context.Background(), args, providers); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if fake.redactN < 1 {
			t.Errorf("redactN = %d, want >= 1", fake.redactN)
		}
		// FormatResponse redacts the Header (RedactHeader) and the Trailer
		// (RedactTrailer — no Location exemption), so each fires exactly once.
		if fake.headerN != 1 {
			t.Errorf("headerN = %d, want 1", fake.headerN)
		}
		if fake.trailerN != 1 {
			t.Errorf("trailerN = %d, want 1", fake.trailerN)
		}
	})

	t.Run("structured", func(t *testing.T) {
		t.Parallel()

		srv, providers := newServer(t)
		fake := &countingRedactor{}
		args := fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL)

		c := NewClient(WithRedactor(fake))
		if _, err := c.ExecuteStructured(context.Background(), args, providers); err != nil {
			t.Fatalf("ExecuteStructured: %v", err)
		}
		if fake.redactN < 1 {
			t.Errorf("redactN = %d, want >= 1", fake.redactN)
		}
		// ExecuteStructured redacts only the Header, not the Trailer.
		if fake.headerN != 1 {
			t.Errorf("headerN = %d, want 1", fake.headerN)
		}
		if fake.trailerN != 0 {
			t.Errorf("trailerN = %d, want 0", fake.trailerN)
		}
	})
}

func TestFormatResponse_LocationExemptFromRedaction(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusFound, Status: "302 Found", Proto: "HTTP/1.0",
		Body: io.NopCloser(strings.NewReader("")),
		Header: http.Header{
			"Location": []string{"https://objects.githubusercontent.com/o?X-Amz-Signature=deadbeefsig&t=1"},
		},
	}

	out, err := FormatResponse(resp, 4096, redact.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "X-Amz-Signature=deadbeefsig") {
		t.Errorf("Location signature must survive for redirect-following: %q", out)
	}
}

func TestFormatResponse_RedactsTrailer(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1",
		Body:    io.NopCloser(strings.NewReader("body")),
		Header:  http.Header{},
		Trailer: http.Header{"Set-Cookie": []string{"sid=topsecret"}},
	}

	if _, err := FormatResponse(resp, 4096, redact.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := resp.Trailer.Get("Set-Cookie"); got != "[REDACTED:header]" {
		t.Errorf("trailer Set-Cookie not redacted: %q", got)
	}
}

// TestExecute_RedactsRealTrailer proves the full lifecycle: net/http only fills
// resp.Trailer values once the body is read to EOF, so FormatResponse must read
// the body first, then redact the trailer. The handler sets the trailer header
// AFTER writing the body so it is sent as a real chunked trailer.
func TestExecute_RedactsRealTrailer(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Leak")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "small body")
		w.Header().Set("X-Leak", "ghp_"+strings.Repeat("a", 36)) // set after body -> real trailer.
	})

	args := makeArgs(t, map[string]any{
		"url":           srv.URL + "/",
		"auth_provider": "loopback",
	})

	out, _, err := NewClient().Execute(context.Background(), args, providers)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(out, "ghp_"+strings.Repeat("a", 36)) {
		t.Errorf("trailer secret leaked to model output: %q", out)
	}
}

// auditProvider wraps the concrete LoopbackProvider (preserving its CACertData
// and AuthorizesAddr methods for TLS trust and dial authorization) and adds the
// ResponseAuditor capability. Embedding the concrete type rather than the
// auth.Provider interface ensures optional methods (CACertData, AuthorizesAddr)
// are promoted and the loopback TLS request can proceed.
type auditProvider struct {
	*authtest.LoopbackProvider

	audited bool
}

func (a *auditProvider) AuditResponse(_ *http.Request, _ http.Header) { a.audited = true }

func TestExecute_invokesResponseAuditor(t *testing.T) {
	t.Parallel()

	srv, providers := newTLSTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Accepted-Github-Permissions", "issues=read")
		_, _ = w.Write([]byte("ok"))
	})

	// Wrap the concrete loopback provider so it ALSO implements ResponseAuditor
	// without losing its CACertData/AuthorizesAddr (embedding the interface would
	// drop them and break TLS/dial). The cast is safe: newTLSTestServer always
	// returns a *authtest.LoopbackProvider as providers[0].
	ap := &auditProvider{LoopbackProvider: providers[0].(*authtest.LoopbackProvider)}
	args := makeArgs(t, map[string]any{
		"method": "GET", "url": srv.URL + "/x", "auth_provider": ap.Name(),
	})

	if _, _, err := NewClient().Execute(context.Background(), args, []auth.Provider{ap}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !ap.audited {
		t.Error("ResponseAuditor.AuditResponse was not invoked after a successful response")
	}
}
