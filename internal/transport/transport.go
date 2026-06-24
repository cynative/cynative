// Package transport handles HTTP request execution, TLS configuration, and response formatting.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/redact"
)

const (
	defaultMaxResponseBytes  = 32 * 1024        // 32 KB
	absoluteMaxResponseBytes = 10 * 1024 * 1024 // 10 MB
)

const (
	minTimeoutSeconds     = 1
	maxTimeoutSeconds     = 60
	defaultTimeoutSeconds = 20
)

const (
	defaultDialTimeout   = 30 * time.Second
	defaultDialKeepAlive = 30 * time.Second
)

// Transport knobs mirroring [http.DefaultTransport]'s documented defaults. We
// build a fresh transport rather than cloning the mutable global so an embedding
// process cannot inject a Proxy or a DialTLS/DialTLSContext hook that would
// bypass the dial-time IP guard.
const (
	defaultMaxIdleConns          = 100
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
)

// providerNames joins the available provider names for error messages.
func providerNames(providers []auth.Provider) string {
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name()
	}

	return strings.Join(names, ", ")
}

// hostnameOnly strips an optional port (and one pair of IPv6 brackets) from a
// Host header value, mirroring [url.URL.Hostname] for the override authority.
// Malformed values are returned verbatim so they fail closed at the provider.
func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}

	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport[1 : len(hostport)-1]
	}

	return hostport
}

// authorizeHostOverride authorizes req.Host when it differs from req.URL.Host,
// i.e. when the model supplied an explicit Host header that overrides the URL
// authority.  [http.NewRequestWithContext] mirrors URL.Host into req.Host, so
// equality means no override and no second check is needed.
func authorizeHostOverride(
	ctx context.Context,
	req *http.Request,
	providerName string,
	providers []auth.Provider,
	rawArgs json.RawMessage,
) error {
	if req.Host == "" || req.Host == req.URL.Host {
		return nil
	}

	return auth.AuthorizeHost(ctx, providerName, hostnameOnly(req.Host), providers, rawArgs)
}

// certPoolFunc is the type of a function that returns the system certificate pool.
type certPoolFunc func() (*x509.CertPool, error)

// readAllFunc is the type of a function that reads all bytes from a reader.
type readAllFunc func(io.Reader) ([]byte, error)

// redactor is the transport's view of the redaction capability (satisfied by
// *redact.Redactor). A small local interface lets tests inject a fake.
type redactor interface {
	Redact(s string) string
	RedactHeader(h http.Header)
	RedactTrailer(h http.Header)
}

// Option configures a Client.
type Option func(*Client)

// Client holds the injectable seams for transport execution.
type Client struct {
	systemCertPool certPoolFunc
	readAll        readAllFunc
	redactor       redactor
}

// NewClient constructs a Client with production defaults.
func NewClient(opts ...Option) *Client {
	c := &Client{
		systemCertPool: x509.SystemCertPool,
		readAll:        io.ReadAll,
		redactor:       redact.New(),
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

// KeyValue represents a key-value pair for HTTP headers and query parameters.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RequestArgs defines the parameters for an HTTP request, including authentication
// and TLS overrides. The jsonschema tags are consumed by the tool schema generator.
type RequestArgs struct {
	Method string `json:"method" jsonschema:"enum=GET,enum=POST,enum=PUT,enum=DELETE,enum=PATCH,enum=HEAD,enum=OPTIONS" jsonschema_description:"The HTTP method to use."` //nolint:lll // struct tags are indivisible

	URL string `json:"url" jsonschema_description:"The full URL to request (e.g. \"https://api.example.com:8080/v1/users?q=hello\"). Must not embed userinfo (user:pass@): credentials are injected automatically by the auth_provider and model-supplied ones are rejected."` //nolint:lll // struct tags are indivisible

	Headers []KeyValue `json:"headers,omitempty" jsonschema_description:"List of HTTP headers. Omit if none. Never include credential headers (Authorization, Proxy-Authorization, X-Ms-Authorization-Auxiliary, Private-Token, Job-Token): credentials are injected automatically by the auth_provider and model-supplied ones are rejected."` //nolint:lll // struct tags are indivisible
	Body    string     `json:"body,omitempty"    jsonschema_description:"The request body as a string. Omit if none."`

	TimeoutSeconds      int `json:"timeout_seconds,omitempty"        jsonschema_description:"Request timeout in seconds (1-60, default 20)."`
	MaxResponseBodySize int `json:"max_response_body_size,omitempty" jsonschema_description:"Maximum size in bytes for the full response (status line, headers, and body combined). Default 32768."` //nolint:lll // struct tags are indivisible

	AuthProvider string `json:"auth_provider" jsonschema_description:"REQUIRED. Name of the authentication provider to use; one of 'github', 'gitlab', 'aws', 'eks', 'gcp', 'gke', 'azure', 'aks', 'kubernetes'. The request URL must be https and its host must belong to this provider. Available providers are communicated in developer messages."` //nolint:lll // struct tags are indivisible

	AWSAuth        *auth.AWSAuthArgs        `json:"aws_auth,omitempty"        jsonschema_description:"AWS-specific auth config. Required when auth_provider is 'aws'."`                                                           //nolint:lll // struct tags are indivisible
	EKSAuth        *auth.EKSAuthArgs        `json:"eks_auth,omitempty"        jsonschema_description:"EKS-specific auth config. Required when auth_provider is 'eks'."`                                                           //nolint:lll // struct tags are indivisible
	GKEAuth        *auth.GKEAuthArgs        `json:"gke_auth,omitempty"        jsonschema_description:"GKE-specific auth config. Required when auth_provider is 'gke'."`                                                           //nolint:lll // struct tags are indivisible
	GCPAuth        *auth.GCPAuthArgs        `json:"gcp_auth,omitempty"        jsonschema_description:"GCP-specific auth config. Required when auth_provider is 'gcp'."`                                                           //nolint:lll // struct tags are indivisible
	AzureAuth      *auth.AzureAuthArgs      `json:"azure_auth,omitempty"      jsonschema_description:"Azure-specific auth config. Required when auth_provider is 'azure'."`                                                       //nolint:lll // struct tags are indivisible
	AKSAuth        *auth.AKSAuthArgs        `json:"aks_auth,omitempty"        jsonschema_description:"AKS-specific auth config. Required when auth_provider is 'aks'."`                                                           //nolint:lll // struct tags are indivisible
	KubernetesAuth *auth.KubernetesAuthArgs `json:"kubernetes_auth,omitempty" jsonschema_description:"Self-managed Kubernetes auth config. Optional when auth_provider is 'kubernetes' (targets the single configured cluster)."` //nolint:lll // struct tags are indivisible
}

// Response is the structured form of an HTTP response handed to the sandbox.
// Body is the raw response body; it is not parsed, because responses are not
// always JSON. Truncated reports whether Body was cut at the max-bytes limit, so
// the sandbox can tell a clipped body apart from a malformed upstream payload.
type Response struct {
	Status     int                 `json:"status"`
	StatusText string              `json:"statusText"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Truncated  bool                `json:"truncated"`
}

// do parses arguments, clamps limits, builds and sends the HTTP request, and
// returns the live [*http.Response], the clamped max-bytes limit, and a cleanup
// func that releases the per-request transport's idle connections. cleanup is
// always non-nil; the caller must close resp.Body and then run cleanup (defer it
// before resp.Body.Close so LIFO closes the body first, idling the connection so
// cleanup actually closes it rather than no-opping on an in-use connection).
func (c *Client) do(
	ctx context.Context,
	arguments string,
	providers []auth.Provider,
) (*http.Response, int, func(), error) {
	noop := func() {}

	var args RequestArgs

	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return nil, 0, noop, fmt.Errorf("failed to parse http_request arguments: %w", err)
	}

	if args.TimeoutSeconds < minTimeoutSeconds || args.TimeoutSeconds > maxTimeoutSeconds {
		args.TimeoutSeconds = defaultTimeoutSeconds
	}

	switch {
	case args.MaxResponseBodySize < 1:
		args.MaxResponseBodySize = defaultMaxResponseBytes
	case args.MaxResponseBodySize > absoluteMaxResponseBytes:
		args.MaxResponseBodySize = absoluteMaxResponseBytes
	}

	if args.AuthProvider == "" {
		return nil, 0, noop, fmt.Errorf("auth_provider is required (available: %s)", providerNames(providers))
	}

	var reqBody io.Reader
	if args.Body != "" {
		reqBody = strings.NewReader(args.Body)
	}

	req, err := http.NewRequestWithContext(ctx, args.Method, args.URL, reqBody)
	if err != nil {
		return nil, 0, noop, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("User-Agent", "Cynative-Research/1.0")

	// Host: Go ignores req.Header["Host"], so we set req.Host directly.
	// Accept-Encoding: dropped so Go's transport handles decompression transparently.
	// Others: Add (not Set) to support duplicate keys (e.g. multiple Cookies).
	for _, h := range args.Headers {
		if strings.EqualFold(h.Key, "Host") {
			req.Host = h.Value
		} else if !strings.EqualFold(h.Key, "Accept-Encoding") {
			req.Header.Add(h.Key, h.Value)
		}
	}

	if reqBody != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if req.URL.Scheme != "https" {
		return nil, 0, noop, fmt.Errorf("http_request requires an https URL, got scheme %q", req.URL.Scheme)
	}

	// rawArgs is needed by AuthorizeHost, auth.Inject, and configureTransport,
	// so it is computed once here.
	rawArgs := json.RawMessage(arguments)

	if hostErr := auth.AuthorizeHost(ctx, args.AuthProvider, req.URL.Hostname(), providers, rawArgs); hostErr != nil {
		return nil, 0, noop, hostErr
	}

	if hostErr := authorizeHostOverride(ctx, req, args.AuthProvider, providers, rawArgs); hostErr != nil {
		return nil, 0, noop, hostErr
	}

	if actionErr := auth.AuthorizeAction(ctx, args.AuthProvider, req, providers, rawArgs); actionErr != nil {
		return nil, 0, noop, actionErr
	}

	if authErr := auth.Inject(req, args.AuthProvider, providers, rawArgs); authErr != nil {
		return nil, 0, noop, authErr
	}

	httpClient := &http.Client{
		Timeout: time.Duration(args.TimeoutSeconds) * time.Second,
		// Never follow redirects: the build-time gates (AuthorizeHost,
		// AuthorizeAction, Inject) and the approval prompt run once per request,
		// so a followed hop would bypass them all (issue #156). The 3xx is
		// surfaced to the model, which must request the Location URL explicitly
		// — re-entering the full gate chain.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cleanup, err := c.configureTransport(ctx, httpClient, args.AuthProvider, providers, rawArgs)
	if err != nil {
		return nil, 0, noop, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, cleanup, fmt.Errorf("http request failed: %w", err)
	}

	// Post-response, advisory: lets a provider compare the response against its
	// classification (e.g. GitHub's X-Accepted-GitHub-Permissions). No-op for
	// providers without the capability; never blocks, never consumes the body.
	auth.AuditResponse(args.AuthProvider, req, resp.Header, providers)

	return resp, args.MaxResponseBodySize, cleanup, nil
}

// Execute performs the request and returns the dumped, truncated response text
// and the HTTP status code (0 on a transport-level error).
func (c *Client) Execute(ctx context.Context, arguments string, providers []auth.Provider) (string, int, error) {
	resp, maxBytes, cleanup, err := c.do(ctx, arguments, providers)
	// cleanup is always non-nil; defer it unconditionally and before resp.Body.Close
	// so LIFO closes the body — idling the connection — before cleanup releases it.
	defer cleanup()
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	body, ferr := FormatResponse(resp, maxBytes, c.redactor)

	return body, status, ferr
}

// ExecuteStructured performs the request and returns a structured Response. The
// body is capped at the clamped max-bytes limit; when it overflows, Body is the
// clipped prefix and Truncated is set so the caller can distinguish a cut body
// from a genuinely malformed payload and retry with a larger limit if needed.
func (c *Client) ExecuteStructured(
	ctx context.Context,
	arguments string,
	providers []auth.Provider,
) (*Response, error) {
	resp, maxBytes, cleanup, err := c.do(ctx, arguments, providers)
	defer cleanup() // always non-nil; see Execute for the defer-ordering rationale.
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read one byte past the limit so an exact-length read can be told apart
	// from a body that was actually truncated.
	body, err := c.readAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("transport: read response body: %w", err)
	}

	truncated := false
	if len(body) > maxBytes {
		// Redaction runs after this clamp; the open-ended PEM/JWT and credential-field
		// rules catch a secret straddling the boundary. The only residual is a prefixed
		// token clamped below its minimum length, which leaves a non-functional fragment.
		body = body[:maxBytes]
		truncated = true
	}

	c.redactor.RedactHeader(resp.Header)

	redactedBody := c.redactor.Redact(string(body))
	// Redaction can grow the body (short secret values → longer placeholders),
	// so re-apply the cap to keep the sandbox within max_response_body_size.
	if len(redactedBody) > maxBytes {
		redactedBody = redactedBody[:maxBytes]
		truncated = true
	}

	return &Response{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		Headers:    resp.Header,
		Body:       redactedBody,
		Truncated:  truncated,
	}, nil
}

// dialGuard returns a net.Dialer.ControlContext hook that authorizes the
// DNS-resolved IP via auth.AuthorizeAddr before the connection is established.
// Go fires Control on every dial, including IP-literal targets, so it is the
// universal chokepoint for DNS-rebinding / TOCTOU SSRF defense.
func dialGuard(
	providerName string,
	providers []auth.Provider,
	rawArgs json.RawMessage,
) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("transport: split dial address %q: %w", address, err)
		}

		ipAddr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("transport: parse dial address %q: %w", host, err)
		}

		return auth.AuthorizeAddr(ctx, providerName, ipAddr, providers, rawArgs)
	}
}

// configureTransport always installs a per-request [*http.Transport] (a clone of
// [http.DefaultTransport] — never the shared default) whose dialer runs the
// dial-time IP guard, even when no CA / client cert is supplied. When the active
// provider supplies a CA and/or client cert, the TLS material is layered onto the
// same clone. It returns a cleanup function that must be deferred by the caller
// to release idle connections.
func (c *Client) configureTransport(
	ctx context.Context,
	client *http.Client,
	providerName string,
	providers []auth.Provider,
	rawArgs json.RawMessage,
) (func(), error) {
	noop := func() {}

	caData, caErr := auth.GetCACertData(ctx, providerName, providers, rawArgs)
	if caErr != nil {
		return noop, caErr
	}

	clientCertData, clientKeyData, certErr := auth.GetClientCertData(ctx, providerName, providers, rawArgs)
	if certErr != nil {
		return noop, certErr
	}

	serverName, snErr := auth.GetServerNameData(ctx, providerName, providers, rawArgs)
	if snErr != nil {
		return noop, snErr
	}

	// Build a fresh, known transport instead of cloning the mutable global
	// [http.DefaultTransport]: Proxy is intentionally left nil and no
	// DialTLS/DialTLSContext is inherited, so the dial-time IP guard always runs
	// for HTTPS and cannot be bypassed (or panicked) by an embedding process that
	// customized or replaced the global transport.
	base := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
		DialContext: (&net.Dialer{
			Timeout:        defaultDialTimeout,
			KeepAlive:      defaultDialKeepAlive,
			ControlContext: dialGuard(providerName, providers, rawArgs),
		}).DialContext,
	}

	tr, err := c.tlsTransport(base, caData, clientCertData, clientKeyData, serverName)
	if err != nil {
		return noop, err
	}

	client.Transport = tr

	return tr.CloseIdleConnections, nil
}

// tlsTransport returns an [*http.Transport] configured to trust both the system
// root CAs and the given custom CA certificate, and additionally injects a client
// certificate and key if provided. The data parameters must be base64-encoded PEM.
//
// Starting from the system pool ensures that endpoints using publicly-trusted
// certificates (e.g. GKE DNS endpoints) continue to work, while the appended
// custom CA allows connections to private endpoints (e.g. EKS/GKE cluster IPs
// with self-signed CAs).
func (c *Client) tlsTransport(
	base *http.Transport,
	caData, clientCertData, clientKeyData, serverName string,
) (*http.Transport, error) {
	pool, sysErr := c.systemCertPool()
	if sysErr != nil {
		pool = x509.NewCertPool()
	}

	if caData != "" {
		rawCA, err := base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CA certificate: %w", err)
		}

		if !pool.AppendCertsFromPEM(rawCA) {
			return nil, errors.New("failed to parse CA certificate")
		}
	}

	certs, err := parseClientCert(clientCertData, clientKeyData)
	if err != nil {
		return nil, err
	}

	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.RootCAs = pool
	if len(certs) > 0 {
		t.TLSClientConfig.Certificates = certs
	}
	if serverName != "" {
		t.TLSClientConfig.ServerName = serverName
	}

	return t, nil
}

// parseClientCert decodes a base64-encoded PEM client certificate/key pair into
// a [tls.Certificate] slice for mTLS. It returns nil (no client cert) when
// either input is empty, and an error when decoding or pairing fails.
func parseClientCert(clientCertData, clientKeyData string) ([]tls.Certificate, error) {
	if clientCertData == "" || clientKeyData == "" {
		return nil, nil
	}

	rawCert, err := base64.StdEncoding.DecodeString(clientCertData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client certificate: %w", err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(clientKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client key: %w", err)
	}

	cert, err := tls.X509KeyPair(rawCert, rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate key pair: %w", err)
	}

	return []tls.Certificate{cert}, nil
}

// FormatResponse redacts, dumps, and truncates an HTTP response. The body is
// read first so net/http populates resp.Trailer (trailer values are only filled
// once the body reaches EOF); then headers, trailers, and body are redacted
// before the dump, so no credential material reaches the model.
func FormatResponse(resp *http.Response, maxBytes int, r redactor) (string, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Record clipping before redaction: a secret near the start can collapse to a
	// short placeholder, shrinking the dump below maxBytes even though the original
	// body dropped data. Without this, the model would see an apparently-complete
	// response.
	bodyClipped := len(body) > maxBytes

	r.RedactHeader(resp.Header)
	// Populated by the read above; chunked trailers can carry credentials.
	// RedactTrailer (not RedactHeader) so a Location trailer gets no redirect
	// exemption — it cannot be followed, so a token in it must be redacted.
	r.RedactTrailer(resp.Trailer)

	redacted := r.Redact(string(body))
	resp.Body = io.NopCloser(strings.NewReader(redacted))
	resp.ContentLength = int64(len(redacted))

	// Body is now an in-memory reader, so DumpResponse cannot fail on a body
	// read — the only error source — leaving no reachable error branch to test.
	dump, _ := httputil.DumpResponse(resp, true)

	truncated := bodyClipped
	if len(dump) > maxBytes {
		dump = dump[:maxBytes]
		truncated = true
	}

	var suffix string
	if truncated {
		suffix = fmt.Sprintf("\n\n... [Response truncated at %d bytes]", maxBytes)
	}

	return strings.ToValidUTF8(string(dump), "�") + suffix, nil
}
