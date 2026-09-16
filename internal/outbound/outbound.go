// Package outbound resolves the operator-configured HTTP proxy that connector
// traffic is routed through. It answers one question — does a request to this
// URL go through the proxy, and which one — for every outbound client in the
// binary, so the request path, the registration probes and the
// authorization-data fetches all route the same way.
//
// It is a leaf: the standard library plus golang.org/x/net/http/httpproxy,
// whose NO_PROXY matching is the behavior every other Go program has. It reads
// no environment of its own; the composition root passes the values in.
package outbound

import (
	"errors"
	"fmt"
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// ErrProxyURL is returned when the configured proxy value cannot be used as an
// endpoint. It fails startup rather than falling back to a direct connection:
// an operator who configured egress through a proxy must not silently get a
// connection that bypasses it.
var ErrProxyURL = errors.New("outbound: invalid proxy endpoint")

// LookupEnv reads one environment variable, reporting whether it was set. It
// mirrors [os.LookupEnv] so the composition root can pass the real one and
// tests a fake; this package never reads the process environment itself.
type LookupEnv func(string) (string, bool)

// Config is the operator's outbound proxy configuration.
type Config struct {
	// HTTPSProxy is the proxy endpoint every connector request is routed
	// through (the HTTPS_PROXY variable). Empty means every request is dialed
	// directly, which is the default.
	HTTPSProxy string
	// NoProxy is the standard comma-separated list of hosts, domain suffixes
	// and CIDR blocks that stay on a direct connection (the NO_PROXY variable).
	NoProxy string
}

// Routing decides, per target URL, whether a request goes through the proxy or
// straight out. The zero value routes everything directly, so a build with no
// proxy configured dials exactly as it did before this existed.
type Routing struct {
	// resolved is nil for the zero value. A single unexported pointer keeps
	// Routing embeddable in config.Config without the reflection-walking
	// config machinery (viper, defaults, validator) seeing anything to set.
	resolved *resolved
}

// resolved holds a validated proxy endpoint and the NO_PROXY-aware selector
// built from it.
type resolved struct {
	endpoint *url.URL
	proxyFor func(*url.URL) (*url.URL, error)
}

// FromEnv resolves the routing from the standard proxy variables, upper case
// first and then lower, which is the order every Go program reads them in.
// HTTP_PROXY is deliberately not read: every request this binary makes is
// https, so it would never apply.
func FromEnv(lookup LookupEnv) (Routing, error) {
	return New(Config{
		HTTPSProxy: firstSet(lookup, "HTTPS_PROXY", "https_proxy"),
		NoProxy:    firstSet(lookup, "NO_PROXY", "no_proxy"),
	})
}

// firstSet returns the value of the first of names that is set and non-empty.
func firstSet(lookup LookupEnv, names ...string) string {
	for _, name := range names {
		if v, ok := lookup(name); ok && v != "" {
			return v
		}
	}

	return ""
}

// New validates cfg and returns the routing it describes. An empty HTTPSProxy
// yields the zero Routing: every request is dialed directly and NoProxy is
// moot.
func New(cfg Config) (Routing, error) {
	if cfg.HTTPSProxy == "" {
		return Routing{resolved: nil}, nil
	}

	endpoint, err := parseEndpoint(cfg.HTTPSProxy)
	if err != nil {
		return Routing{resolved: nil}, err
	}

	proxyCfg := &httpproxy.Config{ //nolint:exhaustruct // HTTPProxy unused (every request is https); CGI stays false.
		HTTPSProxy: endpoint.String(),
		NoProxy:    cfg.NoProxy,
	}

	return Routing{resolved: &resolved{endpoint: endpoint, proxyFor: proxyCfg.ProxyFunc()}}, nil
}

// parseEndpoint parses a proxy value into an endpoint URL. It accepts what the
// proxy variables have always accepted — "http://host:port" and a bare
// "host:port", which means the same thing — and rejects everything else.
//
// Only an http:// endpoint is accepted. An https:// proxy would be dialed with
// the request's own TLS config, whose ServerName some connectors pin to their
// cluster endpoint, so the proxy's certificate would be verified under the
// wrong name; and a socks5:// endpoint would tunnel without the CONNECT the
// dial pin assumes. Both fail loudly here instead.
func parseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// A bare "host:port" parses as an opaque URL whose scheme is the host,
		// so retry it as the http:// endpoint it is conventionally taken for.
		bare, bareErr := url.Parse("http://" + raw)
		if bareErr != nil || bare.Host == "" {
			return nil, fmt.Errorf("%w: %q is not a host:port or http://host:port URL", ErrProxyURL, raw)
		}

		u = bare
	}

	if u.Scheme != "http" {
		return nil, fmt.Errorf(
			"%w: %q uses scheme %q; only an http:// proxy endpoint is supported", ErrProxyURL, raw, u.Scheme)
	}

	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: %q has a path; a proxy endpoint is a host and port only", ErrProxyURL, raw)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: %q has no host", ErrProxyURL, raw)
	}

	return u, nil
}

// ProxyFor returns the proxy endpoint a request to target must go through, or
// nil when target is reached directly: no proxy configured, or a NO_PROXY
// match. Go's own rule applies, so localhost and loopback targets are never
// proxied.
//
// It owns the target parse so callers have one failure to handle, and both
// failures deny: neither an unparseable target nor a selector that cannot
// decide falls back to a direct dial, which would leave an operator's
// controlled egress silently bypassed.
func (r Routing) ProxyFor(target string) (*url.URL, error) {
	if r.resolved == nil {
		return nil, nil //nolint:nilnil // (nil, nil) is the standard "no proxy" answer, as http.Transport.Proxy gives.
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("outbound: parse target %q: %w", target, err)
	}

	proxy, err := r.resolved.proxyFor(u)
	if err != nil {
		return nil, fmt.Errorf("outbound: select proxy for %q: %w", u.Redacted(), err)
	}

	return proxy, nil
}

// Endpoint returns the configured proxy as scheme://host, or "" when none is
// configured. Any userinfo is dropped, so the value is safe to print.
func (r Routing) Endpoint() string {
	if r.resolved == nil {
		return ""
	}

	return r.resolved.endpoint.Scheme + "://" + r.resolved.endpoint.Host
}
