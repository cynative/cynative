package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/http/httpproxy"
)

// ErrProxyConfig marks an unusable proxy setting in the environment. The run
// stops before any connector registers, because httpproxy would otherwise
// discard the parse error and connect directly.
var ErrProxyConfig = errors.New("proxy configuration")

// proxyConfigError names the variable and the fault, never the value, so the
// startup line reads "HTTPS_PROXY: <fault>". It matches ErrProxyConfig for
// [errors.Is].
type proxyConfigError struct {
	variable string
	problem  string
}

func (e *proxyConfigError) Error() string { return e.variable + ": " + e.problem }

func (e *proxyConfigError) Is(target error) bool { return target == ErrProxyConfig }

// scrubPlaceholder replaces proxy credential material in text that leaves the
// process (tool errors, connector status reasons).
const scrubPlaceholder = "[REDACTED:proxy-credential]"

// Proxy URL schemes net/http can drive. https is deliberately absent: Go reuses
// the connector's TLS config (private CA, mTLS client certificate,
// tls-server-name) for the proxy hop, which no documentation can make safe.
const (
	schemeHTTP    = "http"
	schemeSOCKS5  = "socks5"
	schemeSOCKS5H = "socks5h"

	proxyPortHTTP  = "80"
	proxyPortSOCKS = "1080"
	maxPort        = 65535
)

// Egress is the operator's outbound routing policy: the validated proxy
// settings read once at the composition root, and the selector every connector
// transport consults. It never reads the environment itself.
type Egress struct {
	httpsProxy *url.URL
	httpProxy  *url.URL
	noProxy    string
	proxyFunc  func(*url.URL) (*url.URL, error)
	// secrets is the replacement set Scrub applies: every spelling of each
	// proxy credential that Go or a proxy could echo back.
	secrets []string
}

// NoProxy returns a policy with no proxy configured: every route is direct. It
// is the default the transport client and the tests use.
func NoProxy() *Egress {
	e, _ := NewEgress(func(string) (string, bool) { return "", false }) // cannot fail without variables.

	return e
}

// NewEgress reads the standard proxy variables through lookup and validates
// them: the first non-empty of https_proxy then HTTPS_PROXY, of http_proxy then
// HTTP_PROXY, and of no_proxy then NO_PROXY, the order httpproxy.FromEnvironment
// and curl use.
func NewEgress(lookup func(string) (string, bool)) (*Egress, error) {
	httpsRaw, httpsName := firstNonEmpty(lookup, "https_proxy", "HTTPS_PROXY")
	httpRaw, httpName := firstNonEmpty(lookup, "http_proxy", "HTTP_PROXY")
	noProxy, noProxyName := firstNonEmpty(lookup, "no_proxy", "NO_PROXY")

	httpsProxy, err := parseProxyValue(httpsName, httpsRaw)
	if err != nil {
		return nil, err
	}

	httpProxy, err := parseProxyValue(httpName, httpRaw)
	if err != nil {
		return nil, err
	}

	// Notice prints the list as given, so a newline or another control
	// character would split the startup line in two.
	if strings.ContainsFunc(noProxy, unicode.IsControl) {
		return nil, &proxyConfigError{variable: noProxyName, problem: "control character"}
	}

	cfg := httpproxy.Config{
		HTTPProxy:  httpRaw,
		HTTPSProxy: httpsRaw,
		NoProxy:    noProxy,
	}

	return &Egress{
		httpsProxy: httpsProxy,
		httpProxy:  httpProxy,
		noProxy:    noProxy,
		proxyFunc:  cfg.ProxyFunc(),
		secrets:    scrubForms(httpsProxy, httpProxy),
	}, nil
}

// firstNonEmpty returns the first non-empty value among names and the name it
// came from; the last name is returned when all are empty.
func firstNonEmpty(lookup func(string) (string, bool), names ...string) (string, string) {
	for _, n := range names {
		if v, ok := lookup(n); ok && v != "" {
			return v, n
		}
	}

	return "", names[len(names)-1]
}

// parseProxyValue validates one proxy variable the way httpproxy.parseProxy
// reads it (a scheme-less value is an http proxy), then applies the rules
// httpproxy does not: a supported scheme, an ASCII unzoned host, a port in
// range, and nothing but authority and userinfo. Errors name the variable and
// the fault, never the value.
func parseProxyValue(name, raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // an unset variable is a valid absence, not an error.
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		u, err = url.Parse(schemeHTTP + "://" + raw)
	}
	if err != nil {
		return nil, &proxyConfigError{variable: name, problem: "not a valid proxy URL"}
	}

	if u.Scheme != schemeHTTP && u.Scheme != schemeSOCKS5 && u.Scheme != schemeSOCKS5H {
		return nil, &proxyConfigError{
			variable: name,
			problem:  fmt.Sprintf("unsupported scheme %q; use http://, socks5:// or socks5h://", u.Scheme),
		}
	}

	if u.Hostname() == "" || AdmitHost(u.Hostname()) != nil {
		return nil, &proxyConfigError{variable: name, problem: "not a valid proxy URL"}
	}

	if p := u.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr != nil || n < 1 || n > maxPort {
			return nil, &proxyConfigError{variable: name, problem: "port out of range"}
		}
	}

	if u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery {
		return nil, &proxyConfigError{variable: name, problem: "proxy URL must not carry a path or query"}
	}

	return u, nil
}

// proxyDefaultPort is the port net/http dials when the proxy URL has none.
func proxyDefaultPort(scheme string) string {
	if scheme == schemeHTTP {
		return proxyPortHTTP
	}

	return proxyPortSOCKS
}

// renderProxy is the only rendering of a proxy: scheme://host:port, userinfo
// dropped entirely (username included).
func renderProxy(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = proxyDefaultPort(u.Scheme)
	}

	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

// minScrubbedCredentialLen is the shortest username or password replaced as
// plain text. A shorter one would turn every error containing those few
// letters into placeholders; the Basic token, which is always long, is still
// scrubbed.
const minScrubbedCredentialLen = 4

// credentialForms lists every spelling of u's credential that an error or a
// proxy could echo. Go sends Basic authentication for any userinfo, so the
// Basic token is always listed; the username, the password and their Go-quoted
// forms (what %q produces in a malformed response error) are listed when they
// are long enough, and the raw userinfo whenever either is. Nil when u carries
// no userinfo.
func credentialForms(u *url.URL) []string {
	if u == nil || u.User == nil {
		return nil
	}

	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" && pass == "" {
		return nil
	}

	forms := []string{base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))}
	forms = append(forms, plainForms(user)...)
	forms = append(forms, plainForms(pass)...)
	if len(forms) > 1 {
		forms = append(forms, u.User.String())
	}

	return forms
}

// plainForms returns s and its Go-quoted spelling when s is long enough to be
// replaced as plain text; nil otherwise.
func plainForms(s string) []string {
	if len(s) < minScrubbedCredentialLen {
		return nil
	}
	quoted := strconv.Quote(s)

	return []string{s, quoted[1 : len(quoted)-1]}
}

// scrubForms orders the replacement set longest first, so an encoded form is
// replaced before a shorter password it happens to contain.
func scrubForms(proxies ...*url.URL) []string {
	var forms []string
	for _, u := range proxies {
		forms = append(forms, credentialForms(u)...)
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })

	return forms
}

// Notice renders the startup line body: which proxies are configured and the
// no_proxy list, credentials never included. Empty when no proxy is set.
func (e *Egress) Notice() string {
	var parts []string
	if e.httpsProxy != nil {
		parts = append(parts, "https_proxy "+renderProxy(e.httpsProxy))
	}
	if e.httpProxy != nil {
		parts = append(parts, "http_proxy "+renderProxy(e.httpProxy))
	}
	if len(parts) == 0 {
		return ""
	}
	if e.noProxy != "" {
		parts = append(parts, "no_proxy "+e.noProxy)
	}

	return strings.Join(parts, " · ")
}

// Scrub replaces every configured proxy credential form in s with a
// placeholder. Text without a credential is returned unchanged.
func (e *Egress) Scrub(s string) string {
	for _, secret := range e.secrets {
		s = strings.ReplaceAll(s, secret, scrubPlaceholder)
	}

	return s
}

// scrubbedError carries scrubbed text while keeping the original error in the
// chain, so [errors.Is] and [errors.As] keep working on the sentinels callers
// pin.
type scrubbedError struct {
	text string
	err  error
}

func (s *scrubbedError) Error() string { return s.text }

func (s *scrubbedError) Unwrap() error { return s.err }

// ScrubError returns err unchanged when it carries no proxy credential, and a
// wrapper with the scrubbed text otherwise.
func (e *Egress) ScrubError(err error) error {
	if err == nil {
		return nil
	}

	text := err.Error()

	scrubbed := e.Scrub(text)
	if scrubbed == text {
		return err
	}

	return &scrubbedError{text: scrubbed, err: err}
}

// scrubStatus wraps an inventory callback so every connector status reason
// passes through Scrub before it leaves auth. A nil callback stays nil, which
// GetProviders' consumers treat as "no listener".
func scrubStatus(e *Egress, onStatus func(ConnectorStatus)) func(ConnectorStatus) {
	if onStatus == nil {
		return nil
	}

	return func(s ConnectorStatus) {
		s.Reason = e.Scrub(s.Reason)
		onStatus(s)
	}
}
