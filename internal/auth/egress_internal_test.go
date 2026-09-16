package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// mustEgress builds a policy from vars or fails the test.
func mustEgress(t *testing.T, vars map[string]string) *Egress {
	t.Helper()
	e, err := NewEgress(envFrom(vars))
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// parseURL parses raw or fails the test. A later task adds a shared mustURL
// test helper; this one is local to keep this file self-contained until then.
func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestNewEgress_NoVariablesIsDirect(t *testing.T) {
	t.Parallel()

	e, err := NewEgress(envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if e.httpsProxy != nil || e.httpProxy != nil || e.Notice() != "" {
		t.Fatalf("no variables must yield a direct policy with no notice, got %+v", e)
	}
}

func TestNewEgress_AcceptsSchemesAndDefaults(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, value, wantScheme, wantHost string
	}{
		{"http with port", "http://proxy.corp:3128", "http", "proxy.corp:3128"},
		{"scheme-less gets http", "proxy.corp:3128", "http", "proxy.corp:3128"},
		{"http default port", "http://proxy.corp", "http", "proxy.corp"},
		{"socks5", "socks5://10.0.0.9:1080", "socks5", "10.0.0.9:1080"},
		{"socks5h", "SOCKS5H://proxy.corp", "socks5h", "proxy.corp"},
		{"ipv6 literal", "http://[::1]:3128", "http", "[::1]:3128"},
		{"userinfo kept", "http://user:s3cret@proxy.corp:3128", "http", "proxy.corp:3128"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEgress(envFrom(map[string]string{"HTTPS_PROXY": tc.value}))
			if err != nil {
				t.Fatalf("NewEgress(%q): %v", tc.value, err)
			}
			if e.httpsProxy.Scheme != tc.wantScheme || e.httpsProxy.Host != tc.wantHost {
				t.Fatalf("parsed %s://%s, want %s://%s",
					e.httpsProxy.Scheme, e.httpsProxy.Host, tc.wantScheme, tc.wantHost)
			}
		})
	}
}

func TestNewEgress_RejectsUnusableValues(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, variable, value, wantText string }{
		{"https scheme", "HTTPS_PROXY", "https://proxy.corp:3128", `unsupported scheme "https"`},
		{"ftp scheme", "HTTPS_PROXY", "ftp://proxy.corp", `unsupported scheme "ftp"`},
		{"path", "HTTPS_PROXY", "http://proxy.corp:3128/pac", "must not carry a path or query"},
		{"query", "HTTPS_PROXY", "http://proxy.corp:3128/?x=1", "must not carry a path or query"},
		{"fragment", "HTTPS_PROXY", "http://proxy.corp:3128/#f", "must not carry a path or query"},
		{"port too large", "HTTPS_PROXY", "http://proxy.corp:65536", "port out of range"},
		{"port zero", "HTTPS_PROXY", "http://proxy.corp:0", "port out of range"},
		{"non-ascii host", "HTTPS_PROXY", "http://prox\u00fd.corp:3128", "not a valid proxy URL"},
		{"zoned host", "HTTPS_PROXY", "http://[fe80::1%25eth0]:3128", "not a valid proxy URL"},
		{"empty host", "HTTPS_PROXY", "//proxy.corp:3128", "not a valid proxy URL"},
		{"control character", "HTTPS_PROXY", "http://proxy.corp:31\x0128", "not a valid proxy URL"},
		{"http proxy checked too", "HTTP_PROXY", "https://proxy.corp", `unsupported scheme "https"`},
		{"lower-case spelling checked", "https_proxy", "https://proxy.corp", `unsupported scheme "https"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewEgress(envFrom(map[string]string{tc.variable: tc.value}))
			if !errors.Is(err, ErrProxyConfig) {
				t.Fatalf("err = %v, want ErrProxyConfig", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err = %q, want it to contain %q", err, tc.wantText)
			}
			if strings.Contains(err.Error(), tc.value) {
				t.Fatalf("err = %q must not echo the raw value", err)
			}
			if !strings.HasPrefix(err.Error(), strings.ToUpper(tc.variable)) &&
				!strings.HasPrefix(err.Error(), tc.variable) {
				t.Fatalf("err = %q must name the variable", err)
			}
		})
	}
}

func TestNewEgress_LowerCaseSpellingWinsWhenBothSet(t *testing.T) {
	t.Parallel()

	e, err := NewEgress(envFrom(map[string]string{
		"https_proxy": "http://lower:1",
		"HTTPS_PROXY": "http://upper:2",
		"no_proxy":    "a.example",
		"NO_PROXY":    "b.example",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.httpsProxy.Host != "lower:1" || e.noProxy != "a.example" {
		t.Fatalf("got proxy %q no_proxy %q, want the lower-case spellings", e.httpsProxy.Host, e.noProxy)
	}
}

func TestNewEgress_EmptyLowerCaseFallsBackToUpper(t *testing.T) {
	t.Parallel()

	e, err := NewEgress(envFrom(map[string]string{"https_proxy": "", "HTTPS_PROXY": "http://upper:2"}))
	if err != nil {
		t.Fatal(err)
	}
	if e.httpsProxy.Host != "upper:2" {
		t.Fatalf("got %q, want the upper-case value when the lower-case one is empty", e.httpsProxy.Host)
	}
}

func TestEgress_NoticeRendersWithoutCredentials(t *testing.T) {
	t.Parallel()

	e, err := NewEgress(envFrom(map[string]string{
		"HTTPS_PROXY": "http://alice:s3cret@proxy.corp:3128",
		"HTTP_PROXY":  "socks5://proxy.corp",
		"NO_PROXY":    "10.0.0.0/8,169.254.169.254",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := "https_proxy http://proxy.corp:3128 · http_proxy socks5://proxy.corp:1080 · no_proxy 10.0.0.0/8,169.254.169.254"
	if got := e.Notice(); got != want {
		t.Fatalf("Notice() = %q, want %q", got, want)
	}
	for _, leak := range []string{"alice", "s3cret"} {
		if strings.Contains(e.Notice(), leak) {
			t.Fatalf("Notice() leaks %q", leak)
		}
	}
}

func TestEgress_ScrubReplacesEveryCredentialForm(t *testing.T) {
	t.Parallel()

	// The quote must be percent-encoded in the URL (url.Parse rejects a raw one);
	// the password decodes to `a"b c`, the raw userinfo re-encodes to
	// `alice:a%22b%20c`, the Basic token is base64 of `alice:a"b c`, and %q
	// renders the password as `a\"b c`.
	e, err := NewEgress(envFrom(map[string]string{"HTTPS_PROXY": "http://alice:a%22b%20c@proxy.corp:3128"}))
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{
		`407 Proxy Authentication Required alice:a"b c`,
		`raw alice:a%22b%20c in a line`,
		`malformed HTTP response "a\"b c"`,
		`Basic YWxpY2U6YSJiIGM=`,
	}
	for _, in := range inputs {
		out := e.Scrub(in)
		for _, leak := range []string{`a"b c`, `a\"b c`, `a%22b%20c`, "YWxpY2U6YSJiIGM="} {
			if strings.Contains(out, leak) {
				t.Fatalf("Scrub(%q) = %q still contains %q", in, out, leak)
			}
		}
		if !strings.Contains(out, "[REDACTED:proxy-credential]") {
			t.Fatalf("Scrub(%q) = %q has no placeholder", in, out)
		}
	}
	if got := e.Scrub("nothing to see"); got != "nothing to see" {
		t.Fatalf("Scrub must leave clean text alone, got %q", got)
	}
}

func TestEgress_ScrubReplacesLongerFormsFirst(t *testing.T) {
	t.Parallel()

	// The password "YWxp" is a prefix of its own Basic token "YWxpY2U6WVd4cA==";
	// replacing the password first would leave the tail of the token behind.
	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://alice:YWxp@proxy.corp:3128"})
	out := e.Scrub("Basic YWxpY2U6WVd4cA== and YWxp")
	if strings.Contains(out, "Y2U6") || strings.Contains(out, "YWxp") {
		t.Fatalf("an encoded form survived: %q", out)
	}
}

func TestEgress_ScrubCoversBothProxiesAndUsernameOnlyCredentials(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{
		"HTTPS_PROXY": "http://alice:s3cret@proxy.corp:3128",
		"HTTP_PROXY":  "http://bob@other.corp:3128", // Go still sends Basic bob: for this one.
	})
	out := e.Scrub("s3cret YWxpY2U6czNjcmV0 Ym9iOg==")
	for _, leak := range []string{"s3cret", "YWxpY2U6czNjcmV0", "Ym9iOg=="} {
		if strings.Contains(out, leak) {
			t.Fatalf("Scrub left %q in %q", leak, out)
		}
	}
}

func TestCredentialForms_EdgeCases(t *testing.T) {
	t.Parallel()

	if forms := credentialForms(nil); forms != nil {
		t.Fatalf("nil URL: %v", forms)
	}
	if forms := credentialForms(parseURL(t, "http://proxy.corp:1")); forms != nil {
		t.Fatalf("no userinfo: %v", forms)
	}
	if forms := credentialForms(parseURL(t, "http://:@proxy.corp:1")); forms != nil {
		t.Fatalf("empty userinfo: %v", forms)
	}
	// A short password is not replaced as plain text (it would mangle every
	// error containing those letters); its Basic token still is.
	short := credentialForms(parseURL(t, "http://u:abc@proxy.corp:1"))
	if len(short) != 1 || short[0] != "dTphYmM=" {
		t.Fatalf("short password forms = %v, want only the Basic token", short)
	}
}

func TestEgress_ScrubErrorKeepsChainAndReturnsSameErrorWhenClean(t *testing.T) {
	t.Parallel()

	e, err := NewEgress(envFrom(map[string]string{"HTTPS_PROXY": "http://alice:s3cret@proxy.corp:3128"}))
	if err != nil {
		t.Fatal(err)
	}
	if e.ScrubError(nil) != nil {
		t.Fatal("ScrubError(nil) must be nil")
	}
	clean := errors.New("connection refused")
	if got := e.ScrubError(clean); !unchanged(got, clean) {
		t.Fatalf("a clean error must be returned unchanged, got %v", got)
	}
	leaky := fmt.Errorf("proxy said: %w", errors.New("s3cret exposed"))
	got := e.ScrubError(leaky)
	if strings.Contains(got.Error(), "s3cret") {
		t.Fatalf("ScrubError leaked: %v", got)
	}
	if !errors.Is(got, leaky) {
		t.Fatal("ScrubError must keep the original error in the chain")
	}
	// NoProxy scrubs nothing and never wraps.
	if npGot := NoProxy().ScrubError(leaky); !unchanged(npGot, leaky) {
		t.Fatal("NoProxy().ScrubError must return the error unchanged")
	}
}

// unchanged reports whether got is want, passed through with no wrapper.
// ScrubError promises the identical value back when there is nothing to
// scrub, and [errors.Is] starts by comparing got and want directly (the same
// identity a bare == would check), so a true result here proves identity
// unless got merely wraps want. The [errors.As] check rules out exactly that
// wrapper case: scrubbedError.Unwrap hands back want, which would otherwise
// satisfy [errors.Is] on its own and let a wrapped result pass as unchanged.
func unchanged(got, want error) bool {
	if !errors.Is(got, want) {
		return false
	}
	var wrapped *scrubbedError

	return !errors.As(got, &wrapped)
}

func TestRenderProxy_DefaultPortsAndNoUserinfo(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"http://u:p@h":      "http://h:80",
		"socks5://h":        "socks5://h:1080",
		"socks5h://[::1]:9": "socks5h://[::1]:9",
		"http://h:3128":     "http://h:3128",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := renderProxy(u); got != want {
			t.Fatalf("renderProxy(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestScrubStatus_ScrubsReasonAndPassesThrough(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://alice:s3cret@proxy.corp:3128"})
	var got ConnectorStatus
	wrapped := scrubStatus(e, func(s ConnectorStatus) { got = s })
	wrapped(ConnectorStatus{Name: "gitlab", Reason: "407 s3cret", Posture: "read"})
	if got.Name != "gitlab" || got.Posture != "read" {
		t.Fatalf("scrubStatus must pass the status through, got %+v", got)
	}
	if strings.Contains(got.Reason, "s3cret") {
		t.Fatalf("Reason still carries the credential: %q", got.Reason)
	}
	// A nil onStatus stays nil so GetProviders' nil-safe contract holds.
	if scrubStatus(e, nil) != nil {
		t.Fatal("scrubStatus(e, nil) must be nil")
	}
}

func TestProviderConstructors_DefaultToDirectEgress(t *testing.T) {
	t.Parallel()

	target := mustURL("https://api.example.test/")
	for name, e := range map[string]*Egress{
		"eks":        newEKSProvider(aws.Config{}).egress,
		"gke":        newGKEProvider(nil).egress,
		"aks":        newAKSProvider(nil, cloud.Configuration{}).egress,
		"kubernetes": newKubernetesProvider(resolvedCluster{}).egress,
	} {
		if e == nil || e.Route(target).Proxied() {
			t.Fatalf("%s: constructor must default to a direct policy, got %v", name, e)
		}
	}
}
