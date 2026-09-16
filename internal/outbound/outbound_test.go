package outbound_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/outbound"
)

// fakeEnv answers from a map, reporting absent for anything not in it.
func fakeEnv(vars map[string]string) outbound.LookupEnv {
	return func(name string) (string, bool) {
		v, ok := vars[name]

		return v, ok
	}
}

func TestZeroRouting_DialsDirectly(t *testing.T) {
	t.Parallel()

	var r outbound.Routing

	proxy, err := r.ProxyFor("https://ec2.us-east-1.amazonaws.com/")
	if err != nil {
		t.Fatalf("ProxyFor: %v", err)
	}
	if proxy != nil {
		t.Errorf("ProxyFor = %v, want nil (the zero Routing proxies nothing)", proxy)
	}
	if ep := r.Endpoint(); ep != "" {
		t.Errorf("Endpoint = %q, want empty", ep)
	}
}

func TestNew_AcceptedEndpointForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"scheme and port", "http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"bare host and port", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"bare name", "proxy.corp.example", "http://proxy.corp.example"},
		{"trailing slash", "http://proxy.corp.example:3128/", "http://proxy.corp.example:3128"},
		{"with userinfo", "http://user:pass@proxy.corp.example:3128", "http://proxy.corp.example:3128"},
		{"ipv6 literal", "http://[::1]:8080", "http://[::1]:8080"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			r, err := outbound.New(outbound.Config{HTTPSProxy: c.raw, NoProxy: ""})
			if err != nil {
				t.Fatalf("New(%q): %v", c.raw, err)
			}
			if got := r.Endpoint(); got != c.want {
				t.Errorf("Endpoint = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEndpoint_DropsUserinfo pins that the displayable endpoint carries no
// credential material, because it is printed in the connector inventory.
func TestEndpoint_DropsUserinfo(t *testing.T) {
	t.Parallel()

	r, err := outbound.New(outbound.Config{HTTPSProxy: "http://user:hunter2@proxy.example:3128", NoProxy: ""})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ep := r.Endpoint()
	for _, secret := range []string{"hunter2", "user"} {
		if strings.Contains(ep, secret) {
			t.Errorf("Endpoint = %q, must not carry %q", ep, secret)
		}
	}
}

func TestNew_RejectedEndpoints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{"https endpoint", "https://proxy.corp.example:3128"},
		{"socks5 endpoint", "socks5://proxy.corp.example:1080"},
		{"with a path", "http://proxy.corp.example:3128/tunnel"},
		{"control characters", "http://proxy.corp.example:3128/\x7f"},
		{"empty host", "http://"},
		{"port only", ":8080"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			_, err := outbound.New(outbound.Config{HTTPSProxy: c.raw, NoProxy: ""})
			if !errors.Is(err, outbound.ErrProxyURL) {
				t.Errorf("New(%q) err = %v, want ErrProxyURL", c.raw, err)
			}
		})
	}
}

func TestProxyFor_SelectsAndHonorsNoProxy(t *testing.T) {
	t.Parallel()

	r, err := outbound.New(outbound.Config{
		HTTPSProxy: "http://127.0.0.1:8080",
		NoProxy:    "raw.githubusercontent.com,10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name    string
		target  string
		proxied bool
	}{
		{"cloud api", "https://ec2.us-east-1.amazonaws.com/", true},
		{"no_proxy host", "https://raw.githubusercontent.com/spec.json", false},
		{"no_proxy cidr", "https://10.1.2.3:6443/api", false},
		{"private ip not listed", "https://192.168.64.3:6443/api", true},
		{"loopback is never proxied", "https://127.0.0.1:5443/", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			proxy, perr := r.ProxyFor(c.target)
			if perr != nil {
				t.Fatalf("ProxyFor(%q): %v", c.target, perr)
			}
			if (proxy != nil) != c.proxied {
				t.Errorf("ProxyFor(%q) = %v, want proxied=%v", c.target, proxy, c.proxied)
			}
			if c.proxied && proxy.Host != "127.0.0.1:8080" {
				t.Errorf("proxy host = %q, want 127.0.0.1:8080", proxy.Host)
			}
		})
	}
}

func TestFromEnv(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"unset", map[string]string{}, ""},
		{"empty value is unset", map[string]string{"HTTPS_PROXY": ""}, ""},
		{"upper case", map[string]string{"HTTPS_PROXY": "http://a.example:1"}, "http://a.example:1"},
		{"lower case", map[string]string{"https_proxy": "http://b.example:2"}, "http://b.example:2"},
		{
			"upper wins over lower",
			map[string]string{"HTTPS_PROXY": "http://a.example:1", "https_proxy": "http://b.example:2"},
			"http://a.example:1",
		},
		{"http_proxy is not read", map[string]string{"HTTP_PROXY": "http://c.example:3"}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			r, err := outbound.FromEnv(fakeEnv(c.vars))
			if err != nil {
				t.Fatalf("FromEnv: %v", err)
			}
			if got := r.Endpoint(); got != c.want {
				t.Errorf("Endpoint = %q, want %q", got, c.want)
			}
		})
	}
}

// TestFromEnv_NoProxyVariants pins that both spellings of NO_PROXY are read and
// that the upper-case one wins, matching every other Go program.
func TestFromEnv_NoProxyVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		vars    map[string]string
		target  string
		proxied bool
	}{
		{
			"upper case",
			map[string]string{"HTTPS_PROXY": "http://p.example:1", "NO_PROXY": "skipped.example"},
			"https://skipped.example/x", false,
		},
		{
			"lower case",
			map[string]string{"HTTPS_PROXY": "http://p.example:1", "no_proxy": "skipped.example"},
			"https://skipped.example/x", false,
		},
		{
			"upper wins",
			map[string]string{
				"HTTPS_PROXY": "http://p.example:1",
				"NO_PROXY":    "other.example",
				"no_proxy":    "skipped.example",
			},
			"https://skipped.example/x", true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			r, err := outbound.FromEnv(fakeEnv(c.vars))
			if err != nil {
				t.Fatalf("FromEnv: %v", err)
			}

			proxy, perr := r.ProxyFor(c.target)
			if perr != nil {
				t.Fatalf("ProxyFor: %v", perr)
			}
			if (proxy != nil) != c.proxied {
				t.Errorf("ProxyFor(%q) = %v, want proxied=%v", c.target, proxy, c.proxied)
			}
		})
	}
}

func TestFromEnv_InvalidEndpointFails(t *testing.T) {
	t.Parallel()

	_, err := outbound.FromEnv(fakeEnv(map[string]string{"HTTPS_PROXY": "https://proxy.example:3128"}))
	if !errors.Is(err, outbound.ErrProxyURL) {
		t.Errorf("FromEnv err = %v, want ErrProxyURL", err)
	}
}

// TestProxyFor_UnparseableTargetDenies pins that a target the selector cannot
// even parse is refused rather than dialed around the proxy.
func TestProxyFor_UnparseableTargetDenies(t *testing.T) {
	t.Parallel()

	r, err := outbound.New(outbound.Config{HTTPSProxy: "http://127.0.0.1:8080", NoProxy: ""})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxy, perr := r.ProxyFor("://nonsense")
	if proxy != nil {
		t.Errorf("ProxyFor = %v, want nil", proxy)
	}
	if perr == nil {
		t.Error("ProxyFor err = nil, want a parse failure")
	}
}
