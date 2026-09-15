package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/cynative/cynative/internal/auth/authreq"
	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

func TestRejectUnsafe(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()

	clean := func() (*clientcmdapi.Cluster, *clientcmdapi.AuthInfo) {
		return &clientcmdapi.Cluster{Server: "https://10.0.0.1:6443"},
			&clientcmdapi.AuthInfo{Token: "t"}
	}

	t.Run("clean context passes", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		if _, err := rejectUnsafe(cl, ai); err != nil {
			t.Fatalf("clean context rejected: %v", err)
		}
	})

	t.Run("exec rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Exec = &clientcmdapi.ExecConfig{Command: "/bin/sh"}
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("exec plugin must be rejected")
		}
	})

	t.Run("auth-provider rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "gcp"}
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("auth-provider must be rejected")
		}
	})

	t.Run("insecure-skip-tls-verify rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.InsecureSkipTLSVerify = true
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("insecure-skip-tls-verify must be rejected")
		}
	})

	t.Run("proxy-url rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.ProxyURL = "http://proxy:8080"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("proxy-url must be rejected")
		}
	})

	t.Run("non-https server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "http://10.0.0.1:6443"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("non-https server must be rejected")
		}
	})

	t.Run("unparseable server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "://bad"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("unparseable server must be rejected")
		}
	})

	t.Run("empty-host https server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "https:///api"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("https server with empty host must be rejected")
		}
	})

	t.Run("impersonation rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Impersonate = "system:admin"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonation must be rejected")
		}
	})

	t.Run("basic-auth username rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Username = "admin"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("basic-auth username must be rejected")
		}
	})

	t.Run("basic-auth password rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Password = "hunter2"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("basic-auth password must be rejected")
		}
	})

	t.Run("impersonate-uid rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.ImpersonateUID = "1234"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonate-uid must be rejected")
		}
	})

	t.Run("impersonate-user-extra rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.ImpersonateUserExtra = map[string][]string{"scopes": {"x"}}
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonate-user-extra must be rejected")
		}
	})

	t.Run("server URL userinfo rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "https://user:pass@10.0.0.1:6443"
		if _, err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("server URL with embedded userinfo must be rejected")
		}
	})
}

func TestClassifyCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ai      clientcmdapi.AuthInfo
		want    credMode
		wantErr bool
	}{
		{"bearer literal", clientcmdapi.AuthInfo{Token: "t"}, credBearer, false},
		{"bearer tokenFile", clientcmdapi.AuthInfo{TokenFile: "/run/token"}, credBearer, false},
		{
			"mtls inline",
			clientcmdapi.AuthInfo{ClientCertificateData: []byte("c"), ClientKeyData: []byte("k")},
			credMTLS, false,
		},
		{
			"mtls file paths",
			clientcmdapi.AuthInfo{ClientCertificate: "/c.pem", ClientKey: "/k.pem"},
			credMTLS, false,
		},
		{
			"cert+key+token prefers mtls",
			clientcmdapi.AuthInfo{ClientCertificateData: []byte("c"), ClientKeyData: []byte("k"), Token: "t"},
			credMTLS, false,
		},
		{
			"lone cert with token falls back to bearer",
			clientcmdapi.AuthInfo{ClientCertificateData: []byte("c"), Token: "t"},
			credBearer, false,
		},
		{
			"lone cert no token errors",
			clientcmdapi.AuthInfo{ClientCertificateData: []byte("c")},
			credBearer, true,
		},
		{"no credential errors", clientcmdapi.AuthInfo{}, credBearer, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := classifyCredential(&tc.ai)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("mode = %v, want %v", got, tc.want)
			}
		})
	}
}

func newKubeconfig() *clientcmdapi.Config {
	return &clientcmdapi.Config{
		CurrentContext: "ctx",
		Contexts: map[string]*clientcmdapi.Context{
			"ctx": {Cluster: "c", AuthInfo: "u"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"c": {Server: "https://10.0.0.1:6443", CertificateAuthorityData: []byte("ca")},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"u": {Token: "t"},
		},
	}
}

func TestExtractSelected_SkipSentinels(t *testing.T) {
	t.Parallel()

	t.Run("no current-context returns ErrNoCurrentContext", func(t *testing.T) {
		t.Parallel()
		cfg := newKubeconfig()
		cfg.CurrentContext = ""
		_, err := extractSelected(cfg)
		if !errors.Is(err, ErrNoCurrentContext) {
			t.Fatalf("err = %v, want errors.Is ErrNoCurrentContext", err)
		}
	})

	t.Run("exec plugin returns ErrUnsupportedFeature", func(t *testing.T) {
		t.Parallel()
		cfg := newKubeconfig()
		cfg.AuthInfos["u"].Exec = &clientcmdapi.ExecConfig{Command: "aws"} //nolint:exhaustruct // minimal exec config.
		_, err := extractSelected(cfg)
		if !errors.Is(err, ErrUnsupportedFeature) {
			t.Fatalf("err = %v, want errors.Is ErrUnsupportedFeature", err)
		}
	})

	t.Run("unknown context is structural (not a sentinel)", func(t *testing.T) {
		t.Parallel()
		cfg := newKubeconfig()
		cfg.CurrentContext = "nope"
		_, err := extractSelected(cfg)
		if errors.Is(err, ErrNoCurrentContext) || errors.Is(err, ErrUnsupportedFeature) {
			t.Fatalf("structural error %v must not match a skip sentinel", err)
		}
	})
}

func TestExtractSelected(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()

	t.Run("selects current-context", func(t *testing.T) {
		t.Parallel()

		sel, err := extractSelected(newKubeconfig())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sel.host != "10.0.0.1" {
			t.Fatalf("host = %q, want 10.0.0.1", sel.host)
		}
		if sel.authority != "10.0.0.1:6443" || sel.port != "6443" {
			t.Fatalf("authority = %q port = %q, want 10.0.0.1:6443 / 6443", sel.authority, sel.port)
		}
		if sel.mode != credBearer || sel.token != "t" {
			t.Fatalf("got mode=%v token=%q", sel.mode, sel.token)
		}
		if string(sel.caData) != "ca" {
			t.Fatalf("caData = %q, want \"ca\"", sel.caData)
		}
	})

	t.Run("captures tls-server-name", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.Clusters["c"].TLSServerName = "api.internal"
		sel, err := extractSelected(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sel.serverName != "api.internal" {
			t.Fatalf("serverName = %q, want api.internal", sel.serverName)
		}
	})

	t.Run("no context set errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.CurrentContext = ""
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("empty current-context must error")
		}
	})

	t.Run("unknown context errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.CurrentContext = "nope"
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("unknown context must error")
		}
	})

	t.Run("missing cluster ref errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.Contexts["ctx"].Cluster = "ghost"
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("missing cluster ref must error")
		}
	})

	t.Run("missing user ref errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.Contexts["ctx"].AuthInfo = "ghost"
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("missing user ref must error")
		}
	})

	t.Run("unsafe context errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.AuthInfos["u"].Exec = &clientcmdapi.ExecConfig{Command: "/bin/sh"}
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("exec context must error")
		}
	})

	t.Run("no-credential context errors", func(t *testing.T) {
		t.Parallel()

		cfg := newKubeconfig()
		cfg.AuthInfos["u"] = &clientcmdapi.AuthInfo{}
		if _, err := extractSelected(cfg); err == nil {
			t.Fatal("credential-less context must error")
		}
	})
}

// TestRejectUnsafe_diagnosticsCarryNoCredential pins the rule that a connector's
// skip reason is host-authored output no redactor runs over: a kubeconfig server
// with userinfo must not put that userinfo in the error the operator sees. Each
// row lands in a different branch, named by wantMsg, so a branch that starts
// interpolating the raw URL again cannot hide behind another row.
func TestRejectUnsafe_diagnosticsCarryNoCredential(t *testing.T) {
	t.Parallel()

	const secret = "hunter2"

	tests := []struct{ name, server, wantMsg string }{
		{"userinfo", "https://admin:" + secret + "@api.example:6443", "must not embed credentials"},
		{"non-https scheme", "http://admin:" + secret + "@api.example:6443", "must be https"},
		{"no host", "https://admin:" + secret + "@:6443", "has no host"},
		{"unparseable", "https://admin:" + secret + "@api.example:not a url", "does not parse"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := rejectUnsafe(&clientcmdapi.Cluster{Server: tc.server}, &clientcmdapi.AuthInfo{Token: "t"})
			if err == nil {
				t.Fatalf("rejectUnsafe(%q) = nil, want a rejection", tc.server)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("rejectUnsafe(%q) = %q, want the %q branch", tc.server, err, tc.wantMsg)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("diagnostic %q carries the userinfo password", err)
			}
		})
	}
}

// TestRejectUnsafe_hostAdmission pins the fail-closed rule for a server host
// that has more than one spelling, and the ones that matter here disagree. Go
// maps U+0130 to a plain "i" when lower-casing, while the HTTP client's IDNA
// conversion maps it to "xn--i-9bb", so a lower-cased authority would name a
// different DNS host than the one the operator wrote and the credential would
// be sent there. A zone identifier disagrees for a different reason: the
// authority the gate admits is lower-cased and the interface the kernel picks
// is matched exactly.
func TestRejectUnsafe_hostAdmission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, server string
		want         error
	}{
		{"unicode host", "https://\u0130.example:6443", ErrNonASCIIHost},
		{"percent-encoded unicode host", "https://%C4%B0.example:6443", ErrNonASCIIHost},
		{"eszett", "https://stra\u00dfe.example:6443", ErrNonASCIIHost},
		{"zoned link-local server", "https://[fe80::1%25eth0]:6443", ErrZonedHost},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := rejectUnsafe(&clientcmdapi.Cluster{Server: tc.server}, &clientcmdapi.AuthInfo{Token: "t"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("rejectUnsafe(%q) = %v, want %v", tc.server, err, tc.want)
			}
			// The connector wraps the shared rule so the operator is told which
			// setting to fix; a bare delegation would lose that.
			if !strings.HasPrefix(err.Error(), "kubernetes: server URL: ") {
				t.Fatalf("rejectUnsafe(%q) = %v, want the kubernetes: server URL: prefix", tc.server, err)
			}
		})
	}

	accepted := []struct{ name, server, wantAuthority string }{
		{"an already-punycoded host", "https://xn--i-9bb.example:6443", "xn--i-9bb.example:6443"},
		{"an ipv6 literal with no zone", "https://[2001:db8::1]:6443", "[2001:db8::1]:6443"},
	}
	for _, tc := range accepted {
		t.Run(tc.name+" is accepted", func(t *testing.T) {
			t.Parallel()

			u, err := rejectUnsafe(&clientcmdapi.Cluster{Server: tc.server}, &clientcmdapi.AuthInfo{Token: "t"})
			if err != nil {
				t.Fatalf("rejectUnsafe(%q) = %v, want accepted", tc.server, err)
			}
			if got := clusterTargetOf(u).authority; got != tc.wantAuthority {
				t.Fatalf("authority = %q, want %q unchanged", got, tc.wantAuthority)
			}
		})
	}
}

func TestRejectUnsafe_serverPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, server string
		wantErr      bool
	}{
		{"canonical port", "https://10.0.0.1:6443", false},
		{"ascii host", "https://k8s.example:6443", false},
		{"no port", "https://10.0.0.1", false},
		{"empty port", "https://10.0.0.1:", false},
		{"leading zero", "https://10.0.0.1:06443", true},
		{"zero", "https://10.0.0.1:0", true},
		{"above the range", "https://10.0.0.1:65536", true},
		{"wider than an int", "https://10.0.0.1:99999999999999999999", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := rejectUnsafe(&clientcmdapi.Cluster{Server: tc.server}, &clientcmdapi.AuthInfo{Token: "t"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("rejectUnsafe(%q) = %v, wantErr %v", tc.server, err, tc.wantErr)
			}
		})
	}
}

func TestClusterTargetOf(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, server, host, authority, port string }{
		{"ip with port", "https://10.0.0.1:6443", "10.0.0.1", "10.0.0.1:6443", "6443"},
		{"fqdn with port", "https://api.example.com:6443", "api.example.com", "api.example.com:6443", "6443"},
		{"no explicit port", "https://api.example.com", "api.example.com", "api.example.com", ""},
		{"ipv6 with port", "https://[2001:db8::1]:6443", "2001:db8::1", "[2001:db8::1]:6443", "6443"},
		{"ipv6 without port", "https://[2001:db8::1]", "2001:db8::1", "[2001:db8::1]", ""},
		{"empty port drops the colon", "https://api.example.com:", "api.example.com", "api.example.com", ""},
		{
			"upper-cased host is normalized",
			"https://API.Example.COM:6443",
			"api.example.com",
			"api.example.com:6443",
			"6443",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, err := rejectUnsafe(&clientcmdapi.Cluster{Server: tc.server}, &clientcmdapi.AuthInfo{Token: "t"})
			if err != nil {
				t.Fatalf("rejectUnsafe(%q) errored: %v", tc.server, err)
			}

			if got := clusterTargetOf(u); got.host != tc.host ||
				got.authority != tc.authority || got.port != tc.port {
				t.Fatalf("clusterTargetOf(%q) = %+v, want host=%q authority=%q port=%q",
					tc.server, got, tc.host, tc.authority, tc.port)
			}
		})
	}
}

func TestResolveSelected(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()

	t.Run("bearer with inline CA", func(t *testing.T) {
		t.Parallel()

		sel := selected{
			host:      "h",
			authority: "h:6443",
			port:      "6443",
			caData:    []byte("ca"),
			mode:      credBearer,
			token:     "t",
		}
		rc, err := resolveSelected(sel, func(string) ([]byte, error) {
			t.Fatal("readFile must not be called for inline data")
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.caData != base64.StdEncoding.EncodeToString([]byte("ca")) {
			t.Fatalf("caData = %q", rc.caData)
		}
		if rc.authority != "h:6443" || rc.port != "6443" {
			t.Fatalf("authority = %q port = %q, want h:6443 / 6443", rc.authority, rc.port)
		}
		if rc.mode != credBearer || rc.token != "t" {
			t.Fatalf("got mode=%v token=%q", rc.mode, rc.token)
		}
	})

	t.Run("reads CA from file path", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", caFile: "/ca.pem", mode: credBearer, tokenFile: "/run/token"}
		rc, err := resolveSelected(sel, func(p string) ([]byte, error) {
			if p != "/ca.pem" {
				t.Fatalf("unexpected path %q", p)
			}
			return []byte("file-ca"), nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.caData != base64.StdEncoding.EncodeToString([]byte("file-ca")) {
			t.Fatalf("caData = %q", rc.caData)
		}
		if rc.tokenFile != "/run/token" {
			t.Fatalf("tokenFile = %q", rc.tokenFile)
		}
	})

	t.Run("mtls reads cert and key", func(t *testing.T) {
		t.Parallel()

		sel := selected{
			host: "h", serverName: "api.internal", mode: credMTLS,
			certData: []byte("c"), keyData: []byte("k"),
		}
		rc, err := resolveSelected(sel, func(string) ([]byte, error) { return nil, nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.clientCert != base64.StdEncoding.EncodeToString([]byte("c")) {
			t.Fatalf("clientCert = %q", rc.clientCert)
		}
		if rc.clientKey != base64.StdEncoding.EncodeToString([]byte("k")) {
			t.Fatalf("clientKey = %q", rc.clientKey)
		}
		if rc.serverName != "api.internal" {
			t.Fatalf("serverName = %q, want api.internal", rc.serverName)
		}
	})

	t.Run("mtls drops any token", func(t *testing.T) {
		t.Parallel()

		sel := selected{
			host: "h", mode: credMTLS,
			certData: []byte("c"), keyData: []byte("k"),
			token: "leak", tokenFile: "/leak",
		}
		rc, err := resolveSelected(sel, func(string) ([]byte, error) { return nil, nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.token != "" || rc.tokenFile != "" {
			t.Fatalf("mTLS must carry no token: token=%q tokenFile=%q", rc.token, rc.tokenFile)
		}
	})

	t.Run("no CA yields empty caData", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", mode: credBearer, token: "t"}
		rc, err := resolveSelected(sel, func(string) ([]byte, error) { return nil, nil })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.caData != "" {
			t.Fatalf("caData = %q, want empty", rc.caData)
		}
	})

	t.Run("CA read error", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", caFile: "/ca.pem", mode: credBearer, token: "t"}
		_, err := resolveSelected(sel, func(string) ([]byte, error) { return nil, errors.New("boom") })
		if err == nil {
			t.Fatal("CA read error must propagate")
		}
	})

	t.Run("cert read error", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", mode: credMTLS, certFile: "/c.pem", keyData: []byte("k")}
		_, err := resolveSelected(sel, func(p string) ([]byte, error) {
			if p == "/c.pem" {
				return nil, errors.New("boom")
			}
			return []byte("x"), nil
		})
		if err == nil {
			t.Fatal("cert read error must propagate")
		}
	})

	t.Run("key read error", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", mode: credMTLS, certData: []byte("c"), keyFile: "/k.pem"}
		_, err := resolveSelected(sel, func(p string) ([]byte, error) {
			if p == "/k.pem" {
				return nil, errors.New("boom")
			}
			return []byte("x"), nil
		})
		if err == nil {
			t.Fatal("key read error must propagate")
		}
	})
}

func TestKubernetesProvider_NameDescription(t *testing.T) {
	t.Parallel()

	p := newKubernetesProvider(resolvedCluster{host: "h", mode: credBearer, token: "t"})
	if p.Name() != "kubernetes" {
		t.Fatalf("Name = %q, want kubernetes", p.Name())
	}
	if p.Description() == "" {
		t.Fatal("Description must be non-empty")
	}
}

func TestKubernetesProvider_InjectAuth(t *testing.T) {
	t.Parallel()

	newReq := func() *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "https://h/api", nil)
		return req
	}

	t.Run("bearer literal sets header", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, token: "abc"})
		req := newReq()
		if err := p.InjectAuth(req, noArgs()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer abc" {
			t.Fatalf("Authorization = %q, want Bearer abc", got)
		}
	})

	t.Run("tokenFile is re-read and trimmed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, tokenFile: "/run/token"})
		p.readFile = func(path string) ([]byte, error) {
			if path != "/run/token" {
				t.Fatalf("unexpected path %q", path)
			}
			return []byte("file-token\n"), nil
		}
		req := newReq()
		if err := p.InjectAuth(req, noArgs()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer file-token" {
			t.Fatalf("Authorization = %q, want Bearer file-token", got)
		}
	})

	t.Run("tokenFile read error propagates", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, tokenFile: "/run/token"})
		p.readFile = func(string) ([]byte, error) { return nil, errors.New("gone") }
		if err := p.InjectAuth(newReq(), noArgs()); err == nil {
			t.Fatal("tokenFile read error must propagate")
		}
	})

	t.Run("mtls sets no header", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credMTLS, clientCert: "c", clientKey: "k"})
		req := newReq()
		if err := p.InjectAuth(req, noArgs()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty for mTLS", got)
		}
	})
}

func TestKubernetesProvider_TLSMaterialAndHost(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rc := resolvedCluster{
		host:       "10.0.0.1",
		serverName: "api.internal",
		caData:     "Y2E=",
		mode:       credMTLS,
		clientCert: "Y2VydA==",
		clientKey:  "a2V5",
	}
	p := newKubernetesProvider(rc)

	t.Run("CACertData", func(t *testing.T) {
		t.Parallel()

		got, err := p.CACertData(ctx, noArgs())
		if err != nil || got != "Y2E=" {
			t.Fatalf("CACertData = %q, %v", got, err)
		}
	})

	t.Run("ClientCertData", func(t *testing.T) {
		t.Parallel()

		cert, key, err := p.ClientCertData(ctx, noArgs())
		if err != nil || cert != "Y2VydA==" || key != "a2V5" {
			t.Fatalf("ClientCertData = %q, %q, %v", cert, key, err)
		}
	})

	t.Run("ServerNameData", func(t *testing.T) {
		t.Parallel()

		got, err := p.ServerNameData(ctx, noArgs())
		if err != nil || got != "api.internal" {
			t.Fatalf("ServerNameData = %q, %v", got, err)
		}
	})

	t.Run("AuthorizesHost match", func(t *testing.T) {
		t.Parallel()

		ok, err := p.AuthorizesHost(ctx, "10.0.0.1", noArgs())
		if err != nil || !ok {
			t.Fatalf("AuthorizesHost(match) = %v, %v", ok, err)
		}
	})

	t.Run("AuthorizesHost mismatch", func(t *testing.T) {
		t.Parallel()

		ok, err := p.AuthorizesHost(ctx, "evil.example", noArgs())
		if err != nil || ok {
			t.Fatalf("AuthorizesHost(mismatch) = %v, %v", ok, err)
		}
	})
}

func TestKubernetesProvider_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("ip-literal endpoint: exact match allowed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "203.0.113.7", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), noArgs())
		if err != nil || !ok {
			t.Fatalf("exact IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("ip-literal endpoint: private match allowed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "10.0.0.5", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("10.0.0.5"), noArgs())
		if err != nil || !ok {
			t.Fatalf("private IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("ip-literal endpoint: mismatch denied", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "203.0.113.7", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.8"), noArgs())
		if err != nil || ok {
			t.Fatalf("mismatch IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("floor denies metadata even for ip-literal", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "169.254.169.254", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("169.254.169.254"), noArgs())
		if err != nil || ok {
			t.Fatalf("metadata IP must be denied by floor: ok=%v err=%v", ok, err)
		}
	})

	t.Run("fqdn endpoint: in resolved set allowed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "api.example.com", mode: credBearer, token: "t"})
		p.resolver = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		}
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), noArgs())
		if err != nil || !ok {
			t.Fatalf("in-set: ok=%v err=%v", ok, err)
		}
	})

	t.Run("fqdn endpoint: out of set denied", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "api.example.com", mode: credBearer, token: "t"})
		p.resolver = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		}
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.9"), noArgs())
		if err != nil || ok {
			t.Fatalf("out-of-set: ok=%v err=%v", ok, err)
		}
	})

	t.Run("fqdn endpoint: resolver error fails closed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "api.example.com", mode: credBearer, token: "t"})
		p.resolver = func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("dns boom")
		}
		_, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), noArgs())
		if err == nil {
			t.Fatal("resolver error must deny (fail closed)")
		}
	})
}

// TestKubernetesProvider_WrongPortNeverAttachesTheCredential walks the gate
// sequence the transport runs (host, then action, then inject) for the
// cynative#308 request and asserts the bearer never reaches the request: the
// host gate passes because it only ever sees a port-stripped hostname, so the
// action gate is what has to stop this one.
func TestKubernetesProvider_WrongPortNeverAttachesTheCredential(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	p := newKubernetesProvider(resolvedCluster{
		host: "k3s.example", authority: "k3s.example:6443", port: "6443", mode: credBearer, token: "secret",
	})
	p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
		t.Fatal("the clusterrole fetch must not run for a request on the wrong port")

		return nil, nil //nolint:nilnil // unreachable after t.Fatal; stub never runs.
	}

	providers := []Provider{p}
	const rawURL = "https://k3s.example/api/v1/pods" // the port the model omitted.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	rawArgs := json.RawMessage(`{"kubernetes_auth":{}}`)

	if hostErr := AuthorizeHost(ctx, kubernetesProviderName, req.URL.Hostname(), providers, rawArgs); hostErr != nil {
		t.Fatalf("the host gate is port-blind and should pass here: %v", hostErr)
	}

	actionErr := AuthorizeAction(ctx, kubernetesProviderName, authreq.NewView(req, ""), providers, rawArgs)
	if !errors.Is(actionErr, ErrHostNotAuthorized) {
		t.Fatalf("action gate = %v, want ErrHostNotAuthorized", actionErr)
	}

	// The transport returns at that error, so Inject never runs. Proving the
	// header is absent is what the gate is for.
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want the credential never attached", got)
	}
}

// TestKubernetesProvider_PublishedAuthorityIsAccepted is the property the
// derived spellings of the kubeconfig server exist to keep: whatever authority
// the connector publishes to the operator and the model, used verbatim as a URL
// authority, has to pass both the host gate and the port gate. Each case runs
// the real extract-resolve-construct path, so a normalization applied on one
// side and not the other (case, an IPv6 bracket, an empty port) fails here
// rather than in the field, which is how cynative#308 shipped.
func TestKubernetesProvider_PublishedAuthorityIsAccepted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	servers := []string{
		"https://10.0.0.1:6443",
		"https://10.0.0.1",
		"https://api.example.com:6443",
		"https://API.Example.COM:6443",
		"https://[2001:db8::1]:6443",
		"https://[2001:db8::1]",
		"https://api.example.com:",
	}
	for _, server := range servers {
		t.Run(server, func(t *testing.T) {
			t.Parallel()

			cfg := newKubeconfig()
			cfg.Clusters["c"].Server = server

			sel, err := extractSelected(cfg)
			if err != nil {
				t.Fatalf("extractSelected(%q) = %v", server, err)
			}
			rc, err := resolveSelected(sel, func(string) ([]byte, error) { return nil, nil })
			if err != nil {
				t.Fatalf("resolveSelected(%q) = %v", server, err)
			}

			p := newKubernetesProvider(rc)
			p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
				return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
				}), nil
			}

			// The authority as the model would read it out of the system prompt.
			rawURL := "https://" + rc.authority + "/api/v1/pods"

			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatalf("published authority %q does not parse as a URL: %v", rc.authority, err)
			}

			// authreq.NewView lower-cases the hostname the host gate is given,
			// and url.URL.Hostname() has already stripped the port.
			ok, err := p.AuthorizesHost(ctx, strings.ToLower(u.Hostname()), noArgs())
			if err != nil || !ok {
				t.Fatalf("host gate refused the published authority %q: ok=%v err=%v", rc.authority, ok, err)
			}

			if err = p.AuthorizeAction(ctx, actionView(t, http.MethodGet, rawURL), noArgs()); err != nil {
				t.Fatalf("action gate refused the published authority %q: %v", rc.authority, err)
			}
		})
	}
}

func TestKubernetesProvider_DescriptionNamesTheEndpoint(t *testing.T) {
	t.Parallel()

	p := newKubernetesProvider(resolvedCluster{host: "k3s.example", authority: "k3s.example:6443", port: "6443"})
	if !strings.Contains(p.Description(), "https://k3s.example:6443") {
		t.Fatalf("description %q must name the cluster base URL", p.Description())
	}
}

// TestKubernetesProvider_AuthorizeAction_port is cynative#308: a cluster whose
// kubeconfig names :6443 used to accept a request that omitted the port, which
// was then dialed on 443 and timed out with the credential already attached.
func TestKubernetesProvider_AuthorizeAction_port(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	newProv := func(t *testing.T, authority, port string) *kubernetesProvider {
		t.Helper()

		p := newKubernetesProvider(resolvedCluster{
			host: "k3s.example", authority: authority, port: port, mode: credBearer, token: "t",
		})
		p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			}), nil
		}

		return p
	}

	tests := []struct {
		name, authority, port, url string
		wantAllowed                bool
	}{
		{
			"a request that omits the port is refused", "k3s.example:6443", "6443",
			"https://k3s.example/api/v1/pods", false,
		},
		{
			"the configured port is allowed", "k3s.example:6443", "6443",
			"https://k3s.example:6443/api/v1/pods", true,
		},
		{
			"a cluster on the https default allows an omitted port", "k3s.example", "",
			"https://k3s.example/api/v1/pods", true,
		},
		{
			"a cluster on the https default refuses another port", "k3s.example", "",
			"https://k3s.example:6443/api/v1/pods", false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newProv(t, tc.authority, tc.port)
			err := p.AuthorizeAction(ctx, actionView(t, http.MethodGet, tc.url), noArgs())
			if tc.wantAllowed {
				if err != nil {
					t.Fatalf("AuthorizeAction(%q) = %v, want allowed", tc.url, err)
				}

				return
			}
			if !errors.Is(err, ErrHostNotAuthorized) {
				t.Fatalf("AuthorizeAction(%q) = %v, want ErrHostNotAuthorized", tc.url, err)
			}
			if !strings.Contains(err.Error(), "k3s.example") ||
				!strings.Contains(err.Error(), defaultedPort(tc.port)) {
				t.Fatalf("denial %q must name the expected authority", err)
			}
		})
	}
}

func TestKubernetesProvider_AuthorizeAction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	newProv := func() *kubernetesProvider {
		p := newKubernetesProvider(resolvedCluster{
			host: "h", authority: "h:6443", port: "6443", mode: credBearer, token: "t",
		})
		p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			}), nil
		}
		return p
	}

	t.Run("allows list pods", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		v := actionView(t, http.MethodGet, "https://h:6443/api/v1/namespaces/d/pods")
		if err := p.AuthorizeAction(ctx, v, noArgs()); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("denies get nodes", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		v := actionView(t, http.MethodGet, "https://h:6443/api/v1/nodes")
		if err := p.AuthorizeAction(ctx, v, noArgs()); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("get nodes should be ErrForbidden, got %v", err)
		}
	})

	t.Run("fail closed on fetch error", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}
		v := actionView(t, http.MethodGet, "https://h:6443/api/v1/pods")
		if err := p.AuthorizeAction(ctx, v, noArgs()); err == nil {
			t.Fatal("fetch error must deny (fail closed)")
		}
	})

	t.Run("accepts a present kubernetes_auth block", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		v := actionView(t, http.MethodGet, "https://h:6443/api/v1/pods")
		args := providerArgs(kubernetesProviderName, `{"kubernetes_auth":{}}`)
		if err := p.AuthorizeAction(ctx, v, args); err != nil {
			t.Fatalf("present kubernetes_auth = %v, want nil", err)
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		v := actionView(t, http.MethodGet, "https://h:6443/api/v1/pods")
		if err := p.AuthorizeAction(ctx, v, providerArgs(kubernetesProviderName, `{`)); err == nil {
			t.Fatal("malformed args must error")
		}
	})
}

func TestKubernetesProvider_bearerToken(t *testing.T) {
	t.Parallel()

	t.Run("literal token", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, token: "abc"})
		got, err := p.bearerToken()
		if err != nil || got != "abc" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("tokenFile re-read and trimmed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, tokenFile: "/run/token"})
		p.readFile = func(string) ([]byte, error) { return []byte("file-tok\n"), nil }
		got, err := p.bearerToken()
		if err != nil || got != "file-tok" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("tokenFile read error", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credBearer, tokenFile: "/run/token"})
		p.readFile = func(string) ([]byte, error) { return nil, errors.New("gone") }
		if _, err := p.bearerToken(); err == nil {
			t.Fatal("read error must propagate")
		}
	})

	t.Run("mtls returns empty", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credMTLS, clientCert: "c", clientKey: "k"})
		got, err := p.bearerToken()
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

func TestKubernetesProbeAndSeedView_SeedsViewPolicyCache(t *testing.T) {
	t.Parallel()

	var calls int
	vp := k8sauthz.BuildViewPolicy(nil)
	p := newKubernetesProvider(resolvedCluster{mode: credBearer, token: "t"})
	p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
		calls++

		return vp, nil
	}

	// The registration probe validates the ClusterRole live AND must seed the
	// runtime cache, so the first request does not repeat the fetch.
	if err := p.probeAndSeedView(context.Background()); err != nil {
		t.Fatalf("probeAndSeedView: %v", err)
	}

	if _, err := p.resolveViewPolicy(context.Background(), nil); err != nil {
		t.Fatalf("resolveViewPolicy: %v", err)
	}

	if calls != 1 {
		t.Fatalf(
			"fetchView called %d times; the probe should have seeded the cache so the request skips the fetch",
			calls,
		)
	}
}

func TestKubernetesFetchViewBearerContract(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != clusterRolePath("view") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer integ-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"kind":"ClusterRole","rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list","watch"]}]}`,
		))
	}))
	defer srv.Close()

	// defaultFetchView builds its own dial-guarded client; the httptest server
	// is loopback (forbidden by the floor), so we exercise the bearer-fetch
	// contract through the shared fetchViewPolicy seam that defaultFetchView
	// calls — mirroring the existing TestFetchViewPolicyIntegration.
	vp, err := fetchViewPolicy(context.Background(), srv.Client(), srv.URL, "view", func(r *http.Request) error {
		r.Header.Set("Authorization", "Bearer integ-token")
		return nil
	})
	if err != nil {
		t.Fatalf("fetchViewPolicy: %v", err)
	}
	if !vp.Allows(k8sauthz.RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "pods"}) {
		t.Fatal("fetched policy should allow list pods")
	}
}
