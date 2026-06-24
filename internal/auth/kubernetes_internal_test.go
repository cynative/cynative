package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

func TestParseKubernetesArgs(t *testing.T) {
	t.Parallel()

	t.Run("absent key yields nil, no error", func(t *testing.T) {
		t.Parallel()

		args, err := parseKubernetesArgs(json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args != nil {
			t.Fatalf("want nil args for absent key, got %+v", args)
		}
	})

	t.Run("empty input yields nil, no error", func(t *testing.T) {
		t.Parallel()

		args, err := parseKubernetesArgs(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args != nil {
			t.Fatalf("want nil args for empty input, got %+v", args)
		}
	})

	t.Run("present empty object yields non-nil", func(t *testing.T) {
		t.Parallel()

		args, err := parseKubernetesArgs(json.RawMessage(`{"kubernetes_auth":{}}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args == nil {
			t.Fatal("want non-nil args for present key")
		}
	})

	t.Run("malformed JSON errors", func(t *testing.T) {
		t.Parallel()

		if _, err := parseKubernetesArgs(json.RawMessage(`{`)); err == nil {
			t.Fatal("malformed args must error")
		}
	})
}

func TestRejectUnsafe(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()

	clean := func() (*clientcmdapi.Cluster, *clientcmdapi.AuthInfo) {
		return &clientcmdapi.Cluster{Server: "https://10.0.0.1:6443"},
			&clientcmdapi.AuthInfo{Token: "t"}
	}

	t.Run("clean context passes", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		if err := rejectUnsafe(cl, ai); err != nil {
			t.Fatalf("clean context rejected: %v", err)
		}
	})

	t.Run("exec rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Exec = &clientcmdapi.ExecConfig{Command: "/bin/sh"}
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("exec plugin must be rejected")
		}
	})

	t.Run("auth-provider rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "gcp"}
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("auth-provider must be rejected")
		}
	})

	t.Run("insecure-skip-tls-verify rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.InsecureSkipTLSVerify = true
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("insecure-skip-tls-verify must be rejected")
		}
	})

	t.Run("proxy-url rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.ProxyURL = "http://proxy:8080"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("proxy-url must be rejected")
		}
	})

	t.Run("non-https server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "http://10.0.0.1:6443"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("non-https server must be rejected")
		}
	})

	t.Run("unparseable server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "://bad"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("unparseable server must be rejected")
		}
	})

	t.Run("empty-host https server rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "https:///api"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("https server with empty host must be rejected")
		}
	})

	t.Run("impersonation rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Impersonate = "system:admin"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonation must be rejected")
		}
	})

	t.Run("basic-auth username rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Username = "admin"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("basic-auth username must be rejected")
		}
	})

	t.Run("basic-auth password rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.Password = "hunter2"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("basic-auth password must be rejected")
		}
	})

	t.Run("impersonate-uid rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.ImpersonateUID = "1234"
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonate-uid must be rejected")
		}
	})

	t.Run("impersonate-user-extra rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		ai.ImpersonateUserExtra = map[string][]string{"scopes": {"x"}}
		if err := rejectUnsafe(cl, ai); err == nil {
			t.Fatal("impersonate-user-extra must be rejected")
		}
	})

	t.Run("server URL userinfo rejected", func(t *testing.T) {
		t.Parallel()

		cl, ai := clean()
		cl.Server = "https://user:pass@10.0.0.1:6443"
		if err := rejectUnsafe(cl, ai); err == nil {
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
		if sel.endpoint != "https://10.0.0.1:6443" {
			t.Fatalf("endpoint = %q, want https://10.0.0.1:6443", sel.endpoint)
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

func TestEndpointURL(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, server, want string }{
		{"ip with port", "https://10.0.0.1:6443", "https://10.0.0.1:6443"},
		{"fqdn with port", "https://api.example.com:6443", "https://api.example.com:6443"},
		{"no explicit port", "https://api.example.com", "https://api.example.com"},
		{"ipv6 with port", "https://[2001:db8::1]:6443", "https://[2001:db8::1]:6443"},
		{"unparseable returns empty", "://bad", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := endpointURL(tc.server); got != tc.want {
				t.Fatalf("endpointURL(%q) = %q, want %q", tc.server, got, tc.want)
			}
		})
	}
}

func TestResolveSelected(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()

	t.Run("bearer with inline CA", func(t *testing.T) {
		t.Parallel()

		sel := selected{host: "h", endpoint: "https://h:6443", caData: []byte("ca"), mode: credBearer, token: "t"}
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
		if rc.endpoint != "https://h:6443" {
			t.Fatalf("endpoint = %q, want https://h:6443", rc.endpoint)
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
		if err := p.InjectAuth(req, nil); err != nil {
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
		if err := p.InjectAuth(req, nil); err != nil {
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
		if err := p.InjectAuth(newReq(), nil); err == nil {
			t.Fatal("tokenFile read error must propagate")
		}
	})

	t.Run("mtls sets no header", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{mode: credMTLS, clientCert: "c", clientKey: "k"})
		req := newReq()
		if err := p.InjectAuth(req, nil); err != nil {
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

		got, err := p.CACertData(ctx, nil)
		if err != nil || got != "Y2E=" {
			t.Fatalf("CACertData = %q, %v", got, err)
		}
	})

	t.Run("ClientCertData", func(t *testing.T) {
		t.Parallel()

		cert, key, err := p.ClientCertData(ctx, nil)
		if err != nil || cert != "Y2VydA==" || key != "a2V5" {
			t.Fatalf("ClientCertData = %q, %q, %v", cert, key, err)
		}
	})

	t.Run("ServerNameData", func(t *testing.T) {
		t.Parallel()

		got, err := p.ServerNameData(ctx, nil)
		if err != nil || got != "api.internal" {
			t.Fatalf("ServerNameData = %q, %v", got, err)
		}
	})

	t.Run("AuthorizesHost match", func(t *testing.T) {
		t.Parallel()

		ok, err := p.AuthorizesHost(ctx, "10.0.0.1", nil)
		if err != nil || !ok {
			t.Fatalf("AuthorizesHost(match) = %v, %v", ok, err)
		}
	})

	t.Run("AuthorizesHost mismatch", func(t *testing.T) {
		t.Parallel()

		ok, err := p.AuthorizesHost(ctx, "evil.example", nil)
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
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), nil)
		if err != nil || !ok {
			t.Fatalf("exact IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("ip-literal endpoint: private match allowed", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "10.0.0.5", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("10.0.0.5"), nil)
		if err != nil || !ok {
			t.Fatalf("private IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("ip-literal endpoint: mismatch denied", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "203.0.113.7", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.8"), nil)
		if err != nil || ok {
			t.Fatalf("mismatch IP: ok=%v err=%v", ok, err)
		}
	})

	t.Run("floor denies metadata even for ip-literal", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "169.254.169.254", mode: credBearer, token: "t"})
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("169.254.169.254"), nil)
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
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), nil)
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
		ok, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.9"), nil)
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
		_, err := p.AuthorizesAddr(ctx, netip.MustParseAddr("203.0.113.7"), nil)
		if err == nil {
			t.Fatal("resolver error must deny (fail closed)")
		}
	})
}

func TestKubernetesProvider_AuthorizeAction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	newProv := func() *kubernetesProvider {
		p := newKubernetesProvider(resolvedCluster{host: "h", mode: credBearer, token: "t"})
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
		req, _ := http.NewRequest(http.MethodGet, "https://h/api/v1/namespaces/d/pods", nil)
		if err := p.AuthorizeAction(ctx, req, nil); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("denies get nodes", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://h/api/v1/nodes", nil)
		if err := p.AuthorizeAction(ctx, req, nil); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("get nodes should be ErrForbidden, got %v", err)
		}
	})

	t.Run("fail closed on fetch error", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		p.fetchView = func(context.Context, *KubernetesAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://h/api/v1/pods", nil)
		if err := p.AuthorizeAction(ctx, req, nil); err == nil {
			t.Fatal("fetch error must deny (fail closed)")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://h/api/v1/pods", nil)
		if err := p.AuthorizeAction(ctx, req, json.RawMessage(`{`)); err == nil {
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
