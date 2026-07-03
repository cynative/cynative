package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/rest"
)

func TestBearerInject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		bearer      string
		conditional bool
		wantHeader  string // "" means no Authorization header expected.
	}{
		{name: "unconditional with token", bearer: "tok", conditional: false, wantHeader: "Bearer tok"},
		{name: "unconditional empty token", bearer: "", conditional: false, wantHeader: "Bearer "},
		{name: "conditional with token", bearer: "tok", conditional: true, wantHeader: "Bearer tok"},
		{name: "conditional empty token", bearer: "", conditional: true, wantHeader: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
			if err := bearerInject(tt.bearer, tt.conditional)(req); err != nil {
				t.Fatalf("bearerInject returned error: %v", err)
			}
			if got := req.Header.Get("Authorization"); got != tt.wantHeader {
				t.Errorf("Authorization = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestEKSBearerToken(t *testing.T) {
	t.Parallel()

	const presignURL = "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Expires=60"
	want := "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(presignURL))
	if got := eksBearerToken(presignURL); got != want {
		t.Errorf("eksBearerToken = %q, want %q", got, want)
	}
}

func TestEKSClusterConn(t *testing.T) {
	t.Parallel()

	conn := eksClusterConn("abc123.gr7.us-east-1.eks.amazonaws.com", "Y2EtcGVt")
	if conn.endpoint != "https://abc123.gr7.us-east-1.eks.amazonaws.com" {
		t.Errorf("endpoint = %q", conn.endpoint)
	}
	if conn.caData != "Y2EtcGVt" {
		t.Errorf("caData = %q", conn.caData)
	}
	if conn.clientCert != "" || conn.clientKey != "" || conn.serverName != "" {
		t.Errorf("EKS conn must carry no client cert/serverName: %+v", conn)
	}
}

func TestGKEClusterConn(t *testing.T) {
	t.Parallel()

	conn := gkeClusterConn("34.71.1.2", "Y2EtcGVt")
	if conn.endpoint != "https://34.71.1.2" {
		t.Errorf("endpoint = %q", conn.endpoint)
	}
	if conn.caData != "Y2EtcGVt" {
		t.Errorf("caData = %q", conn.caData)
	}
	if conn.clientCert != "" || conn.clientKey != "" || conn.serverName != "" {
		t.Errorf("GKE conn must carry no client cert/serverName: %+v", conn)
	}
}

func TestAKSClusterTLSMaterial(t *testing.T) {
	t.Parallel()

	ca := []byte("ca-bytes")
	cert := []byte("cert-bytes")
	key := []byte("key-bytes")

	tests := []struct {
		name                      string
		cfg                       *rest.Config
		wantCA, wantCert, wantKey string
	}{
		{name: "all empty", cfg: &rest.Config{}},
		{
			name:   "CA only",
			cfg:    &rest.Config{TLSClientConfig: rest.TLSClientConfig{CAData: ca}},
			wantCA: base64.StdEncoding.EncodeToString(ca),
		},
		{
			name:     "full CA+cert+key",
			cfg:      &rest.Config{TLSClientConfig: rest.TLSClientConfig{CAData: ca, CertData: cert, KeyData: key}},
			wantCA:   base64.StdEncoding.EncodeToString(ca),
			wantCert: base64.StdEncoding.EncodeToString(cert),
			wantKey:  base64.StdEncoding.EncodeToString(key),
		},
		{
			name:   "cert present but key empty",
			cfg:    &rest.Config{TLSClientConfig: rest.TLSClientConfig{CAData: ca, CertData: cert}},
			wantCA: base64.StdEncoding.EncodeToString(ca),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotCA, gotCert, gotKey := aksClusterTLSMaterial(tt.cfg)
			if gotCA != tt.wantCA || gotCert != tt.wantCert || gotKey != tt.wantKey {
				t.Errorf("aksClusterTLSMaterial = (%q,%q,%q), want (%q,%q,%q)",
					gotCA, gotCert, gotKey, tt.wantCA, tt.wantCert, tt.wantKey)
			}
		})
	}
}

func TestAKSNeedsAADToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		bearer     string
		clientCert string
		want       bool
	}{
		{name: "no bearer no cert", bearer: "", clientCert: "", want: true},
		{name: "bearer present", bearer: "tok", clientCert: "", want: false},
		{name: "cert present", bearer: "", clientCert: "cert", want: false},
		{name: "both present", bearer: "tok", clientCert: "cert", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := aksNeedsAADToken(tt.bearer, tt.clientCert); got != tt.want {
				t.Errorf("aksNeedsAADToken(%q,%q) = %v, want %v", tt.bearer, tt.clientCert, got, tt.want)
			}
		})
	}
}

func TestAKSClusterConn(t *testing.T) {
	t.Parallel()

	conn := aksClusterConn("https://myaks-dns-abc.hcp.eastus.azmk8s.io:443", "Y2E=", "Y2VydA==", "a2V5")
	if conn.endpoint != "https://myaks-dns-abc.hcp.eastus.azmk8s.io" {
		t.Errorf("endpoint = %q (port and scheme should be stripped via hostFromEndpoint)", conn.endpoint)
	}
	if conn.caData != "Y2E=" || conn.clientCert != "Y2VydA==" || conn.clientKey != "a2V5" {
		t.Errorf("TLS material mismatch: %+v", conn)
	}
	if conn.serverName != "" {
		t.Errorf("AKS conn serverName = %q, want empty", conn.serverName)
	}
}

func TestKubernetesClusterConn(t *testing.T) {
	t.Parallel()

	rc := resolvedCluster{
		host:       "10.0.0.1",
		endpoint:   "https://10.0.0.1:6443",
		serverName: "kubernetes",
		caData:     "Y2E=",
		clientCert: "Y2VydA==",
		clientKey:  "a2V5",
	}
	conn := kubernetesClusterConn(rc)
	if conn.endpoint != "https://10.0.0.1:6443" {
		t.Errorf("endpoint = %q (must pass through unchanged)", conn.endpoint)
	}
	if conn.caData != "Y2E=" || conn.clientCert != "Y2VydA==" || conn.clientKey != "a2V5" {
		t.Errorf("TLS material mismatch: %+v", conn)
	}
	if conn.serverName != "kubernetes" {
		t.Errorf("serverName = %q, want kubernetes", conn.serverName)
	}
}
