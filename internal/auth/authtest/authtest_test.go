package authtest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"

	"github.com/cynative/cynative/internal/auth/authtest"
)

// addrAuthorizer is the subset of auth.AddrAuthorizer used to assert the test
// doubles allow every resolved IP under the dial-time IP guard.
type addrAuthorizer interface {
	AuthorizesAddr(ctx context.Context, ip netip.Addr, rawArgs json.RawMessage) (bool, error)
}

func TestProviders_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	doubles := map[string]addrAuthorizer{
		"loopback": &authtest.LoopbackProvider{},
		"eks":      authtest.NewEKSCert(""),
		"gke":      authtest.NewGKECert(""),
		"aks":      authtest.NewAKSCert("", "", ""),
	}

	for name, p := range doubles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("127.0.0.1"), nil)
			if err != nil || !ok {
				t.Errorf("AuthorizesAddr: got ok=%v err=%v, want true/nil", ok, err)
			}
		})
	}
}

func TestFailingProvider(t *testing.T) {
	t.Parallel()

	p := &authtest.FailingProvider{}

	if p.Name() != "failing" {
		t.Errorf("expected name 'failing', got %q", p.Name())
	}

	if p.Description() == "" {
		t.Error("expected non-empty description")
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

	if err := p.InjectAuth(req, nil); err == nil {
		t.Fatal("expected error from FailingProvider")
	}

	ok, err := p.AuthorizesHost(context.Background(), "anyhost", nil)
	if err != nil || !ok {
		t.Errorf("AuthorizesHost: got ok=%v err=%v, want true/nil", ok, err)
	}
}

func TestLoopbackProvider_Name(t *testing.T) {
	t.Parallel()

	if got := (&authtest.LoopbackProvider{}).Name(); got != "loopback" {
		t.Errorf("Name() = %q, want %q", got, "loopback")
	}

	if got := (&authtest.LoopbackProvider{ProviderName: "x"}).Name(); got != "x" {
		t.Errorf("Name() = %q, want %q", got, "x")
	}
}

func TestLoopbackProvider_Description(t *testing.T) {
	t.Parallel()

	if (&authtest.LoopbackProvider{}).Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestLoopbackProvider_InjectAuth(t *testing.T) {
	t.Parallel()

	t.Run("WithToken", func(t *testing.T) {
		t.Parallel()

		p := &authtest.LoopbackProvider{Token: "tok"}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok")
		}
	})

	t.Run("NoToken", func(t *testing.T) {
		t.Parallel()

		p := &authtest.LoopbackProvider{}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("expected no Authorization header, got %q", got)
		}
	})
}

func TestLoopbackProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	ok, err := (&authtest.LoopbackProvider{}).AuthorizesHost(context.Background(), "anyhost", nil)
	if err != nil || !ok {
		t.Errorf("AuthorizesHost: got ok=%v err=%v, want true/nil", ok, err)
	}
}

func TestLoopbackProvider_CACertData(t *testing.T) {
	t.Parallel()

	p := &authtest.LoopbackProvider{CACert: "dGVzdC1jYQ=="}
	got, err := p.CACertData(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "dGVzdC1jYQ==" {
		t.Errorf("CACertData = %q, want %q", got, "dGVzdC1jYQ==")
	}
}

func TestGenerateCA(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("expected non-empty cert PEM")
	}

	if len(keyPEM) == 0 {
		t.Error("expected non-empty key PEM")
	}
}

func TestGenerateCert_Server(t *testing.T) {
	t.Parallel()

	caCert, caKey, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	certPEM, keyPEM, err := authtest.GenerateCert(caCert, caKey, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("expected non-empty cert PEM")
	}

	if len(keyPEM) == 0 {
		t.Error("expected non-empty key PEM")
	}
}

func TestGenerateCert_Client(t *testing.T) {
	t.Parallel()

	caCert, caKey, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	certPEM, keyPEM, err := authtest.GenerateCert(caCert, caKey, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("expected non-empty cert PEM")
	}

	if len(keyPEM) == 0 {
		t.Error("expected non-empty key PEM")
	}
}

// TestCertProvider_Constructors verifies Name/Description/AuthorizesHost basics
// for every constructor.
func TestCertProvider_Constructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		p        *authtest.CertProvider
		wantName string
		wantDesc string
	}{
		{"eks", authtest.NewEKSCert(""), "eks", "Test EKS"},
		{"gke", authtest.NewGKECert(""), "gke", "Test GKE"},
		{"aks", authtest.NewAKSCert("", "", ""), "aks", "Test AKS"},
		{"failing", authtest.NewFailingCert(), "ca-fail", "CA cert always fails"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.p.Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}

			if got := tt.p.Description(); got != tt.wantDesc {
				t.Errorf("Description() = %q, want %q", got, tt.wantDesc)
			}

			ok, err := tt.p.AuthorizesHost(context.Background(), "anyhost", nil)
			if err != nil || !ok {
				t.Errorf("AuthorizesHost: got ok=%v err=%v, want true/nil", ok, err)
			}
		})
	}
}

// TestCertProvider_InjectAuth verifies bearer injection and mTLS suppression.
func TestCertProvider_InjectAuth(t *testing.T) {
	t.Parallel()

	t.Run("eks bearer injected", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewEKSCert("")
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer k8s-aws-v1.test" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer k8s-aws-v1.test")
		}
	})

	t.Run("gke bearer injected", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewGKECert("")
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer ya29.test-gke-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer ya29.test-gke-token")
		}
	})

	t.Run("aks bearer injected without mTLS", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewAKSCert("", "", "")
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer eyJ0eXAiOi.test-aks-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer eyJ0eXAiOi.test-aks-token")
		}
	})

	t.Run("aks bearer suppressed with mTLS", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewAKSCert("", "Y2VydC1kYXRh", "a2V5LWRhdGE=")
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("expected no Authorization header for mTLS, got %q", got)
		}
	})

	t.Run("failing cert no bearer", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewFailingCert()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com", nil)

		if err := p.InjectAuth(req, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("expected no Authorization header for failing cert, got %q", got)
		}
	})
}

// TestCertProvider_CACertData_Err verifies that NewFailingCert returns an error.
func TestCertProvider_CACertData_Err(t *testing.T) {
	t.Parallel()

	p := authtest.NewFailingCert()
	_, err := p.CACertData(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error from CACertData")
	}

	if err.Error() != "CA cert resolution failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCertProvider_CACertData_Static verifies the static CA path (NewGKECert).
func TestCertProvider_CACertData_Static(t *testing.T) {
	t.Parallel()

	t.Run("non-empty", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewGKECert("dGVzdC1jYQ==")
		got, err := p.CACertData(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != "dGVzdC1jYQ==" {
			t.Errorf("CACertData = %q, want %q", got, "dGVzdC1jYQ==")
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewGKECert("")
		got, err := p.CACertData(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != "" {
			t.Errorf("expected empty, got: %q", got)
		}
	})
}

// TestCertProvider_CACertData_EKSStatic verifies the EKS double returns its
// constructor-supplied static CA, like the GKE double.
func TestCertProvider_CACertData_EKSStatic(t *testing.T) {
	t.Parallel()

	p := authtest.NewEKSCert("dGVzdC1jYQ==")
	got, err := p.CACertData(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "dGVzdC1jYQ==" {
		t.Errorf("CACertData = %q, want %q", got, "dGVzdC1jYQ==")
	}
}

// TestCertProvider_ClientCertData verifies the cert+key round-trip and empty cases.
func TestCertProvider_ClientCertData(t *testing.T) {
	t.Parallel()

	t.Run("with cert and key", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewAKSCert("", "Y2VydC1kYXRh", "a2V5LWRhdGE=")
		gotCert, gotKey, err := p.ClientCertData(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if gotCert != "Y2VydC1kYXRh" {
			t.Errorf("cert = %q, want %q", gotCert, "Y2VydC1kYXRh")
		}

		if gotKey != "a2V5LWRhdGE=" {
			t.Errorf("key = %q, want %q", gotKey, "a2V5LWRhdGE=")
		}
	})

	t.Run("empty cert and key", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewAKSCert("", "", "")
		gotCert, gotKey, err := p.ClientCertData(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if gotCert != "" || gotKey != "" {
			t.Errorf("expected empty cert and key, got cert=%q key=%q", gotCert, gotKey)
		}
	})

	t.Run("eks returns empty", func(t *testing.T) {
		t.Parallel()

		p := authtest.NewEKSCert("")
		gotCert, gotKey, err := p.ClientCertData(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if gotCert != "" || gotKey != "" {
			t.Errorf("expected empty cert and key for EKS, got cert=%q key=%q", gotCert, gotKey)
		}
	})
}

// TestCertProvider_AuthorizesAddr verifies that every CertProvider instance allows
// all resolved IPs.
func TestCertProvider_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	providers := []*authtest.CertProvider{
		authtest.NewEKSCert(""),
		authtest.NewGKECert(""),
		authtest.NewAKSCert("", "", ""),
		authtest.NewFailingCert(),
	}

	for _, p := range providers {
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel()

			ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.1"), nil)
			if err != nil || !ok {
				t.Errorf("AuthorizesAddr: got ok=%v err=%v, want true/nil", ok, err)
			}
		})
	}
}
