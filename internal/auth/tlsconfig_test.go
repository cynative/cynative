package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
)

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()

	caPEM, _, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	validCA := base64.StdEncoding.EncodeToString(caPEM)

	// A self-signed cert with its matching key, so tls.X509KeyPair succeeds.
	clientCertPEM, clientKeyPEM, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA (client): %v", err)
	}
	validCert := base64.StdEncoding.EncodeToString(clientCertPEM)
	validKey := base64.StdEncoding.EncodeToString(clientKeyPEM)

	// A different key, so cert/key do not match.
	_, otherKeyPEM, err := authtest.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA (mismatch): %v", err)
	}
	mismatchKey := base64.StdEncoding.EncodeToString(otherKeyPEM)

	// Valid base64 of non-PEM bytes, so AppendCertsFromPEM returns false.
	nonPEM := base64.StdEncoding.EncodeToString([]byte("not a pem block"))

	tests := []buildTLSConfigCase{
		{name: "valid CA only", caData: validCA},
		{name: "system pool unavailable falls back to empty pool", poolErr: true, caData: validCA},
		{name: "bad base64 CA", caData: "not-base64-!!", wantErr: "failed to decode CA certificate"},
		{name: "non-PEM CA", caData: nonPEM, wantErr: "failed to parse CA certificate"},
		{name: "server name set", caData: validCA, serverName: "api.example.com", wantServer: "api.example.com"},
		{name: "valid client cert+key", caData: validCA, clientCert: validCert, clientKey: validKey, wantCert: true},
		{
			name: "bad base64 client cert", caData: validCA, clientCert: "not-base64-!!", clientKey: validKey,
			wantErr: "failed to decode client certificate",
		},
		{
			name: "bad base64 client key", caData: validCA, clientCert: validCert, clientKey: "not-base64-!!",
			wantErr: "failed to decode client key",
		},
		{
			name: "mismatched cert/key", caData: validCA, clientCert: validCert, clientKey: mismatchKey,
			wantErr: "failed to parse client certificate key pair",
		},
		{name: "client cert but empty key", caData: validCA, clientCert: validCert, clientKey: "", wantCert: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runBuildTLSConfigCase(t, tt)
		})
	}
}

// buildTLSConfigCase is one row of the TestBuildTLSConfig table.
type buildTLSConfigCase struct {
	name       string
	poolErr    bool // systemPool returns an error (empty-pool fallback).
	caData     string
	clientCert string
	clientKey  string
	serverName string
	wantErr    string // substring; "" means success.
	wantCert   bool   // expect exactly one tls.Certificate.
	wantServer string // expected ServerName.
}

// runBuildTLSConfigCase executes one table row against auth.BuildTLSConfig.
func runBuildTLSConfigCase(t *testing.T, tt buildTLSConfigCase) {
	t.Helper()

	pool := x509.NewCertPool()
	systemPool := func() (*x509.CertPool, error) { return pool, nil }
	if tt.poolErr {
		systemPool = func() (*x509.CertPool, error) { return nil, errors.New("system pool unavailable") }
	}

	cfg, cfgErr := auth.BuildTLSConfig(systemPool, tt.caData, tt.clientCert, tt.clientKey, tt.serverName)

	if tt.wantErr != "" {
		if cfgErr == nil || !strings.Contains(cfgErr.Error(), tt.wantErr) {
			t.Fatalf("want error containing %q, got %v", tt.wantErr, cfgErr)
		}

		return
	}
	if cfgErr != nil {
		t.Fatalf("unexpected error: %v", cfgErr)
	}
	assertBuiltTLSConfig(t, cfg, tt.wantServer, tt.wantCert)
	if !tt.poolErr && cfg.RootCAs != pool {
		t.Error("RootCAs should be the system pool")
	}
}

// assertBuiltTLSConfig checks the success-path shape of a built TLS config.
func assertBuiltTLSConfig(t *testing.T, cfg *tls.Config, wantServer string, wantCert bool) {
	t.Helper()

	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if cfg.ServerName != wantServer {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, wantServer)
	}
	if gotCert := len(cfg.Certificates) == 1; gotCert != wantCert {
		t.Errorf("one client certificate present = %v, want %v", gotCert, wantCert)
	}
}
