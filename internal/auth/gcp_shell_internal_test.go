package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// testKeyBits is the smallest RSA size the JWT signer accepts.
const testKeyBits = 2048

// writeServiceAccountKey writes a syntactically complete service-account key
// whose token_uri is tokenURL, so a token exchange lands on the test server
// rather than Google.
func writeServiceAccountKey(t *testing.T, tokenURL string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, testKeyBits)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemKey := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)},
	) //nolint:exhaustruct // headers unused.
	key, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "bench-project",
		"private_key":  string(pemKey),
		"client_email": "reader@bench-project.iam.gserviceaccount.com",
		"token_uri":    tokenURL,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if writeErr := os.WriteFile(path, key, 0o600); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	return path
}

func TestLoadGCPCredentials_File(t *testing.T) {
	t.Parallel()

	t.Run("missing file is an attributed error", func(t *testing.T) {
		t.Parallel()
		_, err := loadGCPCredentials(context.Background(), filepath.Join(t.TempDir(), "absent.json"))
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want a wrapped os.ErrNotExist", err)
		}
	})

	t.Run("malformed JSON is refused before any credential is built", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "bad.json")
		if writeErr := os.WriteFile(path, []byte("not json"), 0o600); writeErr != nil {
			t.Fatalf("WriteFile: %v", writeErr)
		}
		_, err := loadGCPCredentials(context.Background(), path)
		if !errors.Is(err, ErrGCPCredentialsFile) {
			t.Fatalf("err = %v, want ErrGCPCredentialsFile", err)
		}
	})

	t.Run("service-account key resolves to its project and mints at its token_uri", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"emulator-token","token_type":"Bearer","expires_in":3599}`))
		}))
		defer srv.Close()
		path := writeServiceAccountKey(t, srv.URL+"/token")

		creds, err := loadGCPCredentials(context.Background(), path)
		if err != nil {
			t.Fatalf("loadGCPCredentials: %v", err)
		}
		if creds.ProjectID != "bench-project" {
			t.Errorf("ProjectID = %q, want bench-project", creds.ProjectID)
		}
		if probeErr := probeGCPToken(context.Background(), path); probeErr != nil {
			t.Fatalf("probeGCPToken: %v", probeErr)
		}
		tok, err := creds.TokenSource.Token()
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if tok.AccessToken != "emulator-token" {
			t.Errorf("AccessToken = %q, want the test server's", tok.AccessToken)
		}
	})
}
