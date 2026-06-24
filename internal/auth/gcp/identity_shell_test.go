package gcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestTokeninfoProberPrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"email":"me@example.com","email_verified":"true"}`))
	}))
	defer srv.Close()

	principal, err := gcphardening.ProbeTokeninfo(
		context.Background(), srv.Client(), srv.URL,
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "raw"}),
	)
	if err != nil {
		t.Fatalf("ProbeTokeninfo: %v", err)
	}
	if principal != "me@example.com" {
		t.Errorf("principal = %q, want me@example.com", principal)
	}
}
