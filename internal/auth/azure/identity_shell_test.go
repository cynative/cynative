package azure_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return "h." + enc(claims) + ".s"
}

func TestIdentityShellProbe(t *testing.T) {
	jwt := fakeJWT(t, map[string]any{
		"tid": "home-tid",
		"oid": "oid-1",
		"upn": "me@contoso.onmicrosoft.com",
	})
	prober := azurehardening.NewIdentityProber(azurehardening.IdentityConfig{
		TokenFunc: func(_ context.Context, _ string) (string, error) { return jwt, nil },
	})
	id, err := prober.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if id.TenantID != "home-tid" {
		t.Errorf("TenantID = %q, want home-tid", id.TenantID)
	}
	if id.Principal != "me@contoso.onmicrosoft.com" {
		t.Errorf("Principal = %q, want upn", id.Principal)
	}
}

func TestIdentityShellTokenError(t *testing.T) {
	prober := azurehardening.NewIdentityProber(azurehardening.IdentityConfig{
		TokenFunc: func(_ context.Context, _ string) (string, error) { return "", errors.New("AADSTS error") },
	})
	if _, err := prober.Probe(context.Background()); err == nil {
		t.Fatal("expected error on token acquisition failure")
	}
}

func TestIdentityShellNoTenant(t *testing.T) {
	// A token whose claims carry no tid must fail closed (cannot resolve home).
	jwt := fakeJWT(t, map[string]any{"oid": "oid-only"})
	prober := azurehardening.NewIdentityProber(azurehardening.IdentityConfig{
		TokenFunc: func(_ context.Context, _ string) (string, error) { return jwt, nil },
	})
	if _, err := prober.Probe(context.Background()); err == nil {
		t.Fatal("expected error when token has no tid claim")
	}
}
