package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// makeJWT builds an unsigned three-segment JWT whose claims segment is the
// base64url-encoded JSON of claims. Header and signature are throwaway.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(claims) + ".sig"
}

func TestDecodeClaimsHappy(t *testing.T) {
	t.Parallel()

	jwt := makeJWT(t, map[string]any{
		"tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
		"oid": "00000000-0000-0000-0000-000000000abc",
		"upn": "svc@contoso.onmicrosoft.com",
	})
	tid, principal, err := DecodeClaims(jwt)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if tid != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Errorf("tid = %q", tid)
	}
	if principal != "svc@contoso.onmicrosoft.com" {
		t.Errorf("principal = %q, want upn", principal)
	}
}

func TestDecodeClaimsPrincipalFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{
			name:   "preferred_username when no upn",
			claims: map[string]any{"tid": "t", "preferred_username": "user@x.com"},
			want:   "user@x.com",
		},
		{
			name:   "unique_name fallback",
			claims: map[string]any{"tid": "t", "unique_name": "uniq@x.com"},
			want:   "uniq@x.com",
		},
		{
			name:   "appid fallback for service principals",
			claims: map[string]any{"tid": "t", "appid": "app-guid"},
			want:   "app-guid",
		},
		{
			name:   "oid last-resort when nothing else",
			claims: map[string]any{"tid": "t", "oid": "oid-guid"},
			want:   "oid-guid",
		},
		{
			name:   "empty principal when no identity fields present",
			claims: map[string]any{"tid": "t"},
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, principal, err := DecodeClaims(makeJWT(t, tc.claims))
			if err != nil {
				t.Fatalf("DecodeClaims: %v", err)
			}
			if principal != tc.want {
				t.Errorf("principal = %q, want %q", principal, tc.want)
			}
		})
	}
}

func TestDecodeClaimsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jwt  string
	}{
		{name: "empty", jwt: ""},
		{name: "one segment", jwt: "onlyone"},
		{name: "two segments", jwt: "a.b"},
		{name: "bad base64 claims", jwt: "h.!!!notbase64!!!.s"},
		{name: "claims not json", jwt: "h." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := DecodeClaims(tc.jwt); err == nil {
				t.Errorf("DecodeClaims(%q) = nil error, want error", tc.jwt)
			}
		})
	}
}

func TestDecodeClaimsStdBase64Padding(t *testing.T) {
	t.Parallel()
	// A standard-base64 (padded) claims segment must also decode — some issuers
	// emit padded segments. tid alone is enough to validate tolerance.
	payload := base64.StdEncoding.EncodeToString([]byte(`{"tid":"abc","oid":"o"}`))
	tid, _, err := DecodeClaims("h." + payload + ".s")
	if err != nil {
		t.Fatalf("DecodeClaims padded: %v", err)
	}
	if tid != "abc" {
		t.Errorf("tid = %q, want abc", tid)
	}
}

func TestProbeIdentity(t *testing.T) {
	t.Parallel()
	t.Run("token error double-wrap", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("AADSTS boom")
		_, err := probeIdentity(
			context.Background(),
			func(context.Context, string) (string, error) { return "", sentinel },
			"https://management.azure.com/.default",
		)
		if !errors.Is(err, ErrTenantUnresolved) || !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want wraps both ErrTenantUnresolved and sentinel", err)
		}
	})
	t.Run("malformed jwt propagates", func(t *testing.T) {
		t.Parallel()
		_, err := probeIdentity(
			context.Background(),
			func(context.Context, string) (string, error) { return "not.a.jwt", nil },
			"https://management.azure.com/.default",
		)
		if !errors.Is(err, ErrTenantUnresolved) {
			t.Errorf("err = %v, want ErrTenantUnresolved", err)
		}
	})
	t.Run("valid tid assembled", func(t *testing.T) {
		t.Parallel()
		jwt := makeJWT(t, map[string]any{"tid": "home-tid", "upn": "me@contoso.com"})
		id, err := probeIdentity(
			context.Background(),
			func(context.Context, string) (string, error) { return jwt, nil },
			"https://management.azure.com/.default",
		)
		if err != nil {
			t.Fatalf("probeIdentity: %v", err)
		}
		if id.TenantID != "home-tid" || id.Principal != "me@contoso.com" {
			t.Errorf("id = %+v", id)
		}
	})
	t.Run("empty tid fail closed", func(t *testing.T) {
		t.Parallel()
		jwt := makeJWT(t, map[string]any{"oid": "oid-only"})
		_, err := probeIdentity(
			context.Background(),
			func(context.Context, string) (string, error) { return jwt, nil },
			"https://management.azure.com/.default",
		)
		if !errors.Is(err, ErrTenantUnresolved) || !strings.Contains(err.Error(), "token carries no tid claim") {
			t.Errorf("err = %v, want fail-closed no-tid", err)
		}
	})
	t.Run("uses the given scope", func(t *testing.T) {
		t.Parallel()
		var gotScope string
		tok := func(_ context.Context, scope string) (string, error) {
			gotScope = scope
			return makeJWT(t, map[string]any{"tid": "t", "oid": "o"}), nil
		}
		if _, err := probeIdentity(
			context.Background(), tok, "https://management.usgovcloudapi.net/.default",
		); err != nil {
			t.Fatalf("probeIdentity: %v", err)
		}
		if gotScope != "https://management.usgovcloudapi.net/.default" {
			t.Errorf("scope = %q, want the US-Gov ARM scope", gotScope)
		}
	})
}
