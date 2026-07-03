package auth

import (
	"testing"
)

func TestParseCredentialHelperOutput(t *testing.T) {
	t.Parallel()
	id := func(s string) string { return s }
	exp := "2026-07-03T12:07:21Z"
	tests := []struct {
		name     string
		stdout   string
		wantKind credKind
		wantTok  string
		wantExp  bool // expects a non-zero Expiry.
	}{
		{
			"oauth2 success",
			`{"type":"success","instance_url":"https://gitlab.com","token":{"type":"oauth2","token":"abc","expiry_timestamp":"` + exp + `"}}`,
			credOK, "abc", true,
		},
		{
			"pat success no expiry",
			`{"type":"success","instance_url":"https://gitlab.com","token":{"type":"access_token","token":"pat"}}`,
			credOK, "pat", false,
		},
		{
			"oauth2 missing expiry is incompatible",
			`{"type":"success","instance_url":"https://gitlab.com","token":{"type":"oauth2","token":"abc"}}`,
			credIncompatible, "", false,
		},
		{
			"error not authenticated",
			`{"type":"error","message":"glab is not authenticated. Use glab auth login to authenticate"}`,
			credNotAuthenticated, "", false,
		},
		{
			"empty token is incompatible",
			`{"type":"success","instance_url":"https://gitlab.com","token":{"type":"oauth2","token":""}}`,
			credIncompatible, "", false,
		},
		{"help text is incompatible", "\n  USAGE\n  glab auth <command>\n", credIncompatible, "", false},
		{"empty stdout is incompatible", "", credIncompatible, "", false},
		{"unknown type is incompatible", `{"type":"other"}`, credIncompatible, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseCredentialHelperOutput([]byte(tc.stdout), id)
			if got.kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", got.kind, tc.wantKind)
			}
			if tc.wantKind == credOK {
				if got.token == nil || got.token.AccessToken != tc.wantTok {
					t.Fatalf("token = %+v, want AccessToken %q", got.token, tc.wantTok)
				}
				if got.token.Expiry.IsZero() == tc.wantExp {
					t.Fatalf("expiry zero=%v, wantExp=%v", got.token.Expiry.IsZero(), tc.wantExp)
				}
			}
		})
	}
}

func TestParseCredentialHelperOutput_NeverEchoesToken(t *testing.T) {
	t.Parallel()
	// A malformed success carrying a token must not surface the token in any field.
	got := parseCredentialHelperOutput(
		[]byte(`{"type":"success","token":{"type":"oauth2","token":"SECRET"}}`),
		func(s string) string { return s },
	)
	if got.kind != credIncompatible {
		t.Fatalf("kind = %v, want credIncompatible", got.kind)
	}
	if got.message != "" {
		t.Fatalf("message = %q, want empty (no stdout echo)", got.message)
	}
}
