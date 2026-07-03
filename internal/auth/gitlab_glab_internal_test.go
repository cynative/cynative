package auth

import (
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/oauth2"
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

func TestParseCredentialHelperOutput_RedactsErrorMessage(t *testing.T) {
	t.Parallel()
	got := parseCredentialHelperOutput(
		[]byte(`{"type":"error","message":"boom"}`),
		func(string) string { return "[REDACTED]" },
	)
	if got.kind != credNotAuthenticated || got.message != "[REDACTED]" {
		t.Fatalf("got kind=%v message=%q, want credNotAuthenticated + redacted", got.kind, got.message)
	}
}

func TestGlabHelperEnv(t *testing.T) {
	t.Parallel()
	parent := []string{
		"HOME=/home/u", "PATH=/usr/bin", "XDG_RUNTIME_DIR=/run/u",
		"GITLAB_TOKEN=leak", "OPENAI_API_KEY=leak", "AWS_SECRET_ACCESS_KEY=leak",
		"DBUS_SESSION_BUS_ADDRESS=unix:x", "GITLAB_HOST=stale", "MALFORMED_NO_EQUALS",
	}
	got := glabHelperEnv(parent, "gitlab.com")
	has := func(kv string) bool { return slices.Contains(got, kv) }
	for _, keep := range []string{"HOME=/home/u", "PATH=/usr/bin", "XDG_RUNTIME_DIR=/run/u", "DBUS_SESSION_BUS_ADDRESS=unix:x"} {
		if !has(keep) {
			t.Errorf("dropped allowlisted %q", keep)
		}
	}
	for _, drop := range []string{"GITLAB_TOKEN=leak", "OPENAI_API_KEY=leak", "AWS_SECRET_ACCESS_KEY=leak", "GITLAB_HOST=stale"} {
		if has(drop) {
			t.Errorf("leaked non-allowlisted %q", drop)
		}
	}
	for _, want := range []string{"GITLAB_HOST=gitlab.com", "GLAB_CHECK_UPDATE=false", "GLAB_SEND_TELEMETRY=false"} {
		if !has(want) {
			t.Errorf("missing injected %q", want)
		}
	}
}

func TestGlabLoginHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		configHost, apiHost, wantHost string
		wantOK                        bool
	}{
		{"", "", "gitlab.com", true},
		{"gitlab.example.com", "", "gitlab.example.com", true},
		{"gitlab.example.com:8443", "", "gitlab.example.com", true},
		{"", "gitlab.private.com", "", false},          // api_host-only default: no glab path (leak guard).
		{"gitlab.com", "gitlab.private.com", "", false}, // explicit public host + api override: leak guard.
		{"gitlab.example.com", "api.example.com", "gitlab.example.com", true},
	}
	for _, tc := range tests {
		gotHost, gotOK := glabLoginHost(tc.configHost, tc.apiHost)
		if gotHost != tc.wantHost || gotOK != tc.wantOK {
			t.Errorf("glabLoginHost(%q,%q) = (%q,%v), want (%q,%v)",
				tc.configHost, tc.apiHost, gotHost, gotOK, tc.wantHost, tc.wantOK)
		}
	}
}

func TestValidateInstanceURL(t *testing.T) {
	t.Parallel()
	if err := validateInstanceURL("https://gitlab.com", "gitlab.com"); err != nil {
		t.Errorf("match: unexpected err %v", err)
	}
	if err := validateInstanceURL("https://GITLAB.com:443", "gitlab.com"); err != nil {
		t.Errorf("case/port-insensitive match: unexpected err %v", err)
	}
	if err := validateInstanceURL("https://evil.com", "gitlab.com"); err == nil {
		t.Error("mismatch: want error")
	}
	if err := validateInstanceURL("://junk", "gitlab.com"); err == nil {
		t.Error("unparseable: want error")
	}
}

func TestGlabHelperArgs(t *testing.T) {
	t.Parallel()
	if got := glabHelperArgs(); len(got) != 2 || got[0] != "auth" || got[1] != "credential-helper" {
		t.Fatalf("glabHelperArgs() = %v", got)
	}
}

func TestCapWriter(t *testing.T) {
	t.Parallel()
	w := &capWriter{max: 4} //nolint:exhaustruct // buf grows.
	n, err := w.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("Write = (%d,%v), want (8,nil) so the pipe drains", n, err)
	}
	if string(w.Bytes()) != "abcd" {
		t.Fatalf("Bytes = %q, want capped %q", w.Bytes(), "abcd")
	}
	if _, _ = w.Write([]byte("ij")); string(w.Bytes()) != "abcd" {
		t.Fatalf("Bytes = %q, want still %q after cap", w.Bytes(), "abcd")
	}
}

func TestGlabHelperSource(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	mk := func(access string, exp time.Time) *oauth2.Token {
		return &oauth2.Token{AccessToken: access, Expiry: exp} //nolint:exhaustruct // access+expiry.
	}

	t.Run("valid cache skips fetch", func(t *testing.T) {
		t.Parallel()
		calls := 0
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { calls++; return mk("new", base.Add(time.Hour)), nil },
			func() time.Time { return base }, mk("seed", base.Add(time.Hour)))
		tok, err := s.Token()
		if err != nil || tok.AccessToken != "seed" || calls != 0 {
			t.Fatalf("got (%v,%v) calls=%d, want seed with no fetch", tok, err, calls)
		}
	})

	t.Run("zero-expiry PAT cached forever", func(t *testing.T) {
		t.Parallel()
		calls := 0
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { calls++; return nil, nil },
			func() time.Time { return base.Add(1000 * time.Hour) }, mk("pat", time.Time{}))
		tok, _ := s.Token()
		if tok.AccessToken != "pat" || calls != 0 {
			t.Fatalf("PAT re-fetched: calls=%d", calls)
		}
	})

	t.Run("expired token triggers fetch", func(t *testing.T) {
		t.Parallel()
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { return mk("fresh", base.Add(2*time.Hour)), nil },
			func() time.Time { return base.Add(time.Hour) }, mk("stale", base.Add(30*time.Minute)))
		tok, err := s.Token()
		if err != nil || tok.AccessToken != "fresh" {
			t.Fatalf("got (%v,%v), want fresh", tok, err)
		}
	})

	t.Run("adopt-on-failure returns still-valid seed", func(t *testing.T) {
		t.Parallel()
		// now within refresh skew of the seed expiry forces a fetch; fetch fails; seed
		// still not hard-expired, so it is adopted.
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { return nil, errGitLabHelperUnavailable },
			func() time.Time { return base.Add(time.Hour) }, mk("seed", base.Add(time.Hour+30*time.Second)))
		tok, err := s.Token()
		if err != nil || tok.AccessToken != "seed" {
			t.Fatalf("got (%v,%v), want seed adopted on transient failure", tok, err)
		}
	})

	t.Run("hard-expired plus fetch failure fails closed", func(t *testing.T) {
		t.Parallel()
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { return nil, errGitLabHelperUnavailable },
			func() time.Time { return base.Add(2 * time.Hour) }, mk("dead", base.Add(time.Hour)))
		if _, err := s.Token(); err == nil {
			t.Fatal("want error when cached is hard-expired and fetch fails")
		}
	})

	t.Run("failure cooldown suppresses re-exec", func(t *testing.T) {
		t.Parallel()
		calls := 0
		now := base.Add(2 * time.Hour) // seed hard-expired.
		s := newGlabHelperSource(
			func() (*oauth2.Token, error) { calls++; return nil, errGitLabHelperUnavailable },
			func() time.Time { return now }, mk("dead", base.Add(time.Hour)))
		_, _ = s.Token() // first call: fetch (calls=1), records lastFail.
		_, _ = s.Token() // second call within cooldown: no new fetch.
		if calls != 1 {
			t.Fatalf("calls=%d, want 1 (cooldown suppresses the second exec)", calls)
		}
	})
}

func TestTokenFromHelper(t *testing.T) {
	t.Parallel()
	id := func(s string) string { return s }
	ok := `{"type":"success","instance_url":"https://gitlab.com","token":{"type":"oauth2","token":"abc","expiry_timestamp":"2026-07-03T12:00:00Z"}}`
	tok, err := tokenFromHelper("gitlab.com", []byte(ok), id)
	if err != nil || tok.AccessToken != "abc" {
		t.Fatalf("got (%v,%v), want abc", tok, err)
	}
	if _, err := tokenFromHelper("gitlab.com", []byte(`{"type":"error","message":"x"}`), id); !errors.Is(err, errGitLabHelperUnavailable) {
		t.Fatalf("error JSON: err = %v, want errGitLabHelperUnavailable", err)
	}
	mismatch := `{"type":"success","instance_url":"https://evil.com","token":{"type":"oauth2","token":"x","expiry_timestamp":"2026-07-03T12:00:00Z"}}`
	if _, err := tokenFromHelper("gitlab.com", []byte(mismatch), id); !errors.Is(err, errGitLabInstanceMismatch) {
		t.Fatalf("mismatch: err = %v", err)
	}
}
