package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

func tokAt(access string, expiry time.Time) *oauth2.Token {
	return &oauth2.Token{AccessToken: access, Expiry: expiry} //nolint:exhaustruct // test token.
}

func TestTokenExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		tok  *oauth2.Token
		want bool
	}{
		{"zero/unknown expiry forces refresh", tokAt("a", time.Time{}), true},
		{"far future valid", tokAt("a", now.Add(time.Hour)), false},
		{"within skew expired", tokAt("a", now.Add(30*time.Second)), true},
		{"past expired", tokAt("a", now.Add(-time.Minute)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenExpired(tc.tok, now); got != tc.want {
				t.Fatalf("tokenExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFreshestToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	older := tokAt("old", now.Add(time.Hour))
	newer := tokAt("new", now.Add(2*time.Hour))

	if got := freshestToken(nil, nil); got != nil {
		t.Fatalf("nil/nil: got %v, want nil", got)
	}
	if got := freshestToken(nil, newer); got != newer {
		t.Fatalf("nil/newer: got %v", got)
	}
	if got := freshestToken(older, nil); got != older {
		t.Fatalf("older/nil: got %v", got)
	}
	if got := freshestToken(older, newer); got != newer {
		t.Fatalf("older/newer: want newer, got %q", got.AccessToken)
	}
	// When a is strictly fresher than b → prefer a.
	if got := freshestToken(newer, older); got != newer {
		t.Fatalf("newer/older: want newer (a), got %q", got.AccessToken)
	}
	// Tie on expiry → prefer the on-disk (second) arg, which reflects external writes.
	tieA := tokAt("mem", now.Add(time.Hour))
	tieB := tokAt("disk", now.Add(time.Hour))
	if got := freshestToken(tieA, tieB); got != tieB {
		t.Fatalf("tie: want on-disk, got %q", got.AccessToken)
	}
}

func TestCredToToken(t *testing.T) {
	t.Parallel()
	if credToToken(glabCredential{}) != nil { //nolint:exhaustruct // empty.
		t.Fatal("empty cred should yield nil token")
	}
	tok := credToToken(glabCredential{AccessToken: "a", RefreshToken: "r"}) //nolint:exhaustruct // partial.
	if tok == nil || tok.AccessToken != "a" || tok.RefreshToken != "r" {
		t.Fatalf("credToToken = %+v", tok)
	}
}

const sampleGlabConfig = `hosts:
  gitlab.com:
    token: glpat-ABC
    oauth2_refresh_token: refresh-XYZ
    oauth2_expiry_date: "2026-06-18T14:00:00Z"
    is_oauth2: true
  gitlab.example.com:
    token: selfmanaged-tok
    client_id: cid-123
    is_oauth2: true
`

func TestParseGlabCred(t *testing.T) {
	t.Parallel()

	t.Run("oauth token gitlab.com", func(t *testing.T) {
		t.Parallel()
		cred, err := parseGlabCred([]byte(sampleGlabConfig), "gitlab.com")
		if err != nil {
			t.Fatalf("parseGlabCred: %v", err)
		}
		if cred.AccessToken != "glpat-ABC" || cred.RefreshToken != "refresh-XYZ" ||
			!cred.IsOAuth2 || cred.ClientID != "" || cred.Host != "gitlab.com" {
			t.Fatalf("cred = %+v", cred)
		}
		want := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
		if !cred.Expiry.Equal(want) {
			t.Fatalf("expiry = %v, want %v", cred.Expiry, want)
		}
	})

	t.Run("self-managed carries client_id", func(t *testing.T) {
		t.Parallel()
		cred, err := parseGlabCred([]byte(sampleGlabConfig), "gitlab.example.com")
		if err != nil {
			t.Fatalf("parseGlabCred: %v", err)
		}
		if cred.AccessToken != "selfmanaged-tok" || cred.ClientID != "cid-123" || !cred.IsOAuth2 {
			t.Fatalf("cred = %+v", cred)
		}
	})

	t.Run("absent host → empty", func(t *testing.T) {
		t.Parallel()
		cred, err := parseGlabCred([]byte(sampleGlabConfig), "nope.com")
		if err != nil || cred.AccessToken != "" {
			t.Fatalf("cred=%+v err=%v, want empty", cred, err)
		}
	})

	t.Run("empty bytes → empty", func(t *testing.T) {
		t.Parallel()
		cred, err := parseGlabCred(nil, "gitlab.com")
		if err != nil || cred.AccessToken != "" {
			t.Fatalf("cred=%+v err=%v, want empty", cred, err)
		}
	})
}

func TestParseGlabCred_RealGlabSerialization(t *testing.T) {
	t.Parallel()

	t.Run("real glab serialization: !!null token + quoted is_oauth2", func(t *testing.T) {
		t.Parallel()
		cfg := "hosts:\n" +
			"    gitlab.com:\n" +
			"        token: !!null abc123hex\n" +
			"        oauth2_refresh_token: !!null refreshXYZ\n" +
			"        oauth2_expiry_date: \"2026-06-18T14:00:00Z\"\n" +
			"        is_oauth2: \"true\"\n" +
			"        user: !!null 0xh0b0\n"
		cred, err := parseGlabCred([]byte(cfg), "gitlab.com")
		if err != nil {
			t.Fatalf("parseGlabCred on real glab config: %v", err)
		}
		if cred.AccessToken != "abc123hex" || cred.RefreshToken != "refreshXYZ" || !cred.IsOAuth2 {
			t.Fatalf("cred = %+v, want access=abc123hex refresh=refreshXYZ is_oauth2=true", cred)
		}
	})
}

func TestParseGlabCred_Expiry(t *testing.T) {
	t.Parallel()

	t.Run("ambiguous RFC822 zone abbreviation → zero (fail-safe, not a fabricated offset)", func(t *testing.T) {
		t.Parallel()
		// A non-numeric zone abbreviation (e.g. JST) must NOT be parsed: time.Parse
		// would fabricate a zero-offset zone, making a stale token look valid. It
		// yields zero, which tokenExpired treats as expired → a safe refresh.
		cfg := "hosts:\n  gitlab.com:\n    token: t\n    oauth2_expiry_date: \"18 Aug 25 19:18 JST\"\n    is_oauth2: \"true\"\n"
		cred, err := parseGlabCred([]byte(cfg), "gitlab.com")
		if err != nil || !cred.Expiry.IsZero() {
			t.Fatalf("cred=%+v err=%v, want zero expiry (fail-safe)", cred, err)
		}
	})

	t.Run("RFC3339 with numeric offset is parsed", func(t *testing.T) {
		t.Parallel()
		cfg := "hosts:\n  gitlab.com:\n    token: t\n    oauth2_expiry_date: \"2026-06-18T14:00:00+09:00\"\n    is_oauth2: \"true\"\n"
		cred, err := parseGlabCred([]byte(cfg), "gitlab.com")
		if err != nil || cred.Expiry.IsZero() {
			t.Fatalf("cred=%+v err=%v, want parsed RFC3339 expiry", cred, err)
		}
	})

	t.Run("unparseable expiry → zero (treated as expired)", func(t *testing.T) {
		t.Parallel()
		cfg := "hosts:\n  gitlab.com:\n    token: t\n    oauth2_expiry_date: not-a-date\n    is_oauth2: true\n"
		cred, err := parseGlabCred([]byte(cfg), "gitlab.com")
		if err != nil || !cred.Expiry.IsZero() {
			t.Fatalf("cred=%+v err=%v, want zero expiry", cred, err)
		}
	})

	t.Run("malformed yaml errors", func(t *testing.T) {
		t.Parallel()
		if _, err := parseGlabCred([]byte("hosts: [oops"), "gitlab.com"); err == nil {
			t.Fatal("want error on malformed yaml")
		}
	})

	t.Run("non-oauth token", func(t *testing.T) {
		t.Parallel()
		cfg := "hosts:\n  gitlab.com:\n    token: glpat-plain\n"
		cred, err := parseGlabCred([]byte(cfg), "gitlab.com")
		if err != nil || cred.IsOAuth2 || cred.AccessToken != "glpat-plain" {
			t.Fatalf("cred=%+v err=%v", cred, err)
		}
	})
}

func TestResolveOAuthClientID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		servedHost string
		cred       glabCredential
		want       string
		wantOK     bool
	}{
		{
			name: "gitlab.com uses default", servedHost: "gitlab.com",
			cred: glabCredential{}, want: gitlabDefaultClientID, wantOK: true, //nolint:exhaustruct // test.
		},
		{
			name: "gitlab.com with port still default", servedHost: "gitlab.com:443",
			cred: glabCredential{}, want: gitlabDefaultClientID, wantOK: true, //nolint:exhaustruct // test.
		},
		{
			name: "self-managed uses configured", servedHost: "gl.example.com",
			cred: glabCredential{ClientID: "cid"}, want: "cid", wantOK: true, //nolint:exhaustruct // test.
		},
		{
			name: "self-managed without client_id unresolved", servedHost: "gl.example.com",
			cred: glabCredential{}, want: "", wantOK: false, //nolint:exhaustruct // test.
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := resolveOAuthClientID(tc.servedHost, tc.cred)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("resolveOAuthClientID = (%q,%v), want (%q,%v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestRebaseGlabConfig(t *testing.T) {
	t.Parallel()
	base := `hosts:
  gitlab.com:
    token: old-access
    oauth2_refresh_token: old-refresh
    oauth2_expiry_date: "2026-06-18T12:00:00Z"
    is_oauth2: true
  other.com:
    token: untouched
# a trailing comment
`
	newTok := &oauth2.Token{ //nolint:exhaustruct // test.
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		Expiry:       time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC),
	}
	out, err := rebaseGlabConfig([]byte(base), "gitlab.com", newTok)
	if err != nil {
		t.Fatalf("rebaseGlabConfig: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "new-access") || !strings.Contains(s, "new-refresh") ||
		!strings.Contains(s, "2026-06-18T14:00:00Z") {
		t.Fatalf("updated fields missing:\n%s", s)
	}
	if !strings.Contains(s, "untouched") || !strings.Contains(s, "# a trailing comment") ||
		!strings.Contains(s, "is_oauth2: true") {
		t.Fatalf("unrelated content lost:\n%s", s)
	}
	if strings.Contains(s, "old-access") || strings.Contains(s, "old-refresh") {
		t.Fatalf("stale values remain:\n%s", s)
	}
	cred, err := parseGlabCred(out, "gitlab.com")
	if err != nil || cred.AccessToken != "new-access" || cred.RefreshToken != "new-refresh" {
		t.Fatalf("reparse cred=%+v err=%v", cred, err)
	}
}

func TestRebaseGlabConfig_AppendsMissingKeys(t *testing.T) {
	t.Parallel()
	// Host has only token; refresh + expiry must be APPENDED (the setMappingScalar
	// append branch), not error.
	base := "hosts:\n  gitlab.com:\n    token: old\n    is_oauth2: true\n"
	newTok := &oauth2.Token{ //nolint:exhaustruct // test.
		AccessToken: "new", RefreshToken: "appended-refresh",
		Expiry: time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC),
	}
	out, err := rebaseGlabConfig([]byte(base), "gitlab.com", newTok)
	if err != nil {
		t.Fatalf("rebaseGlabConfig: %v", err)
	}
	if !strings.Contains(string(out), "appended-refresh") {
		t.Fatalf("refresh token not appended:\n%s", out)
	}
}

func TestRebaseGlabConfig_MissingHost(t *testing.T) {
	t.Parallel()
	_, err := rebaseGlabConfig([]byte("hosts:\n  a.com:\n    token: t\n"), "gitlab.com",
		&oauth2.Token{AccessToken: "x"}) //nolint:exhaustruct // test.
	if !errors.Is(err, errGitLabHostNodeMissing) {
		t.Fatalf("err = %v, want errGitLabHostNodeMissing", err)
	}
}

func TestRebaseGlabConfig_Malformed(t *testing.T) {
	t.Parallel()
	// "hosts: [oops" triggers a genuine yaml.Unmarshal error (unclosed bracket).
	if _, err := rebaseGlabConfig([]byte("hosts: [oops"), "gitlab.com",
		&oauth2.Token{AccessToken: "x"}); err == nil { //nolint:exhaustruct // test.
		t.Fatal("want parse error")
	}
}

func TestDocumentRoot_NonDocument(t *testing.T) {
	t.Parallel()
	// documentRoot must return n unchanged when it is not a DocumentNode, covering
	// the "already a mapping/scalar" fallback branch (unreachable via rebaseGlabConfig
	// but part of the function's contract).
	n := &yaml.Node{Kind: yaml.MappingNode} //nolint:exhaustruct // test node.
	if got := documentRoot(n); got != n {
		t.Fatalf("documentRoot(mapping) = %p, want %p (identity)", got, n)
	}
}

func TestMappingValue_Nil(t *testing.T) {
	t.Parallel()
	// mappingValue(nil, key) must return nil without panicking.
	if got := mappingValue(nil, "any"); got != nil {
		t.Fatalf("mappingValue(nil) = %v, want nil", got)
	}
	// A non-mapping kind must also return nil.
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Value: "v"} //nolint:exhaustruct // test.
	if got := mappingValue(scalar, "any"); got != nil {
		t.Fatalf("mappingValue(scalar) = %v, want nil", got)
	}
}

func TestRebaseGlabConfig_NoHostsKey(t *testing.T) {
	t.Parallel()
	// A valid yaml with no "hosts" key at all: mappingValue returns nil for "hosts",
	// then the inner mappingValue(nil, host) exercises the m==nil branch.
	_, err := rebaseGlabConfig([]byte("other: value\n"), "gitlab.com",
		&oauth2.Token{AccessToken: "x"}) //nolint:exhaustruct // test.
	if !errors.Is(err, errGitLabHostNodeMissing) {
		t.Fatalf("err = %v, want errGitLabHostNodeMissing", err)
	}
}

func TestRebaseGlabConfig_MarshalError(t *testing.T) {
	t.Parallel()
	// rebaseGlabConfigWith lets us inject a failing marshalFn to cover the
	// yaml.Marshal error path, which is unreachable with real yaml.Marshal.
	base := "hosts:\n  gitlab.com:\n    token: t\n    is_oauth2: true\n"
	boom := errors.New("marshal failed")
	_, err := rebaseGlabConfigWith([]byte(base), "gitlab.com",
		&oauth2.Token{AccessToken: "x"}, //nolint:exhaustruct // test.
		func(any) ([]byte, error) { return nil, boom },
	)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want marshal error", err)
	}
}

// fakeClock is a deterministic clock whose Sleep advances Now, so the bounded
// invalid_grant retry loop terminates without real time passing.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// oauthHarness bundles a glabOAuthSource with controllable seams.
type oauthHarness struct {
	src     *glabOAuthSource
	clock   *fakeClock
	disk    *oauth2.Token // current on-disk token (mutate to simulate concurrent writers).
	mu      sync.Mutex
	written []*oauth2.Token
	warned  []error
	probeOK bool
}

func newHarness(t *testing.T, clientID string, initial *oauth2.Token, now time.Time) *oauthHarness {
	t.Helper()
	h := &oauthHarness{clock: &fakeClock{t: now}, disk: initial, probeOK: true} //nolint:exhaustruct // zero ok.
	h.src = &glabOAuthSource{                                                   //nolint:exhaustruct // mu zero.
		host: "gitlab.com", clientID: clientID, cached: initial,
		readCreds: func() (glabCredential, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.disk == nil {
				return glabCredential{}, nil //nolint:exhaustruct // absent.
			}

			return glabCredential{ //nolint:exhaustruct // test.
				Host: "gitlab.com", AccessToken: h.disk.AccessToken,
				RefreshToken: h.disk.RefreshToken, Expiry: h.disk.Expiry, IsOAuth2: true,
			}, nil
		},
		probe: func() error {
			if h.probeOK {
				return nil
			}

			return errors.New("dir not writable")
		},
		writeBack: func(_ string, newTok *oauth2.Token) (*oauth2.Token, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.written = append(h.written, newTok)

			return newTok, nil
		},
		warn: func(err error) { h.warned = append(h.warned, err) },
		now:  h.clock.now, sleep: h.clock.sleep,
	}

	return h
}

func TestGlabOAuthSource_Token(t *testing.T) { //nolint:gocognit,gocyclo,cyclop // many subtests by design.
	t.Parallel()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

	t.Run("valid token returned without refresh", func(t *testing.T) {
		t.Parallel()
		tok := tokAt("valid", now.Add(time.Hour))
		h := newHarness(t, gitlabDefaultClientID, tok, now)
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { panic("must not refresh") }
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "valid" {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	})

	t.Run("adopts newer on-disk token when cached still valid", func(t *testing.T) {
		t.Parallel()
		cached := tokAt("cached", now.Add(30*time.Minute))
		h := newHarness(t, gitlabDefaultClientID, cached, now)
		h.disk = tokAt("disk-newer", now.Add(2*time.Hour))
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { panic("must not refresh") }
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "disk-newer" {
			t.Fatalf("got=%+v err=%v, want disk-newer", got, err)
		}
	})

	t.Run("expired refreshes and writes back the rotation", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{
			AccessToken:  "dead",
			RefreshToken: "rt1",
			Expiry:       now.Add(-time.Minute),
		} //nolint:exhaustruct // test.
		fresh := &oauth2.Token{
			AccessToken:  "fresh",
			RefreshToken: "rt2",
			Expiry:       now.Add(2 * time.Hour),
		} //nolint:exhaustruct // test.
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(in *oauth2.Token) (*oauth2.Token, error) {
			if in.RefreshToken != "rt1" {
				t.Fatalf("refreshed with %q, want rt1", in.RefreshToken)
			}

			return fresh, nil
		}
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "fresh" {
			t.Fatalf("got=%+v err=%v", got, err)
		}
		if len(h.written) != 1 || h.written[0].RefreshToken != "rt2" {
			t.Fatalf("write-back = %+v, want rotated rt2", h.written)
		}
	})

	t.Run("zero/unknown-expiry OAuth token triggers a refresh", func(t *testing.T) {
		t.Parallel()
		// oauth2_expiry_date missing/unparseable → zero Expiry → must refresh (not be
		// treated as a never-expiring static token).
		unknown := &oauth2.Token{AccessToken: "stale", RefreshToken: "rt1"} //nolint:exhaustruct // zero Expiry.
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, unknown, now)
		h.disk = unknown
		refreshed := false
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { refreshed = true; return fresh, nil }
		got, err := h.src.Token()
		if err != nil || !refreshed || got.AccessToken != "fresh" {
			t.Fatalf("got=%+v err=%v refreshed=%v, want a refresh", got, err, refreshed)
		}
	})

	t.Run("expired with no client_id is a dead session (no refresh attempted)", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		h := newHarness(t, "", expired, now) // no client_id → cannot refresh.
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { panic("must not refresh") }
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("expired but config unwritable does not burn the token", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.probeOK = false
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { panic("must not refresh when probe fails") }
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("valid token returned even when refresh is impossible", func(t *testing.T) {
		t.Parallel()
		valid := tokAt("still-valid", now.Add(time.Hour))
		h := newHarness(t, "", valid, now) // no client_id, but token is valid.
		h.disk = valid
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "still-valid" {
			t.Fatalf("got=%+v err=%v, want the still-valid token", got, err)
		}
	})

	t.Run("valid cached token + on-disk host removed → fail closed (stop using it)", func(t *testing.T) {
		t.Parallel()
		// The cached token is still valid (future expiry), but the user removed the
		// host from glab config (e.g. glab auth logout). Local config is the source of
		// truth for the USE decision too: we must stop using the cached token immediately,
		// not wait for it to expire.
		valid := tokAt("still-valid", now.Add(time.Hour))
		h := newHarness(t, gitlabDefaultClientID, valid, now)
		h.src.readCreds = func() (glabCredential, error) {
			return glabCredential{}, nil //nolint:exhaustruct // host removed.
		}
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			panic("must not refresh when the on-disk host was removed")
		}
		got, err := h.src.Token()
		if !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
		if got != nil {
			t.Fatalf("token = %+v, want nil (must not use the cached token once the host is gone)", got)
		}
	})

	t.Run("valid cached token + on-disk host switched to PAT → fail closed", func(t *testing.T) {
		t.Parallel()
		// The cached token is still valid, but the user switched this host to a PAT
		// (non-OAuth credential). Local config is the source of truth: stop injecting
		// the cached OAuth bearer immediately.
		valid := tokAt("still-valid", now.Add(time.Hour))
		h := newHarness(t, gitlabDefaultClientID, valid, now)
		h.src.readCreds = func() (glabCredential, error) {
			return glabCredential{ //nolint:exhaustruct // PAT replacement.
				Host: "gitlab.com", AccessToken: "pat-xyz", IsOAuth2: false,
			}, nil
		}
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			panic("must not refresh when the on-disk host is a PAT")
		}
		got, err := h.src.Token()
		if !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
		if got != nil {
			t.Fatalf("token = %+v, want nil (must not use the cached token after a switch to PAT)", got)
		}
	})

	t.Run("invalid_grant recovers when a valid token lands on disk", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{
			AccessToken:  "dead",
			RefreshToken: "rt1",
			Expiry:       now.Add(-time.Minute),
		} //nolint:exhaustruct // test.
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"} //nolint:exhaustruct // err.
		}
		// The winner publishes a valid token after the first recovery re-read.
		reads := 0
		base := h.src.readCreds
		h.src.readCreds = func() (glabCredential, error) {
			reads++
			if reads >= 3 { // initial freshest read + first recovery read see dead; then the winner's.
				return glabCredential{ //nolint:exhaustruct // test.
					Host: "gitlab.com", AccessToken: "winner", Expiry: now.Add(2 * time.Hour), IsOAuth2: true,
				}, nil
			}

			return base()
		}
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "winner" {
			t.Fatalf("got=%+v err=%v, want recovered winner token", got, err)
		}
	})

	t.Run(
		"invalid_grant recovery: disk switched to a PAT with future expiry → fail closed (not adopted)",
		func(t *testing.T) {
			t.Parallel()
			// During recovery the host is switched to a PAT (non-OAuth) that happens to carry
			// a parseable future oauth2_expiry_date. Local config is the source of truth: a
			// non-OAuth credential must NOT be pulled into the OAuth session. The loop keeps
			// waiting (fakeClock.sleep advances now) and ultimately fails closed.
			expired := &oauth2.Token{ //nolint:exhaustruct // test.
				AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
			}
			h := newHarness(t, gitlabDefaultClientID, expired, now)
			h.disk = expired
			h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
				return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"} //nolint:exhaustruct // err.
			}
			reads := 0
			base := h.src.readCreds
			h.src.readCreds = func() (glabCredential, error) {
				reads++
				if reads >= 2 { // initial freshest read sees the OAuth cred; recovery reads see the PAT.
					return glabCredential{ //nolint:exhaustruct // PAT with future expiry.
						Host: "gitlab.com", AccessToken: "pat", IsOAuth2: false, Expiry: now.Add(2 * time.Hour),
					}, nil
				}

				return base()
			}
			got, err := h.src.Token()
			if !errors.Is(err, errGitLabRefreshDead) {
				t.Fatalf("err = %v, want errGitLabRefreshDead", err)
			}
			if got != nil {
				t.Fatalf("token = %+v, want nil (a PAT must never be adopted into the OAuth session)", got)
			}
		},
	)

	t.Run("invalid_grant past deadline is a dead session", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{
			AccessToken:  "dead",
			RefreshToken: "rt1",
			Expiry:       now.Add(-time.Minute),
		} //nolint:exhaustruct // test.
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired // disk never updates → stays dead; fakeClock.sleep advances now past the deadline.
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"} //nolint:exhaustruct // err.
		}
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("non-invalid_grant refresh error propagates", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		boom := errors.New("network down")
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return nil, boom }
		if _, err := h.src.Token(); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want network error", err)
		}
	})

	t.Run("post-proof persistence failure warns and still returns the refreshed token", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return fresh, nil }
		// A POST-proof persistence failure (the atomic write failed after confirming the
		// on-disk host is still our OAuth credential) → warn + use the minted token.
		wbErr := fmt.Errorf("%w: disk full", errGitLabPersistFailed)
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) { return nil, wbErr }
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "fresh" {
			t.Fatalf("got=%+v err=%v, want fresh token + nil error", got, err)
		}
		if len(h.warned) != 1 || !errors.Is(h.warned[0], wbErr) {
			t.Fatalf("warned = %v, want one persist-failed warning", h.warned)
		}
	})

	t.Run("write-back pre-proof failure → fail closed", func(t *testing.T) {
		t.Parallel()
		// A generic (non-errGitLabPersistFailed) write-back error means we could NOT
		// confirm the on-disk host is still our OAuth credential (e.g. the config
		// vanished/became unreadable mid-refresh). Fail closed and do not warn-and-use.
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return fresh, nil }
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) {
			return nil, errors.New("config vanished mid-refresh")
		}
		got, err := h.src.Token()
		if !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
		if got != nil {
			t.Fatalf("token = %+v, want nil (must not use the minted token on a pre-proof failure)", got)
		}
		if len(h.warned) != 0 {
			t.Fatalf("warned = %v, want no warning for a pre-proof failure", h.warned)
		}
	})

	t.Run("write-back reports host switched to PAT → fail closed (do not use the minted token)", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return fresh, nil }
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) {
			return nil, errGitLabHostNotOAuth
		}
		got, err := h.src.Token()
		if !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
		if got != nil {
			t.Fatalf("token = %+v, want nil (must not use the minted token)", got)
		}
		if len(h.warned) != 0 {
			t.Fatalf("warned = %v, want no warning for a config-changed case", h.warned)
		}
	})

	t.Run("write-back reports host removed → fail closed", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return fresh, nil }
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) {
			return nil, errGitLabHostNodeMissing
		}
		got, err := h.src.Token()
		if !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
		if got != nil {
			t.Fatalf("token = %+v, want nil (must not use the minted token)", got)
		}
		if len(h.warned) != 0 {
			t.Fatalf("warned = %v, want no warning for a config-changed case", h.warned)
		}
	})

	t.Run("write-back adopt-and-skip returns the adopted token", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		fresh := tokAt("fresh", now.Add(2*time.Hour))
		adopted := tokAt("adopted-by-winner", now.Add(3*time.Hour))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { return fresh, nil }
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) { return adopted, nil }
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "adopted-by-winner" {
			t.Fatalf("got=%+v err=%v, want adopted token", got, err)
		}
	})

	t.Run("write-back failure then later refresh repairs (no stale adopt)", func(t *testing.T) {
		t.Parallel()
		// Refresh #1 succeeds but write-back fails: source caches new(rt2), disk keeps
		// old(rt1). Later, cached expires; refresh #2 must WRITE the newest token, not
		// adopt the stale on-disk rt1. This pins the round-3 provenance fix.
		old := &oauth2.Token{
			AccessToken:  "old",
			RefreshToken: "rt1",
			Expiry:       now.Add(-time.Minute),
		} //nolint:exhaustruct // test.
		two := &oauth2.Token{
			AccessToken:  "two",
			RefreshToken: "rt2",
			Expiry:       now.Add(-time.Second),
		} //nolint:exhaustruct // expired soon.
		three := &oauth2.Token{
			AccessToken:  "three",
			RefreshToken: "rt3",
			Expiry:       now.Add(2 * time.Hour),
		} //nolint:exhaustruct // test.
		h := newHarness(t, gitlabDefaultClientID, old, now)
		h.disk = old // disk stays at rt1 throughout (write-back keeps failing first).
		// First refresh returns rt2 but write-back fails; second returns rt3 and succeeds.
		refreshOut := []*oauth2.Token{two, three}
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			out := refreshOut[0]
			refreshOut = refreshOut[1:]

			return out, nil
		}
		fail := true
		var wroteSnapshots []string
		h.src.writeBack = func(diskRefresh string, newTok *oauth2.Token) (*oauth2.Token, error) {
			wroteSnapshots = append(wroteSnapshots, diskRefresh)
			if fail {
				fail = false
				// POST-proof persistence failure → warn + use the minted token (rt2 cached).
				return nil, fmt.Errorf("%w: disk full", errGitLabPersistFailed)
			}
			h.disk = newTok // success persists.

			return newTok, nil
		}
		if _, err := h.src.Token(); err != nil { // refresh #1: cached=two, disk still rt1.
			t.Fatalf("refresh #1: %v", err)
		}
		got, err := h.src.Token() // refresh #2: must write rt3, NOT adopt stale rt1.
		if err != nil || got.AccessToken != "three" {
			t.Fatalf("got=%+v err=%v, want freshly-written three (not stale adopt)", got, err)
		}
		// Both write-backs saw the same on-disk snapshot rt1 (cached rt2 never reached disk).
		for _, s := range wroteSnapshots {
			if s != "rt1" {
				t.Fatalf("write-back snapshot = %q, want rt1 (the disk snapshot)", s)
			}
		}
	})

	t.Run("read error + expired cached fails closed before any refresh", func(t *testing.T) {
		t.Parallel()
		expired := tokAt("dead", now.Add(-time.Minute))
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.src.readCreds = func() (glabCredential, error) { //nolint:exhaustruct // err.
			return glabCredential{}, errors.New("io error")
		}
		// probe would succeed and refresh must never run: the fail-closed happens in
		// freshest() before probe/refresh, so the single-use token is never burned.
		h.src.probe = func() error { return nil }
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			panic("must not refresh after a read failure on an expired token")
		}
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("read error + valid cached falls back to cache without refresh", func(t *testing.T) {
		t.Parallel()
		valid := tokAt("cached-valid", now.Add(time.Hour))
		h := newHarness(t, gitlabDefaultClientID, valid, now)
		h.src.readCreds = func() (glabCredential, error) { //nolint:exhaustruct // err.
			return glabCredential{}, errors.New("io error")
		}
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) { panic("must not refresh") }
		got, err := h.src.Token()
		if err != nil || got.AccessToken != "cached-valid" {
			t.Fatalf("got=%+v err=%v, want cached-valid with no error", got, err)
		}
	})

	t.Run("invalid_grant recovery: read error in recover loop propagates", func(t *testing.T) {
		t.Parallel()
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.disk = expired
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"} //nolint:exhaustruct // err.
		}
		// The initial readCreds (in freshest) succeeds; the recovery re-read fails.
		reads := 0
		recoverErr := errors.New("disk gone")
		base := h.src.readCreds
		h.src.readCreds = func() (glabCredential, error) {
			reads++
			if reads > 1 { // first call is from freshest(); subsequent from recover().
				return glabCredential{}, recoverErr //nolint:exhaustruct // err.
			}

			return base()
		}
		if _, err := h.src.Token(); !errors.Is(err, recoverErr) {
			t.Fatalf("err = %v, want recover read error", err)
		}
	})

	t.Run("no token anywhere is a dead session", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gitlabDefaultClientID, nil, now)
		h.disk = nil
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("disk host removed mid-session is dead — no refresh", func(t *testing.T) {
		t.Parallel()
		// Cached OAuth token is expired, but the user removed the host from glab config
		// (logout). Local config is the source of truth: refuse to refresh.
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.src.readCreds = func() (glabCredential, error) { return glabCredential{}, nil } //nolint:exhaustruct // gone.
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			panic("must not refresh when the on-disk host was removed")
		}
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})

	t.Run("disk host replaced by a PAT mid-session is dead — no refresh, no write-back", func(t *testing.T) {
		t.Parallel()
		// Cached OAuth token is expired, but the user swapped this host to a PAT
		// (non-OAuth). Refuse to refresh OR clobber the new PAT.
		expired := &oauth2.Token{ //nolint:exhaustruct // test.
			AccessToken: "dead", RefreshToken: "rt1", Expiry: now.Add(-time.Minute),
		}
		h := newHarness(t, gitlabDefaultClientID, expired, now)
		h.src.readCreds = func() (glabCredential, error) {
			return glabCredential{ //nolint:exhaustruct // PAT replacement.
				Host: "gitlab.com", AccessToken: "pat-xyz", IsOAuth2: false,
			}, nil
		}
		h.src.refresh = func(*oauth2.Token) (*oauth2.Token, error) {
			panic("must not refresh when the on-disk host is a PAT")
		}
		h.src.writeBack = func(string, *oauth2.Token) (*oauth2.Token, error) {
			panic("must not write back over a PAT")
		}
		if _, err := h.src.Token(); !errors.Is(err, errGitLabRefreshDead) {
			t.Fatalf("err = %v, want errGitLabRefreshDead", err)
		}
	})
}

func TestAdoptOnDiskRotation(t *testing.T) {
	t.Parallel()

	t.Run("disk changed since snapshot → adopt", func(t *testing.T) {
		t.Parallel()
		cur := glabCredential{AccessToken: "winner", RefreshToken: "rt-new"} //nolint:exhaustruct // test.
		got, ok := adoptOnDiskRotation(cur, "rt1")                           // snapshot was rt1, disk now rt-new.
		if !ok || got.AccessToken != "winner" {
			t.Fatalf("got=%+v ok=%v, want adopted winner", got, ok)
		}
	})
	t.Run("disk unchanged since snapshot → no adopt (repairs after write-back failure)", func(t *testing.T) {
		t.Parallel()
		// Disk still holds the snapshot's rt1 (e.g. a prior write-back failed); must
		// NOT adopt this stale token — the caller writes the freshly-refreshed one.
		cur := glabCredential{AccessToken: "same", RefreshToken: "rt1"} //nolint:exhaustruct // test.
		if _, ok := adoptOnDiskRotation(cur, "rt1"); ok {
			t.Fatal("must not adopt when disk is unchanged since the snapshot")
		}
	})
	t.Run("absent host (empty cred) → no adopt", func(t *testing.T) {
		t.Parallel()
		if _, ok := adoptOnDiskRotation(glabCredential{}, "rt1"); ok { //nolint:exhaustruct // empty.
			t.Fatal("must not adopt when the on-disk host is absent")
		}
	})
}

func TestIsInvalidGrant(t *testing.T) {
	t.Parallel()
	if !isInvalidGrant(&oauth2.RetrieveError{ErrorCode: "invalid_grant"}) { //nolint:exhaustruct // err.
		t.Fatal("invalid_grant should match")
	}
	if isInvalidGrant(&oauth2.RetrieveError{ErrorCode: "temporarily_unavailable"}) { //nolint:exhaustruct // err.
		t.Fatal("other code should not match")
	}
	if isInvalidGrant(errors.New("plain")) {
		t.Fatal("non-RetrieveError should not match")
	}
}

func TestGitlabCredFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("env token wins as non-oauth PAT with empty ConfigPath", func(t *testing.T) {
		t.Parallel()
		cred, err := gitlabCredFromConfig("glpat-env", "/cfg/config.yml", []byte(sampleGlabConfig),
			[]string{"gitlab.com"})
		if err != nil || cred.AccessToken != "glpat-env" || cred.IsOAuth2 || cred.Host != "" {
			t.Fatalf("cred=%+v err=%v", cred, err)
		}
		if cred.ConfigPath != "" {
			t.Fatalf("env token must not carry a ConfigPath, got %q", cred.ConfigPath)
		}
	})

	t.Run("config oauth for first matching host stamps ConfigPath", func(t *testing.T) {
		t.Parallel()
		cred, err := gitlabCredFromConfig("", "/cfg/config.yml", []byte(sampleGlabConfig),
			[]string{"missing.com", "gitlab.com"})
		if err != nil || cred.AccessToken != "glpat-ABC" || !cred.IsOAuth2 || cred.Host != "gitlab.com" {
			t.Fatalf("cred=%+v err=%v", cred, err)
		}
		if cred.ConfigPath != "/cfg/config.yml" {
			t.Fatalf("config cred must carry the source path, got %q", cred.ConfigPath)
		}
	})

	t.Run("absent everywhere → empty", func(t *testing.T) {
		t.Parallel()
		cred, err := gitlabCredFromConfig("", "/cfg/config.yml", []byte(sampleGlabConfig), []string{"none.com"})
		if err != nil || cred.AccessToken != "" || cred.ConfigPath != "" {
			t.Fatalf("cred=%+v err=%v", cred, err)
		}
	})

	t.Run("malformed config errors", func(t *testing.T) {
		t.Parallel()
		if _, err := gitlabCredFromConfig("", "/cfg/config.yml", []byte("hosts: [oops"),
			[]string{"gitlab.com"}); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestFirstReadableConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips an unreadable path and returns the first readable one", func(t *testing.T) {
		t.Parallel()
		read := func(path string) ([]byte, error) {
			if path == "/a/config.yml" {
				return nil, errors.New("permission denied")
			}

			return []byte("body-b"), nil
		}
		path, body := firstReadableConfig([]string{"/a/config.yml", "/b/config.yml"}, read)
		if path != "/b/config.yml" || string(body) != "body-b" {
			t.Fatalf("path=%q body=%q, want the second (readable) path", path, body)
		}
	})

	t.Run("all unreadable → empty path, nil bytes", func(t *testing.T) {
		t.Parallel()
		read := func(string) ([]byte, error) { return nil, errors.New("nope") }
		path, body := firstReadableConfig([]string{"/a/config.yml", "/b/config.yml"}, read)
		if path != "" || body != nil {
			t.Fatalf("path=%q body=%v, want empty/nil", path, body)
		}
	})
}
