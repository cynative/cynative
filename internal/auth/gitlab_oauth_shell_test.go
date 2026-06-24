//nolint:testpackage // integration tests for unexported shell functions use internal package.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func tlsTokenServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access", "token_type": "bearer",
			"expires_in": 7200, "refresh_token": "new-refresh",
		})
	}))
}

func providerForServer(srv *httptest.Server, ip string) *gitlabProvider {
	host := strings.TrimPrefix(srv.URL, "https://") // 127.0.0.1:PORT
	p := &gitlabProvider{                           //nolint:exhaustruct // test provider.
		host: host, allowPrivateNetwork: true,
		resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(ip)}, nil
		},
	}
	p.httpClientFactory = func() (*http.Client, error) { return srv.Client(), nil }

	return p
}

func TestRefreshViaOAuth2_RotatesAndUsesParamsAuth(t *testing.T) {
	var gotClientID, gotGrant, gotRefresh string
	var gotBasic bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, gotBasic = r.BasicAuth()
		_ = r.ParseForm()
		gotClientID, gotGrant, gotRefresh = r.Form.Get(
			"client_id",
		), r.Form.Get(
			"grant_type",
		), r.Form.Get(
			"refresh_token",
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access", "token_type": "bearer", "expires_in": 7200, "refresh_token": "new-refresh",
		})
	}))
	defer srv.Close()
	p := providerForServer(srv, "127.0.0.1")

	old := &oauth2.Token{
		AccessToken:  "old",
		RefreshToken: "rt-old",
		Expiry:       time.Unix(0, 0),
	} //nolint:exhaustruct // test.
	newTok, err := refreshViaOAuth2(p, gitlabDefaultClientID, old)
	if err != nil {
		t.Fatalf("refreshViaOAuth2: %v", err)
	}
	if newTok.AccessToken != "new-access" || newTok.RefreshToken != "new-refresh" {
		t.Fatalf("token = %+v, want rotated", newTok)
	}
	if gotBasic {
		t.Fatal("client_id must be in the body, not HTTP Basic")
	}
	if gotClientID != gitlabDefaultClientID || gotGrant != "refresh_token" || gotRefresh != "rt-old" {
		t.Fatalf("form: client_id=%q grant=%q refresh=%q", gotClientID, gotGrant, gotRefresh)
	}
}

// Invariant: the production refresh client (buildProbeClient path) sets a concrete
// timeout and the fail-closed no-redirect policy.
func TestRefreshClient_TimeoutAndNoRedirect(t *testing.T) {
	p := &gitlabProvider{ //nolint:exhaustruct // test provider.
		host: "gitlab.com",
		resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
	hc, err := refreshClient(p) // no httpClientFactory → real buildProbeClient.
	if err != nil {
		t.Fatalf("refreshClient: %v", err)
	}
	if hc.Timeout != refreshTimeout {
		t.Fatalf("timeout = %v, want %v", hc.Timeout, refreshTimeout)
	}
	if hc.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set (fail-closed no-redirect)")
	}
	redirectErr := hc.CheckRedirect(&http.Request{}, nil) //nolint:exhaustruct // probe.
	if !errors.Is(redirectErr, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", redirectErr)
	}
}

// Invariant: a disallowed dial IP is rejected by the dial guard before the refresh
// POST leaves the host. The dial guard runs in the Dialer's ControlContext, which
// fires at dial time BEFORE the TLS handshake — so the real pinned client
// (system-root CA) denies the internal IP first, with no need to weaken TLS.
func TestRefreshViaOAuth2_DialGuardDenies(t *testing.T) {
	srv := tlsTokenServer(t)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	p := &gitlabProvider{ //nolint:exhaustruct // test provider.
		host: host, // allowPrivateNetwork false → 127.0.0.1 is an internal IP, denied.
		resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	// Real pinned client (no httpClientFactory override): the dial guard fires
	// before TLS, so the request never leaves the host.
	old := &oauth2.Token{
		AccessToken:  "old",
		RefreshToken: "rt-old",
		Expiry:       time.Unix(0, 0),
	} //nolint:exhaustruct // test.
	if _, err := refreshViaOAuth2(p, gitlabDefaultClientID, old); err == nil {
		t.Fatal("want dial-guard denial for an internal IP without allowPrivateNetwork")
	}
}

func TestWriteBackGlabConfig_PreservesUnrelatedAndSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real-config.yml")
	base := "hosts:\n  gitlab.com:\n    token: old\n    oauth2_refresh_token: rtold\n" +
		"    is_oauth2: true\n  other.com:\n    token: keep\n"
	if err := os.WriteFile(realFile, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yml")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	newTok := &oauth2.Token{ //nolint:exhaustruct // test.
		AccessToken: "new", RefreshToken: "rtnew", Expiry: time.Unix(1000, 0),
	}
	// On-disk refresh token is "rtold"; the snapshot matches it → write (no adopt).
	used, err := writeBackGlabConfig(link, "gitlab.com", "rtold", newTok)
	if err != nil {
		t.Fatalf("writeBackGlabConfig: %v", err)
	}
	if used.AccessToken != "new" {
		t.Fatalf("used = %+v, want the written token", used)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink not preserved: mode=%v err=%v", fi.Mode(), err)
	}
	got, _ := os.ReadFile(realFile)
	s := string(got)
	if !strings.Contains(s, "new") || !strings.Contains(s, "rtnew") || !strings.Contains(s, "keep") {
		t.Fatalf("write-back content wrong:\n%s", s)
	}
	if rfi, _ := os.Stat(realFile); rfi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", rfi.Mode().Perm())
	}
}

func TestWriteBackGlabConfig_AdoptAndSkip(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	// On-disk refresh token (rt-winner) differs from prev (rt1) → a concurrent
	// process rotated; write-back must adopt on-disk and NOT overwrite.
	winnerCfg := "hosts:\n  gitlab.com:\n    token: winner\n" +
		"    oauth2_refresh_token: rt-winner\n    is_oauth2: true\n"
	if err := os.WriteFile(cfg, []byte(winnerCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	newTok := &oauth2.Token{AccessToken: "mine", RefreshToken: "rt2"} //nolint:exhaustruct // test.
	// Pre-refresh disk snapshot was rt1; disk now holds rt-winner → adopt, skip write.
	used, err := writeBackGlabConfig(cfg, "gitlab.com", "rt1", newTok)
	if err != nil {
		t.Fatalf("writeBackGlabConfig: %v", err)
	}
	if used.AccessToken != "winner" {
		t.Fatalf("used = %+v, want adopted on-disk winner", used)
	}
	if got, _ := os.ReadFile(cfg); strings.Contains(string(got), "mine") {
		t.Fatalf("must not have written our token:\n%s", got)
	}
}

func TestWriteBackGlabConfig_RefusesNonOAuthHost(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	// The user switched this host to a PAT (no is_oauth2) during the refresh window.
	// Local config is the source of truth: write-back must refuse to clobber it.
	patCfg := "hosts:\n  gitlab.com:\n    token: glpat-user-pat\n"
	if err := os.WriteFile(cfg, []byte(patCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	newTok := &oauth2.Token{AccessToken: "mine", RefreshToken: "rt2"} //nolint:exhaustruct // test.
	_, err := writeBackGlabConfig(cfg, "gitlab.com", "rt1", newTok)
	if !errors.Is(err, errGitLabHostNotOAuth) {
		t.Fatalf("err = %v, want errGitLabHostNotOAuth", err)
	}
	got, _ := os.ReadFile(cfg)
	if !strings.Contains(string(got), "glpat-user-pat") || strings.Contains(string(got), "mine") {
		t.Fatalf("must not have overwritten the user's PAT:\n%s", got)
	}
}

func TestWriteBackGlabConfig_RefusesHostWithoutToken(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	// Host node remains but its token was removed/blanked (e.g. the user logged out).
	original := "hosts:\n  gitlab.com:\n    is_oauth2: true\n"
	if err := os.WriteFile(cfg, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	newTok := &oauth2.Token{AccessToken: "minted", RefreshToken: "rt2"} //nolint:exhaustruct // test.
	_, err := writeBackGlabConfig(cfg, "gitlab.com", "rt1", newTok)
	if !errors.Is(err, errGitLabHostNotOAuth) {
		t.Fatalf("err = %v, want errGitLabHostNotOAuth", err)
	}
	got, _ := os.ReadFile(cfg)
	if string(got) != original || strings.Contains(string(got), "minted") {
		t.Fatalf("config must be unchanged (no minted token written):\n%s", got)
	}
}

func TestWriteBackGlabConfig_RebaseKeepsConcurrentUnrelatedEdit(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	// Same refresh token (rt1) as prev, but an unrelated host was added → rebase
	// onto latest, keep the added host, write our token.
	concurrentCfg := "hosts:\n  gitlab.com:\n    token: old\n    oauth2_refresh_token: rt1\n    is_oauth2: true\n" +
		"  added.com:\n    token: concurrent\n"
	if err := os.WriteFile(cfg, []byte(concurrentCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	newTok := &oauth2.Token{AccessToken: "fresh", RefreshToken: "rt2"} //nolint:exhaustruct // test.
	// Disk refresh token unchanged (rt1) since the snapshot → rebase + write.
	if _, err := writeBackGlabConfig(cfg, "gitlab.com", "rt1", newTok); err != nil {
		t.Fatalf("writeBackGlabConfig: %v", err)
	}
	got, _ := os.ReadFile(cfg)
	if !strings.Contains(string(got), "concurrent") || !strings.Contains(string(got), "fresh") {
		t.Fatalf("rebase lost the concurrent edit:\n%s", got)
	}
}

func TestDirWriteProbe(t *testing.T) {
	dir := t.TempDir()
	if err := dirWriteProbe(filepath.Join(dir, "config.yml")); err != nil {
		t.Fatalf("dirWriteProbe on writable dir: %v", err)
	}
	if err := dirWriteProbe(filepath.Join(dir, "nope", "config.yml")); err == nil {
		t.Fatal("dirWriteProbe must fail on a non-existent directory")
	}
}

func TestDiscoverGitLabCredFrom_EnvWins(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == "GITLAB_TOKEN" {
			return "glpat-env", true
		}

		return "", false
	}
	cred, err := discoverGitLabCredFrom(lookup, "/cfg/config.yml", []byte(sampleGlabConfig), []string{"gitlab.com"})
	if err != nil || cred.AccessToken != "glpat-env" || cred.IsOAuth2 || cred.Host != "" {
		t.Fatalf("cred=%+v err=%v, want env PAT", cred, err)
	}
	if cred.ConfigPath != "" {
		t.Fatalf("env PAT must not carry a ConfigPath, got %q", cred.ConfigPath)
	}
}

func TestDiscoverGitLabCredFrom_ConfigFallback(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	cred, err := discoverGitLabCredFrom(lookup, "/cfg/config.yml", []byte(sampleGlabConfig),
		[]string{"missing.com", "gitlab.com"})
	if err != nil || cred.AccessToken != "glpat-ABC" || !cred.IsOAuth2 || cred.Host != "gitlab.com" {
		t.Fatalf("cred=%+v err=%v, want oauth config cred", cred, err)
	}
	if cred.ConfigPath != "/cfg/config.yml" {
		t.Fatalf("config cred must carry the source path, got %q", cred.ConfigPath)
	}
}

func TestBuildGitLabProvider_StaticForPAT(t *testing.T) {
	p, err := buildGitLabProvider(GitLabHardeningConfig{Host: "gitlab.com"}, "gitlab.com", //nolint:exhaustruct // min.
		glabCredential{AccessToken: "glpat-x"}) //nolint:exhaustruct // PAT.
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := p.tokenSource.Token()
	if err != nil || tok.AccessToken != "glpat-x" {
		t.Fatalf("tok=%+v err=%v, want static PAT", tok, err)
	}
	if _, ok := p.tokenSource.(*glabOAuthSource); ok {
		t.Fatal("PAT must not get a refreshing source")
	}
}

func TestBuildGitLabProvider_OAuthGetsRefreshingSource(t *testing.T) {
	p, err := buildGitLabProvider(
		GitLabHardeningConfig{Host: "gitlab.com"},
		"gitlab.com", //nolint:exhaustruct // min.
		glabCredential{
			Host:         "gitlab.com",
			AccessToken:  "acc",
			RefreshToken: "ref",
			IsOAuth2:     true,
		},
	) //nolint:exhaustruct // oauth.
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	src, ok := p.tokenSource.(*glabOAuthSource)
	if !ok {
		t.Fatalf("tokenSource is %T, want *glabOAuthSource", p.tokenSource)
	}
	if src.clientID != gitlabDefaultClientID {
		t.Fatalf("clientID = %q, want default", src.clientID)
	}
}

func TestProbeConfigRefreshable(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("hosts:\n  gitlab.com:\n    token: t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeConfigRefreshable(cfg); err != nil {
		t.Fatalf("readable file + writable dir: %v", err)
	}
	// Missing file → fail-closed (EvalSymlinks fails).
	if err := probeConfigRefreshable(filepath.Join(dir, "nope.yml")); err == nil {
		t.Fatal("missing config must fail the probe")
	}
}

func TestProbeConfigRefreshable_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := probeConfigRefreshable(cfg); err == nil {
		t.Fatal("unreadable config must fail the probe (so refresh is not attempted)")
	}
}
