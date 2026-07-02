package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"

	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/cache"
)

// maxIntrospectBytes caps the eager /user validation response read.
const maxIntrospectBytes = 1 << 20 // 1 MiB.

// readGlabConfigWithPath returns the (path, bytes) of the first READABLE glab
// config.yml in glab's search order, or ("", nil) when none is readable. The path
// is threaded onto the credential so re-reads, the write-probe, and write-back all
// target the exact file the bytes came from (not a path that merely exists but is
// unreadable). Shell I/O.
func readGlabConfigWithPath() (string, []byte) {
	glabDir, _ := os.LookupEnv("GLAB_CONFIG_DIR")
	xdg, _ := os.LookupEnv("XDG_CONFIG_HOME")
	userCfg, _ := os.UserConfigDir() // "" on error → candidate skipped.

	return firstReadableConfig(glabConfigPaths(glabDir, xdg, userCfg, homeDirOrEmpty()), os.ReadFile)
}

// readCACertBase64 reads a PEM CA file and returns it base64-encoded, or
// ("", nil) when path is empty. A configured-but-unreadable path is an error.
func readCACertBase64(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	pem, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("gitlab: read ca_cert %q: %w", path, err)
	}

	return base64.StdEncoding.EncodeToString(pem), nil
}

// buildGitLabProvider constructs the gitlabProvider for an already-discovered
// (non-empty) credential. It returns (nil, error) when a configured ca_cert is
// unreadable — which gitlabOutcome surfaces as a visible unavailable status — and
// (provider, nil) otherwise. The token source is static for a PAT/env credential
// and a refreshing glabOAuthSource for a glab OAuth credential (newTokenSource).
func buildGitLabProvider(cfg GitLabHardeningConfig, host string, cred glabCredential) (*gitlabProvider, error) {
	caData, err := readCACertBase64(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	p := &gitlabProvider{ //nolint:exhaustruct // httpClientFactory left nil (defaulted at use).
		host: host, apiHost: cfg.APIHost,
		allowPrivateNetwork: cfg.AllowPrivateNetwork,
		caData:              caData, resolver: defaultResolveAddrs,
		exposure: gitlabclass.BuildExposure(cfg.Permissions),
		tables: cache.NewTableCache(cfg.Config, newGitLabOpenAPIFetcher(),
			gitlabclass.DistillOpenAPI, (*gitlabclass.Table).Serialize,
			gitlabclass.UnmarshalTable, gitlabclass.AdmitTable),
	}

	p.tokenSource = newTokenSource(p, cred)

	return p, nil
}

// buildProbeClient constructs the pinned HTTP client used for the eager /user
// validation and the OAuth refresh POST: dial-guarded, configured CA, and
// fail-closed on redirects.
func buildProbeClient(p *gitlabProvider) (*http.Client, error) {
	hc, err := pinnedHTTPClient(p.caData, "", "", "", dialControl(p.authorizesDialIP))
	if err != nil {
		return nil, fmt.Errorf("%w: build client: %w", errGitLabProbe, err)
	}

	// Match the main transport's fail-closed redirect policy: never follow a 30x,
	// so the Bearer token cannot be forwarded to a redirect target that bypasses
	// the connector's host/action gates.
	hc.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return hc, nil
}

// validateGitLabToken eagerly validates the token at registration via a
// dial-guarded GET /api/v4/user (which authenticates a PAT, project/group, OR
// OAuth token) and returns the authenticating username for the inventory identity.
// It builds its own pinned probe client; the caller bounds ctx. Shell I/O.
func validateGitLabToken(ctx context.Context, p *gitlabProvider) (string, error) {
	accessToken, err := p.currentToken() // triggers the first refresh + write-back for a stale OAuth token.
	if err != nil {
		return "", err
	}

	hc, err := buildProbeClient(p)
	if err != nil {
		return "", err
	}

	body, err := gitlabProbeBody(ctx, hc, p, "/api/v4/user", accessToken)
	if err != nil {
		return "", err
	}

	return parseGitLabUser(body)
}

// gitlabProbeBody issues a Bearer GET to path on the served host using hc and
// returns the 2xx response body. Used by the eager /user validation. Shell I/O;
// the body parse is a pure helper.
func gitlabProbeBody(
	ctx context.Context,
	hc *http.Client,
	p *gitlabProvider,
	path, accessToken string,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+p.servedHost()+path, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", errGitLabProbe, err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken) // Bearer works for PAT + OAuth tokens.
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGitLabProbe, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", errGitLabProbe, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: status %d", errGitLabProbe, resp.StatusCode)
	}

	return body, nil
}

// refreshClient returns the pinned HTTP client for the OAuth refresh POST: the
// injected factory in tests, else buildProbeClient (dial-guard + CA + no-redirect)
// with a concrete refresh timeout (the source binds a background ctx, so the
// timeout is the only per-refresh bound).
func refreshClient(p *gitlabProvider) (*http.Client, error) {
	if p.httpClientFactory != nil {
		return p.httpClientFactory()
	}
	hc, err := buildProbeClient(p)
	if err != nil {
		return nil, err
	}
	hc.Timeout = refreshTimeout

	return hc, nil
}
