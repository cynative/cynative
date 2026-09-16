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
// (non-empty) credential. It returns (nil, error) when the served host is one
// [AdmitHost] refuses (validateGitLabHosts) or a configured ca_cert is
// unreadable, both of which gitlabOutcome surfaces as a visible unavailable
// status, and (provider, nil) otherwise. gitlabOutcome admits the same
// authority before it discovers the credential, so on that path this is the
// second of two checks; it sits here so the rule does not rest on the caller.
// The token source is static for an env/PAT credential and a caching
// glab-helper source for a glab OAuth credential (newTokenSource).
func buildGitLabProvider(
	cfg GitLabHardeningConfig, host string, cred glabCredential, e *Egress,
) (*gitlabProvider, error) {
	if err := validateGitLabHosts(host, cfg.APIHost); err != nil {
		return nil, err
	}

	caData, err := readCACertBase64(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	p := &gitlabProvider{ //nolint:exhaustruct // tokenSource set below.
		host: host, apiHost: cfg.APIHost,
		allowPrivateNetwork: cfg.AllowPrivateNetwork,
		caData:              caData, resolver: defaultResolveAddrs,
		egress:   e,
		exposure: gitlabclass.BuildExposure(cfg.Permissions),
		tables: cache.NewTableCache(cfg.Config, newGitLabOpenAPIFetcher(e),
			gitlabclass.DistillOpenAPI, (*gitlabclass.Table).Serialize,
			gitlabclass.UnmarshalTable, gitlabclass.AdmitTable),
	}

	p.tokenSource = newTokenSource(p, cred)

	return p, nil
}

// buildProbeClient constructs the pinned HTTP client used for the eager /user
// validation and the OAuth refresh POST: routed by the egress policy,
// dial-guarded on the direct path, configured CA, and fail-closed on redirects.
func buildProbeClient(p *gitlabProvider) (*http.Client, error) {
	route, err := p.egress.RouteEndpoint("https://" + p.servedHost())
	if err != nil {
		return nil, fmt.Errorf("%w: route: %w", errGitLabProbe, err)
	}

	hc, err := pinnedHTTPClient(p.caData, "", "", "", route, dialControl(p.authorizesDialIP))
	if err != nil {
		return nil, fmt.Errorf("%w: build client: %w", errGitLabProbe, err)
	}

	return hc, nil
}

// validateGitLabToken eagerly validates the token at registration via a
// dial-guarded GET /api/v4/user (which authenticates a PAT, project/group, OR
// OAuth token) and returns the authenticating username for the inventory identity.
// It builds its own pinned probe client; the caller bounds ctx. Shell I/O.
func validateGitLabToken(ctx context.Context, p *gitlabProvider) (string, error) {
	accessToken, err := p.currentToken() // triggers the first credential-helper resolution for a glab OAuth cred.
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
