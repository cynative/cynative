package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// maxGithubOpenAPIBytes caps the bundled-spec download (~12 MB live; 16 MiB
// headroom).
const maxGithubOpenAPIBytes = 16 << 20

// newGithubOpenAPIFetcher returns a fetcher that downloads the raw OpenAPI over
// the dedicated bootstrap client. It deliberately bypasses the gated transport
// (raw.githubusercontent.com is not a pinned host and InjectAuth would otherwise
// attach the gh token), mirroring the K8s ClusterRole bootstrap fetch.
func newGithubOpenAPIFetcher() func(ctx context.Context) ([]byte, error) {
	client := buildGithubFetchClient()
	return func(ctx context.Context) ([]byte, error) {
		return fetchGithubOpenAPI(ctx, client)
	}
}

// newGithubOpenAPIRequest builds the anonymous GET for the OpenAPI. It sets no
// Authorization header — the gh token must never reach the CDN. It lives in the
// shell: NewRequestWithContext with the constant URL has an unreachable error
// branch the 100% core gate cannot cover.
func newGithubOpenAPIRequest(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubOpenAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github_hardening: build openapi request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// fetchGithubOpenAPI performs the size-capped anonymous GET.
func fetchGithubOpenAPI(ctx context.Context, client *http.Client) ([]byte, error) {
	req, err := newGithubOpenAPIRequest(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github_hardening: fetch openapi: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github_hardening: fetch openapi: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGithubOpenAPIBytes))
	if err != nil {
		return nil, fmt.Errorf("github_hardening: read openapi: %w", err)
	}
	return body, nil
}
