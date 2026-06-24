package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// newGitLabOpenAPIFetcher returns a fetcher that downloads the raw OpenAPI v3
// YAML over the dedicated dial-guarded bootstrap client (gitlab.com is not a
// pinned host and the gitlab provider's InjectAuth must not run for this
// anonymous fetch). https-only, no-redirect, size-capped. The raw host serves
// the body directly (HTTP 200), so this is a plain GET.
func newGitLabOpenAPIFetcher() func(ctx context.Context) ([]byte, error) {
	client := buildGitLabFetchClient()
	return func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, gitlabOpenAPIURL, nil)
		if err != nil {
			return nil, fmt.Errorf("gitlab_hardening: build openapi request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gitlab_hardening: fetch openapi: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("gitlab_hardening: openapi fetch status %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, gitlabSpecMaxBytes))
	}
}
