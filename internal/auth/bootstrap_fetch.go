package auth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	// githubOpenAPIURL is GitHub's first-party bundled REST OpenAPI on the public
	// CDN. main floats so the taxonomy stays current; the admission guard anchors
	// the security-critical routes (see internal/auth/github).
	githubOpenAPIURL = "https://raw.githubusercontent.com/github/rest-api-description/" +
		"main/descriptions/api.github.com/api.github.com.json"
	// githubFetchTimeout bounds the one-shot bundled-spec download.
	githubFetchTimeout = 30 * time.Second
	// githubFetchAccept pins the JSON representation of the bundled spec.
	githubFetchAccept = "application/json"

	// gitlabOpenAPIURL is GitLab's auto-generated REST OpenAPI v3 in the monorepo.
	// master floats so the taxonomy stays current; the admission guard anchors the
	// ci-variables family (see internal/auth/gitlab). The same spec governs
	// gitlab.com and self-managed instances (a self-managed version lag may
	// over-deny renamed endpoints: fail-closed, documented). The raw host serves
	// the body directly (HTTP 200, no redirect to a CDN), so the fetch is a plain
	// GET.
	gitlabOpenAPIURL = "https://gitlab.com/gitlab-org/gitlab/-/raw/master/doc/api/openapi/openapi_v3.yaml"
	// gitlabFetchTimeout bounds the one-shot spec download (the spec is ~3.3 MB).
	gitlabFetchTimeout = 60 * time.Second

	// bootstrapSpecMaxBytes caps each spec read (github ~12 MB live, gitlab
	// ~3.3 MB; 16 MiB headroom).
	bootstrapSpecMaxBytes = 16 << 20
)

// newGithubOpenAPIFetcher returns a fetcher that downloads the raw OpenAPI over
// the dedicated bootstrap client. It deliberately bypasses the gated transport
// (raw.githubusercontent.com is not a pinned host and InjectAuth would otherwise
// attach the gh token), mirroring the K8s ClusterRole bootstrap fetch.
func newGithubOpenAPIFetcher() func(ctx context.Context) ([]byte, error) {
	return newBootstrapSpecFetcher(
		buildBootstrapFetchClient(githubFetchTimeout), githubOpenAPIURL, githubFetchAccept, "github_hardening",
	)
}

// newGitLabOpenAPIFetcher returns a fetcher that downloads the raw OpenAPI v3
// YAML over the dedicated dial-guarded bootstrap client (gitlab.com is not a
// pinned host and the gitlab provider's InjectAuth must not run for this
// anonymous fetch). https-only, no-redirect, size-capped.
func newGitLabOpenAPIFetcher() func(ctx context.Context) ([]byte, error) {
	return newBootstrapSpecFetcher(
		buildBootstrapFetchClient(gitlabFetchTimeout), gitlabOpenAPIURL, "", "gitlab_hardening",
	)
}

// bootstrapDialAuthorizer denies dials to internal IPs (loopback/link-local/
// RFC1918/metadata) so the un-gated bootstrap fetches cannot be SSRF'd via DNS
// rebinding.
func bootstrapDialAuthorizer(_ context.Context, ip netip.Addr) (bool, error) {
	return !isInternalIP(ip), nil
}

// buildBootstrapFetchClient builds a dedicated bootstrap client: dial-guarded,
// redirect-refusing, timeout-bounded, with no shared/default transport.
func buildBootstrapFetchClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{ //nolint:exhaustruct // only dial control configured; Proxy intentionally nil.
		DialContext: (&net.Dialer{ //nolint:exhaustruct // only ControlContext configured.
			ControlContext: dialControl(bootstrapDialAuthorizer),
		}).DialContext,
	}
	return &http.Client{ //nolint:exhaustruct // only Transport/Timeout/CheckRedirect set.
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newBootstrapSpecFetcher binds a client and per-connector constants into the
// fetcher shape the table sources consume.
func newBootstrapSpecFetcher(
	client *http.Client, url, accept, errPrefix string,
) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return fetchBootstrapSpec(ctx, client, url, accept, errPrefix)
	}
}

// newBootstrapSpecRequest builds the anonymous GET for a spec. It sets no
// Authorization header (the connector token must never reach the spec host)
// and sets Accept only when the connector pins one.
func newBootstrapSpecRequest(ctx context.Context, url, accept, errPrefix string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build openapi request: %w", errPrefix, err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req, nil
}

// fetchBootstrapSpec performs the size-capped anonymous GET.
func fetchBootstrapSpec(ctx context.Context, client *http.Client, url, accept, errPrefix string) ([]byte, error) {
	req, err := newBootstrapSpecRequest(ctx, url, accept, errPrefix)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: fetch openapi: %w", errPrefix, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: fetch openapi: status %d", errPrefix, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, bootstrapSpecMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: read openapi: %w", errPrefix, err)
	}
	return body, nil
}
