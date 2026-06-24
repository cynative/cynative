package gcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// DefaultTokeninfoURL is the OAuth2 tokeninfo endpoint. //nolint:gosec // URL, not a credential.
const DefaultTokeninfoURL = "https://oauth2.googleapis.com/tokeninfo" //nolint:gosec // URL, not a credential.

// defaultIdentityTimeout is the HTTP client timeout for the tokeninfo probe.
const defaultIdentityTimeout = 30 * time.Second

// defaultCloudPlatformScope is the ADC scope used when probing credentials.
const defaultCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// IdentityConfig configures the real identity prober.
type IdentityConfig struct {
	HTTPClient   *http.Client
	TokeninfoURL string
	Scopes       []string
}

// realMetadata adapts cloud.google.com/go/compute/metadata to metadataProber.
type realMetadata struct{}

func (realMetadata) OnGCE() bool { return metadata.OnGCE() }

func (realMetadata) Email(ctx context.Context) (string, error) {
	return metadata.EmailWithContext(ctx, "default")
}

func (realMetadata) ProjectID(ctx context.Context) (string, error) {
	return metadata.ProjectIDWithContext(ctx)
}

type realIdentity struct {
	client       *http.Client
	tokeninfoURL string
	scopes       []string
	md           metadataProber
}

// NewIdentityProber builds the real ADC identity prober. Excluded from the gate.
func NewIdentityProber(cfg IdentityConfig) identityProber {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultIdentityTimeout} //nolint:exhaustruct // defaults fine
	}
	if cfg.TokeninfoURL == "" {
		cfg.TokeninfoURL = DefaultTokeninfoURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{defaultCloudPlatformScope}
	}
	return &realIdentity{client: cfg.HTTPClient, tokeninfoURL: cfg.TokeninfoURL, scopes: cfg.Scopes, md: realMetadata{}}
}

// Probe resolves the ADC principal email and the caller's project ID. The
// credential type is computed internally to detect the metadata/attached-SA
// case but is not returned (Layer-2 + host pinning do not need it).
func (r *realIdentity) Probe(ctx context.Context) (string, string, error) {
	creds, err := google.FindDefaultCredentials(ctx, r.scopes...)
	if err != nil {
		return "", "", fmt.Errorf("find default credentials: %w", err)
	}
	facts := credFacts{credJSON: creds.JSON, projectID: creds.ProjectID}
	return resolveIdentity(ctx, facts, r.md, func(ctx context.Context) (string, error) {
		return ProbeTokeninfo(ctx, r.client, r.tokeninfoURL, creds.TokenSource)
	})
}

// ProbeTokeninfo resolves a principal email from a token source via the
// tokeninfo endpoint. Exported for the shell integration test.
func ProbeTokeninfo(
	ctx context.Context,
	client *http.Client,
	tokeninfoURL string,
	ts oauth2.TokenSource,
) (string, error) {
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("source token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokeninfoURL+"?access_token="+tok.AccessToken, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return principalFromTokeninfo(body, resp.StatusCode)
}
