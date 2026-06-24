package auth

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	// gitlabOpenAPIURL is GitLab's auto-generated REST OpenAPI v3 in the monorepo.
	// master floats so the taxonomy stays current; the admission guard anchors the
	// ci-variables family (see internal/auth/gitlab). The same spec governs
	// gitlab.com and self-managed instances (a self-managed version lag may
	// over-deny renamed endpoints — fail-closed, documented). The raw host serves
	// the body directly (HTTP 200, no redirect to a CDN), so the shell is a plain
	// GET.
	gitlabOpenAPIURL = "https://gitlab.com/gitlab-org/gitlab/-/raw/master/doc/api/openapi/openapi_v3.yaml"
	// gitlabFetchTimeout bounds the one-shot spec download (the spec is ~3.3 MB).
	gitlabFetchTimeout = 60 * time.Second
	// gitlabSpecMaxBytes caps the spec read (the spec is ~3.3 MB; 16 MiB is ample).
	gitlabSpecMaxBytes = 16 << 20
)

// gitlabFetchDialAuthorizer denies dials to internal IPs so the un-gated
// bootstrap fetch cannot be SSRF'd via DNS rebinding.
func gitlabFetchDialAuthorizer(_ context.Context, ip netip.Addr) (bool, error) {
	return !isInternalIP(ip), nil
}

// buildGitLabFetchClient builds the dedicated bootstrap client: dial-guarded,
// redirect-refusing, timeout-bounded, with no shared/default transport. The raw
// host serves the body directly (200), so the shell is a plain size-capped GET.
func buildGitLabFetchClient() *http.Client {
	tr := &http.Transport{ //nolint:exhaustruct // only dial control configured; Proxy intentionally nil.
		DialContext: (&net.Dialer{ //nolint:exhaustruct // only ControlContext configured.
			ControlContext: dialControl(gitlabFetchDialAuthorizer),
		}).DialContext,
	}
	return &http.Client{ //nolint:exhaustruct // only Transport/Timeout/CheckRedirect set.
		Timeout:   gitlabFetchTimeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
