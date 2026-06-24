package auth

import (
	"context"
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
)

// githubDialAuthorizer denies dials to internal IPs (loopback/link-local/RFC1918/
// metadata) so the un-gated bootstrap fetch cannot be SSRF'd via DNS rebinding.
func githubDialAuthorizer(_ context.Context, ip netip.Addr) (bool, error) {
	return !isInternalIP(ip), nil
}

// buildGithubFetchClient builds the dedicated bootstrap client: dial-guarded,
// redirect-refusing, timeout-bounded, with no shared/default transport.
func buildGithubFetchClient() *http.Client {
	tr := &http.Transport{ //nolint:exhaustruct // only dial control configured; Proxy intentionally nil.
		DialContext: (&net.Dialer{ //nolint:exhaustruct // only ControlContext configured.
			ControlContext: dialControl(githubDialAuthorizer),
		}).DialContext,
	}
	return &http.Client{ //nolint:exhaustruct // only Transport/Timeout/CheckRedirect set.
		Timeout:   githubFetchTimeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
