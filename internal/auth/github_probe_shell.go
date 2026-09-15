package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	ghAuth "github.com/cli/go-gh/v2/pkg/auth"

	"github.com/cynative/cynative/internal/outbound"
)

// resolveGithubToken resolves the gh token, bounding go-gh's keyring `gh`
// subprocess via ctx (a canceled parent or the registration timeout aborts the
// wait). The result channel is buffered so the spawned goroutine never blocks on
// send and exits when TokenForHost returns; a hung `gh` therefore abandons exactly
// one goroutine, bounded by the subprocess's own lifetime. Returns (_, false, nil)
// for a genuinely absent token and (_, false, err) when ctx fires first. NOTE:
// go-gh's TokenForHost(host) returns (token, source) — NOT an error — so the `_`
// discards the SOURCE; the resolver's only err source is ctx.Done() (a hung-keyring
// resolution timeout). The hung goroutine is abandoned, not cancelled (go-gh has no
// ctx-aware API) — accepted. Shell I/O.
func resolveGithubToken(ctx context.Context) (string, bool, error) {
	type res struct {
		token   string
		present bool
	}

	ch := make(chan res, 1)
	go func() {
		token, _ := ghAuth.TokenForHost("github.com")
		ch <- res{token, token != ""}
	}()

	select {
	case r := <-ch:
		return r.token, r.present, nil
	case <-ctx.Done():
		return "", false, fmt.Errorf("github_hardening: token resolution: %w", ctx.Err())
	}
}

// guardedGithubClient builds the bootstrap transport for the github bearer-token
// probes: NO redirects (the bearer never follows a 3xx) and a dial guard via
// githubDialAllowed (public-global-unicast only — NOT isInternalIP, which permits
// CGNAT/benchmark ranges for private K8s), so a DNS-rebound api.github.com can never
// reach an internal/special-use address. An operator proxy replaces that guard
// with a pin to the proxy endpoint, as it does on the request path.
func guardedGithubClient(r outbound.Routing) (*http.Client, error) {
	control := dialControl(func(_ context.Context, ip netip.Addr) (bool, error) {
		return githubDialAllowed(ip), nil
	})

	route, err := RouteOutbound(r, githubUserURL, control)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{} //nolint:exhaustruct // only the route's dial config is set, below.
	route.Apply(tr, &net.Dialer{})

	return &http.Client{ //nolint:exhaustruct // only Transport + CheckRedirect set.
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// validateGithubToken is the production validation seam: the /user→/rate_limit
// fallback probe over the guarded client and the real GitHub URLs. Both URLs are
// on api.github.com, so one route covers the fallback too.
func validateGithubToken(ctx context.Context, r outbound.Routing, token string) (string, error) {
	hc, err := guardedGithubClient(r)
	if err != nil {
		return "", err
	}

	return githubValidate(ctx, hc, githubUserURL, githubRateLimitURL, token)
}
