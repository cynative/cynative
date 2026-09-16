package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
)

func TestGuardedGithubClient(t *testing.T) {
	t.Parallel()

	c := guardedGithubClient(NoProxy())
	if !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("guarded client must refuse redirects")
	}

	// The client is bound once to the route of githubUserURL and then used for
	// githubRateLimitURL as well, so the two must name the same host: a proxied
	// policy would otherwise send the rate-limit probe down the /user route.
	if user, rate := mustURL(githubUserURL), mustURL(githubRateLimitURL); user.Host != rate.Host {
		t.Fatalf("probe URLs name different hosts: %q and %q", user.Host, rate.Host)
	}

	tr, _ := c.Transport.(*http.Transport)
	for _, ip := range []string{"169.254.169.254", "10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "fc00::1", "100.64.0.1"} {
		// Assert the dial-guard sentinel, not just any error: a broken guard that
		// let the dial through would still fail with a real connect error and pass
		// an err==nil check — errors.Is(ErrAddrNotAuthorized) proves it fired pre-connect.
		_, err := tr.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, "443"))
		if !errors.Is(err, ErrAddrNotAuthorized) {
			t.Errorf("guarded dial to internal %s = %v, want ErrAddrNotAuthorized", ip, err)
		}
	}
}
