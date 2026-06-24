package auth

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

func TestGithubDialAuthorizer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ip   string
		want bool
	}{
		{"140.82.112.3", true},     // public GitHub IP → allowed.
		{"127.0.0.1", false},       // loopback → denied.
		{"10.0.0.5", false},        // RFC1918 → denied.
		{"169.254.169.254", false}, // metadata → denied.
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(c.ip)
			got, err := githubDialAuthorizer(context.Background(), ip)
			if err != nil {
				t.Fatalf("githubDialAuthorizer(%s) err %v", c.ip, err)
			}
			if got != c.want {
				t.Errorf("githubDialAuthorizer(%s) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

func TestBuildGithubFetchClient_rejectsRedirects(t *testing.T) {
	t.Parallel()

	c := buildGithubFetchClient()
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect = nil, want a no-follow policy")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect err = %v, want ErrUseLastResponse", err)
	}
	if c.Timeout == 0 {
		t.Error("Timeout = 0, want a bounded timeout")
	}
}
