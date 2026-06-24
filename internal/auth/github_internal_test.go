package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func githubTestServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestDoGithubUser(t *testing.T) {
	t.Parallel()

	t.Run("200 returns login, nil", func(t *testing.T) {
		t.Parallel()
		srv := githubTestServer(t, http.StatusOK, `{"login":"octocat"}`)
		login, err := doGithubUser(context.Background(), srv.Client(), srv.URL, "tok")
		if err != nil || login != "@octocat" {
			t.Fatalf("got (%q,%v), want (@octocat,nil)", login, err)
		}
	})

	t.Run("200 unparseable body still nil with empty login", func(t *testing.T) {
		t.Parallel()
		srv := githubTestServer(t, http.StatusOK, `not json`)
		login, err := doGithubUser(context.Background(), srv.Client(), srv.URL, "tok")
		if err != nil || login != "" {
			t.Fatalf("got (%q,%v), want (\"\",nil)", login, err)
		}
	})

	t.Run("401 returns githubStatusError", func(t *testing.T) {
		t.Parallel()
		srv := githubTestServer(t, http.StatusUnauthorized, ``)
		_, err := doGithubUser(context.Background(), srv.Client(), srv.URL, "tok")
		var se *githubStatusError
		if !errors.As(err, &se) || se.HTTPStatusCode() != http.StatusUnauthorized {
			t.Fatalf("want *githubStatusError 401, got %v", err)
		}
	})

	t.Run("build error on bad url", func(t *testing.T) {
		t.Parallel()
		_, err := doGithubUser(context.Background(), http.DefaultClient, "http://\x7f", "tok")
		if err == nil {
			t.Fatal("want build error")
		}
	})

	t.Run("transport error on closed server", func(t *testing.T) {
		t.Parallel()
		srv := githubTestServer(t, http.StatusOK, `{}`)
		url := srv.URL
		srv.Close()
		_, err := doGithubUser(context.Background(), http.DefaultClient, url, "tok")
		if err == nil {
			t.Fatal("want transport error")
		}
	})
}

func TestDoGithubRateLimit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		status    int
		wantErr   bool
		transient bool
	}{
		{"200 ok", http.StatusOK, false, false},
		{"401 definitive", http.StatusUnauthorized, true, false},
		{"403 definitive", http.StatusForbidden, true, false},
		{"429 transient", http.StatusTooManyRequests, true, true},
		{"503 transient", http.StatusServiceUnavailable, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := githubTestServer(t, tc.status, ``)
			err := doGithubRateLimit(context.Background(), srv.Client(), srv.URL, "tok")
			if (err != nil) != tc.wantErr {
				t.Fatalf("status %d: err=%v wantErr=%v", tc.status, err, tc.wantErr)
			}
			if tc.wantErr && isTransientProbeErr(err) != tc.transient {
				t.Fatalf("status %d: transient=%v want %v", tc.status, isTransientProbeErr(err), tc.transient)
			}
		})
	}

	t.Run("build error", func(t *testing.T) {
		t.Parallel()
		if err := doGithubRateLimit(context.Background(), http.DefaultClient, "http://\x7f", "t"); err == nil {
			t.Fatal("want build error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		t.Parallel()
		srv := githubTestServer(t, http.StatusOK, ``)
		url := srv.URL
		srv.Close()
		if err := doGithubRateLimit(context.Background(), http.DefaultClient, url, "t"); err == nil {
			t.Fatal("want transport error")
		}
	})
}

func githubDualServer(t *testing.T, userStatus int, userBody string, rlStatus int) (*httptest.Server, *int) {
	t.Helper()
	var rlHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.WriteHeader(userStatus)
			_, _ = w.Write([]byte(userBody))
		case "/rate_limit":
			rlHits++
			w.WriteHeader(rlStatus)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	return srv, &rlHits
}

func TestGithubValidate(t *testing.T) {
	t.Parallel()

	t.Run("user 200 → login, no fallback", func(t *testing.T) {
		t.Parallel()
		srv, rlHits := githubDualServer(t, http.StatusOK, `{"login":"octocat"}`, http.StatusOK)
		login, err := githubValidate(context.Background(), srv.Client(), srv.URL+"/user", srv.URL+"/rate_limit", "t")
		if err != nil || login != "@octocat" || *rlHits != 0 {
			t.Fatalf("got (%q,%v) rlHits=%d; want (@octocat,nil,0)", login, err, *rlHits)
		}
	})

	t.Run("user 401 → rate_limit 200 → register, empty identity", func(t *testing.T) {
		t.Parallel()
		srv, rlHits := githubDualServer(t, http.StatusUnauthorized, ``, http.StatusOK)
		login, err := githubValidate(context.Background(), srv.Client(), srv.URL+"/user", srv.URL+"/rate_limit", "t")
		if err != nil || login != "" || *rlHits != 1 {
			t.Fatalf("got (%q,%v) rlHits=%d; want (\"\",nil,1)", login, err, *rlHits)
		}
	})

	t.Run("user 403 → rate_limit 200 → register (rate-limited /user)", func(t *testing.T) {
		t.Parallel()
		srv, _ := githubDualServer(t, http.StatusForbidden, ``, http.StatusOK)
		_, err := githubValidate(context.Background(), srv.Client(), srv.URL+"/user", srv.URL+"/rate_limit", "t")
		if err != nil {
			t.Fatalf("want nil (fallback ok), got %v", err)
		}
	})

	t.Run("user 401 → rate_limit 401 → invalid", func(t *testing.T) {
		t.Parallel()
		srv, _ := githubDualServer(t, http.StatusUnauthorized, ``, http.StatusUnauthorized)
		_, err := githubValidate(context.Background(), srv.Client(), srv.URL+"/user", srv.URL+"/rate_limit", "t")
		var se *githubStatusError
		if !errors.As(err, &se) || se.HTTPStatusCode() != http.StatusUnauthorized {
			t.Fatalf("want *githubStatusError 401, got %v", err)
		}
	})
}

func TestGithubDialAllowed(t *testing.T) {
	t.Parallel()

	denied := []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "168.63.129.16", // metadata
		"10.0.0.1", "192.168.1.1", "172.16.0.1", // RFC1918
		"fc00::1", "fd00::1", // ULA
		"100.64.0.1", "100.127.255.254", // CGNAT
		"198.18.0.1", "198.19.255.254", // benchmarking
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"224.0.0.1", "239.0.0.1", // multicast
		"0.0.0.0", "0.1.2.3", // unspecified + "this network" (0.0.0.0/8)
		"240.0.0.1", "255.255.255.255", // reserved/future + broadcast
		"192.88.99.1",        // 6to4 relay anycast (deprecated)
		"64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254 (metadata) — embedded internal v4.
		"64:ff9b::a00:1",     // NAT64 of 10.0.0.1 (RFC1918) — embedded internal v4.
		"2002:0a00:0001::",   // 6to4 of 10.0.0.1 (RFC1918) — embedded internal v4.
		"2002:a9fe:a9fe::",   // 6to4 of 169.254.169.254 (metadata) — embedded internal v4.
	}
	for _, s := range denied {
		if githubDialAllowed(netip.MustParseAddr(s)) {
			t.Errorf("githubDialAllowed(%s) = true, want false (must deny)", s)
		}
	}

	// 2606:50c0::153 (a real github GUA, not an IPv4-embedding IPv6 address) and
	// 64:ff9b::8c52:7906 (NAT64 of public 140.82.121.6 — MUST stay allowed so an
	// IPv6-only/DNS64 host can still reach public api.github.com).
	allowed := []string{"140.82.121.6", "20.205.243.166", "2606:50c0::153", "64:ff9b::8c52:7906"}
	for _, s := range allowed {
		if !githubDialAllowed(netip.MustParseAddr(s)) {
			t.Errorf("githubDialAllowed(%s) = false, want true (public)", s)
		}
	}
}
