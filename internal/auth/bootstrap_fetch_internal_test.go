package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestBootstrapDialAuthorizer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ip   string
		want bool
	}{
		{"140.82.112.3", true},     // public IP → allowed.
		{"127.0.0.1", false},       // loopback → denied.
		{"10.0.0.5", false},        // RFC1918 → denied.
		{"169.254.169.254", false}, // metadata → denied.
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(c.ip)
			got, err := bootstrapDialAuthorizer(context.Background(), ip)
			if err != nil {
				t.Fatalf("bootstrapDialAuthorizer(%s) err %v", c.ip, err)
			}
			if got != c.want {
				t.Errorf("bootstrapDialAuthorizer(%s) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

func TestBuildBootstrapFetchClient_rejectsRedirects(t *testing.T) {
	t.Parallel()

	c := buildBootstrapFetchClient(githubFetchTimeout)
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect = nil, want a no-follow policy")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect err = %v, want ErrUseLastResponse", err)
	}
	if c.Timeout != githubFetchTimeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, githubFetchTimeout)
	}
}

// TestNewBootstrapSpecRequest_noToken builds each connector's request and
// verifies method, scheme, no Authorization header, and the Accept header. The
// anonymity of the spec fetch is the security property. No network is involved.
func TestNewBootstrapSpecRequest_noToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		url        string
		accept     string
		wantAccept string
	}{
		{"github", githubOpenAPIURL, githubFetchAccept, "application/json"},
		{"gitlab", gitlabOpenAPIURL, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			req, err := newBootstrapSpecRequest(context.Background(), c.url, c.accept, c.name)
			if err != nil {
				t.Fatalf("newBootstrapSpecRequest: %v", err)
			}
			if req.Method != http.MethodGet {
				t.Errorf("method = %s, want GET", req.Method)
			}
			if req.URL.Scheme != "https" {
				t.Errorf("scheme = %s, want https", req.URL.Scheme)
			}
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("Authorization = %q, want empty (no token to the spec host)", got)
			}
			if got := req.Header.Get("Accept"); got != c.wantAccept {
				t.Errorf("Accept = %q, want %q", got, c.wantAccept)
			}
		})
	}
}

func TestNewBootstrapSpecRequest_badURL(t *testing.T) {
	t.Parallel()

	_, err := newBootstrapSpecRequest(context.Background(), "://bad", "", "github_hardening")
	if err == nil || !strings.Contains(err.Error(), "github_hardening: build openapi request") {
		t.Fatalf("err = %v, want prefixed build error", err)
	}
}

// specRoundTripFunc fakes the bootstrap client transport so every fetch branch
// is exercised hermetically (the real dial guard denies loopback).
type specRoundTripFunc func(*http.Request) (*http.Response, error)

func (f specRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// specClient builds an [http.Client] over a fake transport.
func specClient(rt specRoundTripFunc) *http.Client {
	return &http.Client{Transport: rt} //nolint:exhaustruct // fake transport only.
}

// errReader fails on the first Read to exercise the read-error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func specResponse(status int, body io.Reader) *http.Response {
	return &http.Response{ //nolint:exhaustruct // minimal fake response.
		StatusCode: status,
		Body:       io.NopCloser(body),
	}
}

// TestFetchBootstrapSpec_success drives a fresh fetch for each connector through
// a fake transport and pins, on the wire the transport actually sees, that the
// request carries no Authorization header (the anonymity property) and exactly
// the Accept the connector configures: application/json for github, none for
// gitlab.
func TestFetchBootstrapSpec_success(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		url        string
		accept     string
		wantAccept string
	}{
		{"github", githubOpenAPIURL, githubFetchAccept, "application/json"},
		{"gitlab", gitlabOpenAPIURL, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var got *http.Request
			client := specClient(func(r *http.Request) (*http.Response, error) {
				got = r
				return specResponse(http.StatusOK, strings.NewReader("spec-bytes")), nil
			})
			fetch := newBootstrapSpecFetcher(client, c.url, c.accept, c.name)

			body, err := fetch(context.Background())
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if string(body) != "spec-bytes" {
				t.Errorf("body = %q, want spec-bytes", body)
			}
			if got.Header.Get("Authorization") != "" {
				t.Error("Authorization sent on the wire, want anonymous")
			}
			if got.Header.Get("Accept") != c.wantAccept {
				t.Errorf("Accept on the wire = %q, want %q", got.Header.Get("Accept"), c.wantAccept)
			}
		})
	}
}

func TestFetchBootstrapSpec_errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
		rt   specRoundTripFunc
		want string
	}{
		{
			"bad url", "://bad",
			func(*http.Request) (*http.Response, error) { return nil, errors.New("unreachable") },
			"gitlab_hardening: build openapi request",
		},
		{
			"transport error", gitlabOpenAPIURL,
			func(*http.Request) (*http.Response, error) { return nil, errors.New("conn refused") },
			"gitlab_hardening: fetch openapi",
		},
		{
			"non-200 status", gitlabOpenAPIURL,
			func(*http.Request) (*http.Response, error) {
				return specResponse(http.StatusNotFound, strings.NewReader("")), nil
			},
			"gitlab_hardening: fetch openapi: status 404",
		},
		{
			"read error", gitlabOpenAPIURL,
			func(*http.Request) (*http.Response, error) {
				return specResponse(http.StatusOK, errReader{}), nil
			},
			"gitlab_hardening: read openapi",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			_, err := fetchBootstrapSpec(context.Background(), specClient(c.rt), c.url, "", "gitlab_hardening")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

// TestConnectorFetcherConstructors pins the per-connector constructors: non-nil
// fetchers over the dedicated bootstrap client. They are NOT invoked (invoking
// would hit the network; the dial guard blocks loopback).
func TestConnectorFetcherConstructors(t *testing.T) {
	t.Parallel()

	if newGithubOpenAPIFetcher() == nil {
		t.Error("newGithubOpenAPIFetcher() = nil, want non-nil func")
	}
	if newGitLabOpenAPIFetcher() == nil {
		t.Error("newGitLabOpenAPIFetcher() = nil, want non-nil func")
	}
}
