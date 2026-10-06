package auth

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestBuildGitLabProvider_ServedHostAdmission pins the ASCII admission of the
// served authority at the site that actually runs it. TestValidateGitLabHosts
// calls validateGitLabHosts directly and the registration tests replace the
// whole builder with a stub, so nothing else fails when the call in
// buildGitLabProvider is deleted.
//
// It needs no network and no filesystem: an empty CACertPath skips the CA read,
// and a non-OAuth credential makes newTokenSource a static token source.
func TestBuildGitLabProvider_ServedHostAdmission(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		host    string
		apiHost string
		want    error // nil when the provider is built.
	}{
		{"ASCII host is built", "gitlab.example", "", nil},
		{"non-ASCII served host is refused", "g\u0130tlab.example", "", ErrNonASCIIHost},
		{"non-ASCII served api host is refused", "gitlab.example", "api.g\u0130tlab.example", ErrNonASCIIHost},
		// A bracketed literal with no port reaches AdmitHost only once
		// stripHostPort has taken the brackets off, so these two are the rows
		// that prove the constructor guards the shape the CLI never produces.
		{"zoned served host with no port is refused", "[fe80::1%eth0]", "", ErrZonedHost},
		{"zoned served api host with no port is refused", "gitlab.example", "[fe80::1%25eth0]", ErrZonedHost},
		// The served authority is api_host when it is set, so a non-ASCII host
		// behind an ASCII api_host leaves nothing non-ASCII on the wire.
		{
			"non-ASCII host behind an ASCII api host is built",
			"gitlab.b\u00fccher.example", "gitlab.xn--bcher-kva.example", nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := GitLabHardeningConfig{Host: tc.host, APIHost: tc.apiHost}
			cred := glabCredential{AccessToken: "glpat-test"}

			p, err := buildGitLabProvider(cfg, tc.host, cred, NoProxy())

			if tc.want == nil {
				if err != nil {
					t.Fatalf("buildGitLabProvider(%q, %q) = %v, want a provider", tc.host, tc.apiHost, err)
				}
				if p == nil {
					t.Fatalf("buildGitLabProvider(%q, %q) returned a nil provider and no error", tc.host, tc.apiHost)
				}

				return
			}

			if !errors.Is(err, tc.want) {
				t.Fatalf("buildGitLabProvider(%q, %q) = %v, want %v", tc.host, tc.apiHost, err, tc.want)
			}
			if p != nil {
				t.Fatalf("buildGitLabProvider(%q, %q) returned a provider alongside %v", tc.host, tc.apiHost, err)
			}
		})
	}
}

// TestBuildGitLabProvider_WiresDocsCache pins the docs cache beside the table cache in the connector's cache
// directory. Nothing is fetched: both caches load lazily.
func TestBuildGitLabProvider_WiresDocsCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := GitLabHardeningConfig{Dir: dir, TTL: time.Hour, Clock: time.Now}
	p, err := buildGitLabProvider(cfg, "gitlab.example", glabCredential{AccessToken: "glpat-test"}, NoProxy())
	if err != nil {
		t.Fatal(err)
	}
	if p.docs.cache == nil || p.docs.cache.DataPath != filepath.Join(dir, "docs.json") ||
		p.tables.DataPath != filepath.Join(dir, "table.json") {
		t.Errorf("docs %+v tables %+v", p.docs.cache, p.tables)
	}
}

// TestNewGitLabProvider_OneDownloadFeedsBothCaches pins the handoff at the constructor: after the table loads, the
// docs load costs no second download, and a docs load never fills the table.
func TestNewGitLabProvider_OneDownloadFeedsBothCaches(t *testing.T) {
	t.Parallel()
	newProv := func(t *testing.T, fetches *atomic.Int32) *gitlabProvider {
		t.Helper()
		cfg := GitLabHardeningConfig{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now}
		fetch := func(context.Context) ([]byte, error) {
			fetches.Add(1)

			return []byte(gitlabDocsFixture), nil
		}
		p, err := newGitLabProvider(cfg, "gitlab.com", glabCredential{AccessToken: "glpat-test"}, NoProxy(), fetch)
		if err != nil {
			t.Fatal(err)
		}

		return p
	}
	t.Run("table first", func(t *testing.T) {
		t.Parallel()
		var fetches atomic.Int32
		p := newProv(t, &fetches)
		if p.tables.Get(t.Context()) == nil || p.docs.forReference(t.Context()) == nil {
			t.Fatal("a cache failed to load")
		}
		if n := fetches.Load(); n != 1 {
			t.Errorf("table then docs downloaded %d times, want 1", n)
		}
	})
	t.Run("docs first", func(t *testing.T) {
		t.Parallel()
		var fetches atomic.Int32
		p := newProv(t, &fetches)
		if p.docs.forReference(t.Context()) == nil || p.tables.Get(t.Context()) == nil {
			t.Fatal("a cache failed to load")
		}
		if n := fetches.Load(); n != 2 {
			t.Errorf("docs then table downloaded %d times, want 2: the table must not be served from the docs", n)
		}
	})
}

func TestNewGitLabProvider_UnreadableCACert(t *testing.T) {
	t.Parallel()
	cfg := GitLabHardeningConfig{CACertPath: filepath.Join(t.TempDir(), "missing.pem")}
	p, err := newGitLabProvider(cfg, "gitlab.example", glabCredential{AccessToken: "glpat-test"}, NoProxy(),
		func(context.Context) ([]byte, error) { return nil, errors.New("unused") })
	if err == nil || p != nil {
		t.Errorf("provider %v err %v", p, err)
	}
}
