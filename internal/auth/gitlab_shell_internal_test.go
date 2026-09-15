package auth

import (
	"errors"
	"testing"
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
		wantErr bool
	}{
		{"ASCII host is built", "gitlab.example", "", false},
		{"non-ASCII served host is refused", "g\u0130tlab.example", "", true},
		{"non-ASCII served api host is refused", "gitlab.example", "api.g\u0130tlab.example", true},
		// The served authority is api_host when it is set, so a non-ASCII host
		// behind an ASCII api_host leaves nothing non-ASCII on the wire.
		{
			"non-ASCII host behind an ASCII api host is built",
			"gitlab.b\u00fccher.example", "gitlab.xn--bcher-kva.example", false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := GitLabHardeningConfig{Host: tc.host, APIHost: tc.apiHost}
			cred := glabCredential{AccessToken: "glpat-test"}

			p, err := buildGitLabProvider(cfg, tc.host, cred)

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("buildGitLabProvider(%q, %q) = %v, want a provider", tc.host, tc.apiHost, err)
				}
				if p == nil {
					t.Fatalf("buildGitLabProvider(%q, %q) returned a nil provider and no error", tc.host, tc.apiHost)
				}

				return
			}

			if !errors.Is(err, ErrNonASCIIHost) {
				t.Fatalf("buildGitLabProvider(%q, %q) = %v, want ErrNonASCIIHost", tc.host, tc.apiHost, err)
			}
			if p != nil {
				t.Fatalf("buildGitLabProvider(%q, %q) returned a provider alongside %v", tc.host, tc.apiHost, err)
			}
		})
	}
}
