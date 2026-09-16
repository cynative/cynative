package gcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestTokeninfoProberPrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"email":"me@example.com","email_verified":"true"}`))
	}))
	defer srv.Close()

	principal, err := gcphardening.ProbeTokeninfo(
		context.Background(), srv.Client(), srv.URL,
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "raw"}),
	)
	if err != nil {
		t.Fatalf("ProbeTokeninfo: %v", err)
	}
	if principal != "me@example.com" {
		t.Errorf("principal = %q, want me@example.com", principal)
	}
}

// TestNewIdentityProber_ConfiguredCredentials pins that a prober handed
// credentials describes those, not ADC: the tokeninfo call carries their token
// and the project is theirs. No ADC exists in the test environment, so a fall
// through to discovery would fail the probe.
func TestNewIdentityProber_ConfiguredCredentials(t *testing.T) {
	t.Parallel()

	var seenToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.URL.Query().Get("access_token")
		_, _ = w.Write([]byte(`{"email":"reader@bench.iam.gserviceaccount.com","email_verified":"true"}`))
	}))
	defer srv.Close()

	prober := gcphardening.NewIdentityProber(gcphardening.IdentityConfig{ //nolint:exhaustruct // scopes default.
		HTTPClient:   srv.Client(),
		TokeninfoURL: srv.URL,
		Credentials: &google.Credentials{ //nolint:exhaustruct // the facts the prober reads.
			ProjectID: "bench-project",
			JSON:      []byte(`{"type":"service_account","project_id":"bench-project"}`),
			TokenSource: oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: "configured"},
			), //nolint:exhaustruct // access.
		},
	})
	principal, project, err := prober.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if principal != "reader@bench.iam.gserviceaccount.com" || project != "bench-project" {
		t.Errorf("Probe = (%q, %q), want the configured credentials' identity", principal, project)
	}
	if seenToken != "configured" {
		t.Errorf("tokeninfo saw token %q, want the configured source's", seenToken)
	}
}
