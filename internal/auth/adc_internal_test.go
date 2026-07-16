package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestBoundedADCContext_ThreadsBoundedClient pins the wiring: boundedADCContext
// threads an [http.Client] via the oauth2.HTTPClient context key with the given
// Client.Timeout. Using a per-request Client.Timeout (not a context deadline) is
// what keeps the long-lived registered credentials source from being poisoned:
// each refresh gets a fresh timeout, the context never expires.
func TestBoundedADCContext_ThreadsBoundedClient(t *testing.T) {
	t.Parallel()

	ctx := boundedADCContext(context.Background(), 42*time.Second)

	hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		t.Fatal("boundedADCContext did not thread an *http.Client via the oauth2.HTTPClient context key")
	}
	if hc.Timeout != 42*time.Second {
		t.Fatalf("client timeout = %v, want 42s", hc.Timeout)
	}
	if _, deadlineSet := ctx.Deadline(); deadlineSet {
		t.Fatal("boundedADCContext set a context deadline; it must bound via Client.Timeout only (no poisoning)")
	}
}

// TestBoundedADCContext_BoundsStalledTokenRefresh pins the fix: an oauth2 token
// refresh minted from a boundedADCContext honors the client timeout even against
// a token endpoint that accepts the connection and then never responds. Without
// the bound the refresh uses [http.DefaultClient] (no timeout) and ts.Token()
// blocks forever, since TokenSource.Token takes no context to cancel it.
func TestBoundedADCContext_BoundsStalledTokenRefresh(t *testing.T) {
	t.Parallel()

	// A token endpoint that stalls: the request arrives, TLS/handshake complete,
	// and the response never comes (blackholed token endpoint).
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // client gave up (its bounded timeout fired).
		case <-block: // teardown fallback.
		}
	}))
	// LIFO cleanup: close(block) runs first so any stuck handler unblocks before
	// srv.Close (which waits for outstanding requests) runs.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	cfg := &oauth2.Config{ //nolint:exhaustruct // token endpoint only.
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams},
	}
	// An already-expired token forces a refresh against the stalled endpoint.
	ts := cfg.TokenSource(
		boundedADCContext(context.Background(), 150*time.Millisecond),
		&oauth2.Token{RefreshToken: "refresh", Expiry: time.Unix(1, 0)}, //nolint:exhaustruct // refresh path only.
	)

	done := make(chan error, 1)
	go func() {
		_, err := ts.Token()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the stalled token refresh to be bounded, got a token")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("token refresh was not bounded by the ADC client timeout (still hung after 5s)")
	}
}
