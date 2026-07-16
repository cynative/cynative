package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestWithBoundedTokenRefresh_InjectsClientWithoutDeadline asserts the helper
// carries a bounded [http.Client] under the [oauth2.HTTPClient] key without adding
// a context deadline. The long-lived session credentials source that findGCP
// builds retains this context, so it must be bounded (the client) yet not poisoned
// (no fixed deadline).
func TestWithBoundedTokenRefresh_InjectsClientWithoutDeadline(t *testing.T) {
	t.Parallel()

	ctx := withBoundedTokenRefresh(context.Background())

	hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || hc == nil {
		t.Fatalf("oauth2.HTTPClient value = %v, want a non-nil *http.Client", ctx.Value(oauth2.HTTPClient))
	}
	if hc.Timeout != gcpTokenRefreshOverallTimeout {
		t.Errorf("Client.Timeout = %v, want %v", hc.Timeout, gcpTokenRefreshOverallTimeout)
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Error("withBoundedTokenRefresh must not add a deadline (a fixed deadline would poison the retained source)")
	}
}

// TestBoundedTokenRefreshClient_SetsTimeouts asserts the production refresh client
// carries the overall backstop and the response-header phase timeout, and honors
// the proxy (so enterprise egress that [http.DefaultTransport] allowed still works).
func TestBoundedTokenRefreshClient_SetsTimeouts(t *testing.T) {
	t.Parallel()

	hc := boundedTokenRefreshClient()
	if hc.Timeout != gcpTokenRefreshOverallTimeout {
		t.Errorf("Client.Timeout = %v, want overall backstop %v", hc.Timeout, gcpTokenRefreshOverallTimeout)
	}

	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", hc.Transport)
	}
	if tr.ResponseHeaderTimeout != gcpTokenRefreshResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, gcpTokenRefreshResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout != gcpTokenRefreshTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, gcpTokenRefreshTLSHandshakeTimeout)
	}
	if tr.Proxy == nil {
		t.Error("Proxy must be honored so a token refresh still traverses a configured egress proxy")
	}
}

// TestBoundedTokenRefresh_StalledResponseBodyIsBounded is the end-to-end proof: an
// oauth2 token source constructed under a context carrying the bounded client
// returns promptly with an error instead of blocking forever when the token
// endpoint flushes response headers and then stalls the body. That is exactly the
// case [http.DefaultTransport] (dial/TLS timeouts only, no response-header or
// overall timeout) leaves unbounded, so an otherwise contextless
// [oauth2.TokenSource.Token] would wedge indefinitely.
func TestBoundedTokenRefresh_StalledResponseBodyIsBounded(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-block
	}))
	t.Cleanup(func() { close(block); srv.Close() })

	// A small overall backstop keeps the test fast; the response-header timeout is
	// loose so the OVERALL Client.Timeout is what must end the stalled-body refresh.
	client := boundedTokenRefreshClientWithTimeouts(200*time.Millisecond, 5*time.Second)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	cfg := &oauth2.Config{ //nolint:exhaustruct // only Endpoint is relevant to a refresh.
		Endpoint: oauth2.Endpoint{ //nolint:exhaustruct // token URL only.
			TokenURL:  srv.URL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: "refresh"}) //nolint:exhaustruct // forces a refresh.

	start := time.Now()
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected an overall-timeout error on the stalled token-refresh body, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stalled refresh took %v; the bounded client did not bound it", elapsed)
	}
}

// TestBoundedTokenRefresh_StalledResponseHeadersAreBounded covers the header-stall
// case: a token endpoint that completes the TLS handshake and reads the request
// but never writes a response header is ended by the response-header phase timeout.
func TestBoundedTokenRefresh_StalledResponseHeadersAreBounded(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })

	// A tight response-header timeout with a loose overall backstop so the phase
	// timeout is what ends the wait.
	client := boundedTokenRefreshClientWithTimeouts(5*time.Second, 150*time.Millisecond)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	cfg := &oauth2.Config{ //nolint:exhaustruct // only Endpoint is relevant to a refresh.
		Endpoint: oauth2.Endpoint{ //nolint:exhaustruct // token URL only.
			TokenURL:  srv.URL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: "refresh"}) //nolint:exhaustruct // forces a refresh.

	start := time.Now()
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected a response-header timeout on the stalled response, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled headers took %v; ResponseHeaderTimeout did not bound the refresh", elapsed)
	}
}
