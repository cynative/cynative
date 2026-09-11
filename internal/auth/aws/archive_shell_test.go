package aws_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	awsh "github.com/cynative/cynative/internal/auth/aws"
)

func TestNewModelArchiveFetcher_returnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tarball-bytes"))
	}))
	t.Cleanup(srv.Close)

	raw, err := awsh.NewModelArchiveFetcher(srv.Client(), srv.URL)(t.Context())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(raw) != "tarball-bytes" {
		t.Errorf("unexpected body %q", raw)
	}
}

func TestNewModelArchiveFetcher_nonOKStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	if _, err := awsh.NewModelArchiveFetcher(srv.Client(), srv.URL)(t.Context()); err == nil {
		t.Error("expected error on non-200")
	}
}

// errRoundTripper fails every request, so the transport-error branch is reached
// without a real dial. Closing a server to free its port and dialing it back is
// not hermetic: another listener can rebind the port and answer.
type errRoundTripper struct{ err error }

func (rt errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, rt.err }

func TestNewModelArchiveFetcher_networkFailureFails(t *testing.T) {
	dialErr := errors.New("dial failed")
	client := &http.Client{Transport: errRoundTripper{err: dialErr}}
	_, err := awsh.NewModelArchiveFetcher(client, "https://example.invalid/archive")(t.Context())
	if !errors.Is(err, dialErr) {
		t.Errorf("err = %v, want %v", err, dialErr)
	}
}
