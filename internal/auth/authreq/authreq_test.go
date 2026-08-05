package authreq_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// mustReq builds a request the way the transport does. It never sets the wire
// authority field: that is derived from the URL, and the view must take it
// from there.
func mustReq(t *testing.T, method, raw string) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, raw, nil)
	if err != nil {
		t.Fatalf("new request %q: %v", raw, err)
	}

	return req
}

func TestNewViewProjectsEveryField(t *testing.T) {
	t.Parallel()

	req := mustReq(t, http.MethodPost, "https://Api.GitHub.com:8443/repos/o/r%2Fx?a=1&b=2")
	req.Header.Set("X-Amz-Target", "Svc.Op")

	v := authreq.NewView(req, `{"k":"v"}`)

	for _, tc := range []struct{ name, got, want string }{
		{"Method", v.Method, http.MethodPost},
		{"Hostname", v.Hostname, "api.github.com"},
		{"Port", v.Port, "8443"},
		{"Path", v.Path, "/repos/o/r/x"},
		{"EscapedPath", v.EscapedPath, "/repos/o/r%2Fx"},
		{"RawQuery", v.RawQuery, "a=1&b=2"},
		{"Body", v.Body, `{"k":"v"}`},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}

	if got := v.Header.Get("X-Amz-Target"); got != "Svc.Op" {
		t.Errorf("Header.Get(X-Amz-Target) = %q, want %q", got, "Svc.Op")
	}
}

// TestNewViewIgnoresConflictingWireAuthority pins the projection chokepoint:
// the authority comes from the URL, never from the request's own authority
// field, so the two can never disagree in what a gate judges. This is the test
// that carries the weight the #246 lint pin loses when the gates stop taking a
// request at all.
func TestNewViewIgnoresConflictingWireAuthority(t *testing.T) {
	t.Parallel()

	req := mustReq(t, http.MethodGet, "https://api.github.com/user")
	setConflictingAuthority(req, "codeload.github.com:1234")

	v := authreq.NewView(req, "")

	if v.Hostname != "api.github.com" {
		t.Errorf("Hostname = %q, want %q (the URL must win)", v.Hostname, "api.github.com")
	}

	if v.Port != "" {
		t.Errorf("Port = %q, want %q (the URL carries no port)", v.Port, "")
	}
}

func TestNewViewClonesHeader(t *testing.T) {
	t.Parallel()

	req := mustReq(t, http.MethodGet, "https://api.github.com/user")
	req.Header.Set("X-Keep", "original")

	v := authreq.NewView(req, "")
	v.Header.Set("X-Keep", "mutated")
	v.Header.Set("X-Added", "new")

	if got := req.Header.Get("X-Keep"); got != "original" {
		t.Errorf("req.Header X-Keep = %q, want %q: a view mutation reached the wire request", got, "original")
	}

	if got := req.Header.Get("X-Added"); got != "" {
		t.Errorf("req.Header X-Added = %q, want empty: a view mutation reached the wire request", got)
	}
}

// TestNewViewPreservesNonCanonicalHeaderKeys pins what GitLab's Sudo check
// depends on: cloning keeps key spelling, so raw map iteration still sees a
// non-canonical key that Header.Get would miss.
func TestNewViewPreservesNonCanonicalHeaderKeys(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://gitlab.com/api/v4/user")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{"sudo": []string{"root"}}}

	v := authreq.NewView(req, "")

	var found bool

	for key := range v.Header {
		if key == "sudo" {
			found = true
		}
	}

	if !found {
		t.Error("non-canonical header key \"sudo\" did not survive projection")
	}
}

// TestNewViewNilHeader covers the normalization branch: a request built by
// composite literal can carry a nil header, and Header.Clone reports nil for
// it. Gates iterate the map, so it must be non-nil.
func TestNewViewNilHeader(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://api.github.com/user")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	v := authreq.NewView(&http.Request{Method: http.MethodGet, URL: u}, "")

	if v.Header == nil {
		t.Fatal("Header is nil, want an empty non-nil header")
	}

	if got := len(v.Header); got != 0 {
		t.Errorf("len(Header) = %d, want 0", got)
	}
}

func TestNewAuditView(t *testing.T) {
	t.Parallel()

	req := mustReq(t, http.MethodPatch, "https://api.github.com/repos/o/r%2Fx?a=1")

	av := authreq.NewAuditView(req)

	if av.Method != http.MethodPatch {
		t.Errorf("Method = %q, want %q", av.Method, http.MethodPatch)
	}

	if av.EscapedPath != "/repos/o/r%2Fx" {
		t.Errorf("EscapedPath = %q, want %q", av.EscapedPath, "/repos/o/r%2Fx")
	}
}
