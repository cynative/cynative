package outbound

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// errSelector is what a proxy selector reports when it cannot decide. The real
// one (x/net's httpproxy) only errors in CGI mode, which this package never
// configures, so the selector is exercised through its own seam here. The
// property under test is that an undecidable request is refused rather than
// quietly dialed direct, which would defeat an operator's controlled egress.
var errSelector = errors.New("selector broke")

func TestProxyFor_SelectorErrorDeniesAndRedactsTheTarget(t *testing.T) {
	t.Parallel()

	r := Routing{resolved: &resolved{
		endpoint: &url.URL{Scheme: "http", Host: "127.0.0.1:8080"},
		proxyFor: func(*url.URL) (*url.URL, error) { return nil, errSelector },
	}}

	target := (&url.URL{Scheme: "https", Host: "api.example", User: url.UserPassword("u", "hunter2")}).String()

	proxy, err := r.ProxyFor(target)
	if proxy != nil {
		t.Errorf("ProxyFor = %v, want nil on a selector error", proxy)
	}
	if !errors.Is(err, errSelector) {
		t.Fatalf("ProxyFor err = %v, want the selector error", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q must not carry the target's userinfo", err)
	}
}
