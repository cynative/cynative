package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/apiref"
)

// tokenTrap is a credential source that fails the test if anything asks it for a token.
type tokenTrap struct{ t *testing.T }

func (s tokenTrap) Token() (*oauth2.Token, error) {
	s.t.Error("the api_reference path minted a GCP token")
	return nil, errors.New("token trap")
}

// TestBuildHardenedGCPProvider_WiresDocsOutsideTheBootstrap pins the production wiring: the provider leaves the
// constructor with its docs store already set, before and without the lazy credential bootstrap, and the store
// downloads through the egress policy the catalog's client uses, with no credential. The proxy below sees the
// docs fetch as a CONNECT and refuses it, so nothing leaves the machine.
func TestBuildHardenedGCPProvider_WiresDocsOutsideTheBootstrap(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var connects []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connects = append(connects, r.Method+" "+r.URL.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	e, err := NewEgress(func(k string) (string, bool) {
		if k == "HTTPS_PROXY" {
			return proxy.URL, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := GCPHardeningConfig{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now, Role: "roles/viewer"}
	p := buildHardenedGCPProvider(tokenTrap{t: t}, cfg, e)
	p.doLazyResolve = noBootstrap(t)
	if p.docs == nil {
		t.Fatal("the docs store is not set at construction")
	}
	res := p.Reference(t.Context(), apiref.Query{Connector: "gcp", Operation: "compute.instances.list"})
	if res.Outcome != apiref.OutcomeUnavailable {
		t.Errorf("reference through a refusing proxy = %+v, want unavailable", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(connects, "CONNECT discovery.googleapis.com:443") {
		t.Errorf("proxy saw %q, want the Discovery directory fetch", connects)
	}
}
