package azure_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

// TestNewSpecsHTTPClient_NeverFollowsARedirect pins that the specs client hands a redirect back unfollowed.
func TestNewSpecsHTTPClient_NeverFollowsARedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			t.Error("the redirect was followed")
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	base := srv.Client()
	c := azurehardening.NewSpecsHTTPClient(base)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/start", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || base.CheckRedirect != nil {
		t.Fatalf("status %d; base client modified: %v", resp.StatusCode, base.CheckRedirect != nil)
	}
}

// TestNewSpecsHTTPClient_CarriesNoCookies pins that the specs client drops the base client's cookie jar, so the
// anonymous fetches send no cookie, and that the base keeps its own.
func TestNewSpecsHTTPClient_CarriesNoCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := &http.Client{Jar: jar}
	if c := azurehardening.NewSpecsHTTPClient(base); c.Jar != nil || base.Jar != jar {
		t.Fatalf("specs client jar = %v; base jar kept: %v", c.Jar, base.Jar == jar)
	}
}
