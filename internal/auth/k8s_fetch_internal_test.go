package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

func reqInfoListPods() k8sauthz.RequestInfo {
	return k8sauthz.RequestInfo{ //nolint:exhaustruct // only the fields the matcher reads.
		IsResourceRequest: true,
		Verb:              "list",
		Resource:          "pods",
	}
}

func TestFetchViewPolicyIntegration(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != clusterRolePath("view") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		const body = `{"kind":"ClusterRole","rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list","watch"]}]}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	hc := srv.Client() // trusts the test server's CA.
	inject := func(req *http.Request) error {
		req.Header.Set("Authorization", "Bearer test-token")
		return nil
	}

	vp, err := fetchViewPolicy(context.Background(), hc, srv.URL, "view", inject)
	if err != nil {
		t.Fatalf("fetchViewPolicy: %v", err)
	}
	if !vp.Allows(reqInfoListPods()) {
		t.Fatal("fetched policy should allow list pods")
	}
}

func TestFetchViewPolicyAccessDenied(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchViewPolicy(context.Background(), srv.Client(), srv.URL, "view", func(*http.Request) error {
		return nil
	})
	if !errors.Is(err, ErrClusterAccessDenied) {
		t.Fatalf("403 should map to ErrClusterAccessDenied, got %v", err)
	}
}

func TestFetchViewPolicyServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchViewPolicy(context.Background(), srv.Client(), srv.URL, "view", func(*http.Request) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if errors.Is(err, ErrClusterAccessDenied) {
		t.Fatalf("500 must not be ErrClusterAccessDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "fetch status 500") {
		t.Fatalf("want generic status error, got %v", err)
	}
}

func TestClusterHTTPClient_PropagatesBuildError(t *testing.T) {
	t.Parallel()

	// pinnedHTTPClient is shell (gate-exempt); this guards that it hands its
	// args to buildClusterTLSConfig and passes the helper's error through.
	_, err := pinnedHTTPClient("not-base64-!!", "", "", "", nil)
	if err == nil || !strings.Contains(err.Error(), "k8s_hardening: decode cluster CA:") {
		t.Fatalf("want decode cluster CA error, got %v", err)
	}
}

func TestFetchViewPolicyInjectError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	injectErr := errors.New("credential expired")
	_, err := fetchViewPolicy(context.Background(), srv.Client(), srv.URL, "view", func(*http.Request) error {
		return injectErr
	})
	if !errors.Is(err, injectErr) {
		t.Fatalf("expected inject error, got: %v", err)
	}
}

func TestFetchViewPolicyStatusBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Kubernetes returns 200 with a Status object when RBAC silently denies access.
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"forbidden"}`))
	}))
	defer srv.Close()

	_, err := fetchViewPolicy(context.Background(), srv.Client(), srv.URL, "view", func(*http.Request) error {
		return nil
	})
	if !errors.Is(err, k8sauthz.ErrUnclassifiable) {
		t.Fatalf("expected ErrUnclassifiable for Status body, got: %v", err)
	}
}
