package auth

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// tlsServerCABase64 returns the base64-PEM leaf certificate of an httptest TLS
// server, in the form BuildTLSConfig expects, so a pinnedHTTPClient can trust it.
func tlsServerCABase64(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	return base64.StdEncoding.EncodeToString(pemBytes)
}

func noInject(*http.Request) error { return nil }

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
	// args to BuildTLSConfig and passes the helper's error through.
	_, err := pinnedHTTPClient("not-base64-!!", "", "", "", nil)
	if err == nil || !strings.Contains(err.Error(), "failed to decode CA certificate") {
		t.Fatalf("want decode cluster CA error, got %v", err)
	}
}

func TestFetchViewPolicy_StalledTLSHandshakeIsBounded(t *testing.T) {
	t.Parallel()

	// A raw TCP listener that accepts and never speaks TLS: the dial succeeds, the
	// TLS handshake stalls. With a deadline-free context, only the client's
	// TLSHandshakeTimeout can end it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverDone := make(chan struct{})
	t.Cleanup(func() { close(serverDone); _ = ln.Close() })

	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		<-serverDone // hold the connection open, stalling the handshake.
	}()

	to := k8sFetchTimeouts{
		dial: time.Second, tlsHandshake: 150 * time.Millisecond, responseHeader: time.Second, overall: 5 * time.Second,
	}
	hc, err := pinnedHTTPClientWithTimeouts("", "", "", "", to, nil)
	if err != nil {
		t.Fatalf("pinnedHTTPClientWithTimeouts: %v", err)
	}

	// The backstop deadline is far longer than the timeout under test, so a
	// regression that drops TLSHandshakeTimeout fails fast here instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = fetchViewPolicy(ctx, hc, "https://"+ln.Addr().String(), "view", noInject)
	if err == nil {
		t.Fatal("expected a TLS-handshake timeout on the stalled connection, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled TLS handshake took %v; TLSHandshakeTimeout did not bound the fetch", elapsed)
	}
}

func TestFetchViewPolicy_StalledResponseHeadersAreBounded(t *testing.T) {
	t.Parallel()

	// A TLS server that completes the handshake and reads the request but never
	// responds: only the client's ResponseHeaderTimeout can end it.
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })

	to := k8sFetchTimeouts{
		dial: 2 * time.Second, tlsHandshake: 2 * time.Second,
		responseHeader: 150 * time.Millisecond, overall: 5 * time.Second,
	}
	hc, err := pinnedHTTPClientWithTimeouts(tlsServerCABase64(t, srv), "", "", "", to, nil)
	if err != nil {
		t.Fatalf("pinnedHTTPClientWithTimeouts: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = fetchViewPolicy(ctx, hc, srv.URL, "view", noInject)
	if err == nil {
		t.Fatal("expected a response-header timeout on the stalled response, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled headers took %v; ResponseHeaderTimeout did not bound the fetch", elapsed)
	}
}

func TestFetchViewPolicy_StalledResponseBodyIsBounded(t *testing.T) {
	t.Parallel()

	// A TLS server that flushes the response headers and then stalls mid-body: the
	// phase timeouts do not cover the body read, so only the overall Client.Timeout
	// backstop can end it.
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-block
	}))
	t.Cleanup(func() { close(block); srv.Close() })

	to := k8sFetchTimeouts{
		dial: 2 * time.Second, tlsHandshake: 2 * time.Second,
		responseHeader: 2 * time.Second, overall: 200 * time.Millisecond,
	}
	hc, err := pinnedHTTPClientWithTimeouts(tlsServerCABase64(t, srv), "", "", "", to, nil)
	if err != nil {
		t.Fatalf("pinnedHTTPClientWithTimeouts: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = fetchViewPolicy(ctx, hc, srv.URL, "view", noInject)
	if err == nil {
		t.Fatal("expected an overall-timeout on the stalled body, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled body took %v; the overall Client.Timeout did not bound the fetch", elapsed)
	}
}

func TestPinnedHTTPClient_SetsPhaseTimeouts(t *testing.T) {
	t.Parallel()

	// Without explicit dial/TLS/response-header/overall timeouts a stalled cluster
	// endpoint wedges the bootstrap fetch even under a deadline-free context.
	hc, err := pinnedHTTPClient("", "", "", "", nil)
	if err != nil {
		t.Fatalf("pinnedHTTPClient: %v", err)
	}

	want := defaultK8sFetchTimeouts()
	if hc.Timeout != want.overall {
		t.Errorf("Client.Timeout = %v, want overall backstop %v", hc.Timeout, want.overall)
	}

	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", hc.Transport)
	}
	if tr.TLSHandshakeTimeout != want.tlsHandshake {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, want.tlsHandshake)
	}
	if tr.ResponseHeaderTimeout != want.responseHeader {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, want.responseHeader)
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
