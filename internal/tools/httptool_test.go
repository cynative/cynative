package tools_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authtest"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
	"github.com/cynative/cynative/internal/transport"
)

// tlsCertBase64 returns the base64-encoded PEM of an httptest TLS server's leaf cert.
func tlsCertBase64(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	return base64.StdEncoding.EncodeToString(pemBytes)
}

func TestNewHTTPRequestTool_Info(t *testing.T) {
	t.Parallel()

	tl, err := tools.NewHTTPRequestTool(nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	info := tl.Info()
	if info.Name != "http_request" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Params == nil {
		t.Fatal("expected parameter schema")
	}

	// The generated schema MUST describe the RequestArgs fields. Assert key
	// properties survive invopop's tag inference.
	raw, err := json.Marshal(info.Params)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	t.Logf("generated http_request schema: %s", raw)
	// Assert field names, the method enum values, and a field description all
	// survive invopop's struct-tag inference (the migration risk for this tool).
	for _, want := range []string{"method", "url", "auth_provider", "GET", "POST", "The HTTP method to use"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("schema missing %q; got: %s", want, raw)
		}
	}
}

func TestNewHTTPRequestTool_SchemaError(t *testing.T) {
	t.Parallel()

	_, err := tools.NewHTTPRequestTool(nil,
		tools.WithHTTPSchemaBuilder(func() (*jsonschema.Schema, error) {
			return nil, errors.New("schema build failed")
		}),
	)
	if err == nil {
		t.Fatal("expected error when schema generation fails")
	}
}

func TestHTTPRequestTool_InvokableRun_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}

	tl, _ := tools.NewHTTPRequestTool(providers)
	args, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})

	out, err := tl.Run(context.Background(), string(args))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "pong") {
		t.Errorf("output missing body: %s", out)
	}
}

func TestHTTPRequestTool_InvokableRun_BadJSON(t *testing.T) {
	t.Parallel()

	tl, _ := tools.NewHTTPRequestTool(nil)

	out, err := tl.Run(context.Background(), "not-json")
	if err != nil {
		t.Fatalf("execution errors should be returned as results, not Go errors: %v", err)
	}

	if !strings.Contains(out, "Error executing tool") {
		t.Errorf("expected error diagnostic in result, got: %q", out)
	}
}

func TestHTTPRequestTool_StructuredRun(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clusters":["a"]}`))
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}

	tl, err := tools.NewHTTPRequestTool(providers)
	if err != nil {
		t.Fatalf("NewHTTPRequestTool: %v", err)
	}

	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}

	out, err := sr.StructuredRun(
		context.Background(),
		fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL),
	)
	if err != nil {
		t.Fatalf("StructuredRun: %v", err)
	}

	var got transport.Response
	if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
		t.Fatalf("result is not JSON: %v (%q)", uerr, out)
	}
	if got.Status != http.StatusOK || got.Body != `{"clusters":["a"]}` {
		t.Errorf("structured = %+v", got)
	}
}

func TestHTTPRequestTool_StructuredRun_TransportError(t *testing.T) {
	t.Parallel()

	tl, err := tools.NewHTTPRequestTool(nil)
	if err != nil {
		t.Fatalf("NewHTTPRequestTool: %v", err)
	}

	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}

	// Bad JSON arguments cause transport.ExecuteStructured to return an error.
	_, err = sr.StructuredRun(context.Background(), "not-json")
	if err == nil {
		t.Fatal("expected error for bad JSON arguments")
	}
}

func TestHTTPRequestTool_StructuredRun_MarshalError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}

	tl, err := tools.NewHTTPRequestTool(providers,
		tools.WithHTTPMarshalJSON(func(any) ([]byte, error) {
			return nil, errors.New("marshal failed")
		}),
	)
	if err != nil {
		t.Fatalf("NewHTTPRequestTool: %v", err)
	}

	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}

	_, err = sr.StructuredRun(
		context.Background(),
		fmt.Sprintf(`{"method":"GET","url":%q,"auth_provider":"loopback"}`, srv.URL),
	)
	if err == nil {
		t.Fatal("expected error when marshalJSON fails")
	}
	if !strings.Contains(err.Error(), "marshal structured response") {
		t.Errorf("error message = %q, want to contain %q", err.Error(), "marshal structured response")
	}
}

func TestHTTPRequestTool_Run_MarksFailedOnServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403
	}))
	defer srv.Close()

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	tl, _ := tools.NewHTTPRequestTool(providers)
	args, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})

	ctx, fail := audit.WithFailure(context.Background())
	if _, err := tl.Run(ctx, string(args)); err != nil {
		t.Fatalf("Run returned a Go error: %v", err)
	}
	if !fail.Failed() {
		t.Errorf("a 403 response must mark the call failed")
	}
}

func TestHTTPRequestTool_Run_DoesNotMarkFailedOn2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	tl, _ := tools.NewHTTPRequestTool(providers)
	args, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})

	ctx, fail := audit.WithFailure(context.Background())
	if _, err := tl.Run(ctx, string(args)); err != nil {
		t.Fatalf("Run returned a Go error: %v", err)
	}
	if fail.Failed() {
		t.Errorf("a 200 response must not mark the call failed")
	}
	if fail.Progress() == 0 {
		t.Errorf("a 200 response must mark progress (a useful outcome)")
	}
}

func TestHTTPRequestTool_StructuredRun_MarksFailedOnServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403
	}))
	defer srv.Close()

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	tl, _ := tools.NewHTTPRequestTool(providers)
	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}
	args, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})

	ctx, fail := audit.WithFailure(context.Background())
	if _, err := sr.StructuredRun(ctx, string(args)); err != nil {
		t.Fatalf("StructuredRun returned a Go error: %v", err)
	}
	if !fail.Failed() {
		t.Errorf("a 403 on the structured (code_execution) path must mark the call failed")
	}
}

func TestHTTPRequestTool_StructuredRun_DoesNotMarkFailedOn2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	providers := []auth.Provider{&authtest.LoopbackProvider{CACert: tlsCertBase64(t, srv)}}
	tl, _ := tools.NewHTTPRequestTool(providers)
	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}
	args, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL, "auth_provider": "loopback"})

	ctx, fail := audit.WithFailure(context.Background())
	if _, err := sr.StructuredRun(ctx, string(args)); err != nil {
		t.Fatalf("StructuredRun returned a Go error: %v", err)
	}
	if fail.Failed() {
		t.Errorf("a 200 response must not mark the call failed")
	}
}

func TestHTTPRequestTool_StructuredRun_MarksFailedOnTransportError(t *testing.T) {
	t.Parallel()

	tl, err := tools.NewHTTPRequestTool(nil)
	if err != nil {
		t.Fatalf("NewHTTPRequestTool: %v", err)
	}
	sr, ok := tl.(schema.StructuredRunner)
	if !ok {
		t.Fatalf("http_request does not implement StructuredRunner")
	}

	ctx, fail := audit.WithFailure(context.Background())
	if _, serr := sr.StructuredRun(ctx, "not-json"); serr == nil { // bad args → ExecuteStructured error.
		t.Fatal("expected an error for bad JSON arguments")
	}
	if !fail.Failed() {
		t.Error("a transport/argument error on the structured path must mark the call failed")
	}
}

func assertRequiredSet(t *testing.T, where string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if !slices.Equal(g, w) {
		t.Errorf("%s required = %v, want %v", where, g, w)
	}
}

func TestNewHTTPRequestTool_RequiredFields(t *testing.T) {
	t.Parallel()

	tl, err := tools.NewHTTPRequestTool(nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	info := tl.Info()

	// Top level: only method, url, auth_provider are required.
	assertRequiredSet(t, "<root>", info.Params.Required, []string{"method", "url", "auth_provider"})

	// Each nested auth object requires only its genuinely-needed sub-fields.
	wantNested := map[string][]string{
		"aws_auth":        {"service"}, // region is now optional (derived from host).
		"eks_auth":        {"cluster_name"},
		"gke_auth":        {"cluster_name", "location", "project"},
		"gcp_auth":        {"service"}, // location is now optional (derived from host).
		"azure_auth":      {"service"},
		"aks_auth":        {"cluster_name", "resource_group", "subscription_id"},
		"kubernetes_auth": {},
	}
	for name, want := range wantNested {
		prop, ok := info.Params.Properties.Get(name)
		if !ok {
			t.Fatalf("schema missing property %q", name)
		}
		assertRequiredSet(t, name, prop.Required, want)
	}
}
