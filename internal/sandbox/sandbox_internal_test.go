package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// errSecretBoom is a static test sentinel whose message embeds a secret, to
// prove the error path is redacted (the named-var + [errors.New] pattern matches
// the existing errTest sentinel and is lint-clean).
var errSecretBoom = errors.New("failure with SECRET inside")

// fakeRedact replaces the literal "SECRET" with a marker, standing in for the
// real redactor so the test asserts the redact seam is applied at every sink.
func fakeRedact(s string) string {
	return strings.ReplaceAll(s, "SECRET", "[REDACTED]")
}

// identityRedact is the no-op redactor for tests that do not exercise
// redaction. New requires a non-nil redactor, so call sites pass this not nil.
func identityRedact(s string) string { return s }

func TestRunWorker_RedactsToolResult(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"leak": func(_ context.Context, _ string) (string, error) {
			return `{"token":"SECRET"}`, nil
		},
	}
	s, err := New(funcs, nil, 32*1024, DefaultMaxConcurrency, fakeRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `const r = await leak({}); console.log(r.token)`, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out, "SECRET") {
		t.Fatalf("raw secret reached JS/output: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redacted marker in output, got %q", out)
	}
}

func TestRunWorker_RedactsToolError(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		"boom": func(_ context.Context, _ string) (string, error) {
			return "", errSecretBoom
		},
	}
	s, err := New(funcs, nil, 32*1024, DefaultMaxConcurrency, fakeRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(),
		`try { await boom({}); } catch (e) { console.log(e.message); }`, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out, "SECRET") {
		t.Fatalf("raw secret reached JS error message: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redacted marker in error, got %q", out)
	}
}

func TestRunWorker_RedactsVerboseAndRawString(t *testing.T) {
	t.Parallel()

	var verbose strings.Builder
	funcs := map[string]ToolFunc{
		// Returns a non-JSON raw string — exercises toJSResult's raw-string branch.
		"raw": func(_ context.Context, _ string) (string, error) {
			return "plain SECRET text", nil
		},
	}
	s, err := New(funcs, &verbose, 32*1024, DefaultMaxConcurrency, fakeRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(), `console.log(await raw({}))`, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Raw-string result is redacted on the way to the script/output...
	if strings.Contains(out, "SECRET") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("raw-string result not redacted: %q", out)
	}
	// ...and the verbose log shows the redacted (not raw) result.
	if strings.Contains(verbose.String(), "SECRET") {
		t.Fatalf("verbose log leaked raw secret: %q", verbose.String())
	}
	if !strings.Contains(verbose.String(), "[REDACTED]") {
		t.Fatalf("verbose log missing redaction marker: %q", verbose.String())
	}
}

func TestRunWorker_RedactedJSONStaysParseable(t *testing.T) {
	t.Parallel()

	funcs := map[string]ToolFunc{
		// fakeRedact turns this into {"token":"[REDACTED]","ok":true} — still valid
		// JSON, so toJSResult parses it and the script can read .ok / .token.
		"obj": func(_ context.Context, _ string) (string, error) {
			return `{"token":"SECRET","ok":true}`, nil
		},
	}
	s, err := New(funcs, nil, 32*1024, DefaultMaxConcurrency, fakeRedact)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := s.Run(context.Background(),
		`const r = await obj({}); console.log(r.ok === true ? r.token : "PARSE_FAILED")`, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out, "PARSE_FAILED") {
		t.Fatalf("redacted JSON did not parse: %q", out)
	}
	if strings.Contains(out, "SECRET") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redacted token, got %q", out)
	}
}
