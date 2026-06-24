package redact_test

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedactPreservingLocation_DumpForm preserves a signed Location URL in an
// httputil.DumpResponse blob (the model-egress / direct-path form) while still
// redacting a non-Location secret elsewhere in the response.
func TestRedactPreservingLocation_DumpForm(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := "HTTP/2.0 302 Found\r\n" +
		"Location: https://objects.githubusercontent.com/x?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/us-east-1" +
		"&X-Amz-Signature=abc123def456&X-Amz-Security-Token=FwoToken\r\n" +
		`Body: {"password":"hunter2"}` + "\r\n"
	out := r.RedactPreservingLocation(in)

	for _, want := range []string{"X-Amz-Credential=AKIAIOSFODNN7EXAMPLE", "X-Amz-Signature=abc123def456", "X-Amz-Security-Token=FwoToken"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Location URL not preserved (missing %q):\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || !strings.Contains(out, "[REDACTED:credential-field]") {
		t.Fatalf("non-Location secret not redacted:\n%s", out)
	}
	if strings.Contains(out, "cynative-loc-") || strings.ContainsRune(out, '\x00') {
		t.Fatalf("sentinel leaked into output: %q", out)
	}
}

// TestRedactPreservingLocation_JSONForm preserves a signed Location URL in a
// JSON-marshaled [http.Header] (the sandbox / ExecuteStructured form) while
// redacting a github token embedded in the body.
func TestRedactPreservingLocation_JSONForm(t *testing.T) {
	t.Parallel()

	r := redact.New()
	token := "ghp_" + strings.Repeat("a", 36)
	in := `{"Status":302,"Headers":{"Location":["https://codeload.github.com/x?X-Amz-Signature=sigABC123"]},` +
		`"Body":"tok ` + token + `"}`
	out := r.RedactPreservingLocation(in)

	if !strings.Contains(out, "X-Amz-Signature=sigABC123") {
		t.Fatalf("JSON Location signature not preserved:\n%s", out)
	}
	if strings.Contains(out, token) || !strings.Contains(out, "[REDACTED:github-token]") {
		t.Fatalf("non-Location github token not redacted:\n%s", out)
	}
}

// TestRedactPreservingLocation_RelativeForms preserves scheme-relative ("//host…")
// and root-relative ("/path?sig=…") redirect Locations, while a bare secret on a
// Location line (no leading "/" or scheme) is still redacted.
func TestRedactPreservingLocation_RelativeForms(t *testing.T) {
	t.Parallel()

	r := redact.New()
	for _, loc := range []string{
		"/download/asset?X-Amz-Signature=relsig123",        // root-relative
		"//cdn.example.com/x?X-Amz-Signature=schemesig456", // scheme-relative
	} {
		if got := r.RedactPreservingLocation("Location: " + loc); !strings.Contains(got, loc) {
			t.Fatalf("relative Location not preserved: %q -> %q", loc, got)
		}
	}
}

// TestRedactPreservingLocation_NonURLValueIsRedacted confirms a bare secret on a
// "Location:" line (not a redirect URL) is NOT preserved — only real https?://
// redirect URLs survive, so the carve-out cannot be abused as a bypass.
func TestRedactPreservingLocation_NonURLValueIsRedacted(t *testing.T) {
	t.Parallel()

	r := redact.New()
	tok := "ghp_" + strings.Repeat("a", 36)
	out := r.RedactPreservingLocation("Location: " + tok)
	if strings.Contains(out, tok) {
		t.Fatalf("non-URL Location value was preserved (bypass): %q", out)
	}
	if !strings.Contains(out, "[REDACTED:github-token]") {
		t.Fatalf("expected the bare token to be redacted: %q", out)
	}
}

// TestRedactPreservingLocation_NoLocationEqualsRedact confirms that, with no
// Location present, the method is identical to Redact (so it is a safe drop-in
// for tool-result content of any shape).
func TestRedactPreservingLocation_NoLocationEqualsRedact(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := `{"password":"hunter2","note":"no location here"}`
	if got, want := r.RedactPreservingLocation(in), r.Redact(in); got != want {
		t.Fatalf("with no Location: want %q, got %q", want, got)
	}
}
