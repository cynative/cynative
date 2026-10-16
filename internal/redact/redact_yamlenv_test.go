package redact_test

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedact_YAMLCredentialFields redacts credential-named keys in YAML line form
// ("key: value") — the kubeconfig / k8s-manifest shape an operator pipes.
func TestRedact_YAMLCredentialFields(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := "apiVersion: v1\n" +
		"    token: kubeconfig-opaque-token-xyz\n" +
		"    password: hunter2supersecret\n" +
		"    client-key-data: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS1tb3Jl\n" +
		"    name: not-a-secret\n"
	out := r.Redact(in)

	for _, leaked := range []string{"kubeconfig-opaque-token-xyz", "hunter2supersecret", "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS1tb3Jl"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("YAML secret not redacted (%q present):\n%s", leaked, out)
		}
	}
	// Non-credential keys and the YAML structure are preserved.
	if !strings.Contains(out, "name: not-a-secret") || !strings.Contains(out, "token:") {
		t.Fatalf("YAML structure/non-secret damaged:\n%s", out)
	}
}

// TestRedact_EnvCredentialFields redacts credential-named keys in env line form
// ("KEY=value"), including prefixed names (DB_PASSWORD, AWS_SECRET_ACCESS_KEY).
func TestRedact_EnvCredentialFields(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n" +
		"DB_PASSWORD=hunter2supersecret\n" +
		"API_TOKEN=tok-abc-123\n" +
		"REGION=us-east-1\n"
	out := r.Redact(in)

	for _, leaked := range []string{"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "hunter2supersecret", "tok-abc-123"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("env secret not redacted (%q present):\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "REGION=us-east-1") {
		t.Fatalf("non-secret env var was damaged:\n%s", out)
	}
}

// TestRedact_EnvExportAndYAMLSequence covers the shell "export KEY=value" form
// and the YAML "- key: value" sequence-item form.
func TestRedact_EnvExportAndYAMLSequence(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7secretvalue\n" +
		"  - token: sequence-entry-secret\n"
	out := r.Redact(in)

	for _, leaked := range []string{"wJalrXUtnFEMIK7secretvalue", "sequence-entry-secret"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("export/sequence secret not redacted (%q present):\n%s", leaked, out)
		}
	}
	// The export keyword and the sequence dash are preserved (key structure intact).
	if !strings.Contains(out, "export ") || !strings.Contains(out, "- token:") {
		t.Fatalf("export/sequence structure damaged:\n%s", out)
	}
}

// TestRedact_Base64PEMWrapped redacts a base64 PEM split across newline-wrapped
// continuation lines, without swallowing the following non-base64 key.
func TestRedact_Base64PEMWrapped(t *testing.T) {
	t.Parallel()

	r := redact.New()
	cont := "Z2txaGtpRzl3MEJBUUVGQUFTQ0JLZ3dnZ1NrQWdFQUFvSUJBUUM" // 51 base64 chars (>=32)
	in := "    client-key-data:\n" +
		"      LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS1NSUlFdmdJQkFEQU5C\n" +
		"      " + cont + "\n" +
		"    name: not-a-secret\n"
	out := r.Redact(in)

	if strings.Contains(out, cont) {
		t.Fatalf("wrapped base64 PEM continuation not redacted:\n%s", out)
	}
	if !strings.Contains(out, "name: not-a-secret") {
		t.Fatalf("base64 block over-consumed the following key:\n%s", out)
	}
}

// TestRedact_Base64PEM catches a base64-encoded PEM private key regardless of the
// surrounding key name (kubeconfig client-key-data, k8s secret data, etc.).
func TestRedact_Base64PEM(t *testing.T) {
	t.Parallel()

	r := redact.New()
	// base64("-----BEGIN PRIVATE KEY-----\nMIIE...") starts LS0tLS1CRUdJTi.
	in := "blob: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS1NSUlFdmdJQkFEQU5C and more"
	out := r.Redact(in)
	if strings.Contains(out, "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS1NSUlFdmdJQkFEQU5C") {
		t.Fatalf("base64 PEM not redacted:\n%s", out)
	}
	if !strings.Contains(out, "[REDACTED:base64-pem]") {
		t.Fatalf("expected base64-pem placeholder:\n%s", out)
	}
}

// TestRedact_Base64PEMEscapedNewlines redacts a wrapped base64 PEM whose line
// breaks are spelled \n or \r\n in a JSON string, so its continuation lines are
// redacted with the first (#419).
func TestRedact_Base64PEMEscapedNewlines(t *testing.T) {
	t.Parallel()

	r := redact.New()
	first := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCgABAgMEBQYHCAkKCwwNDg8QERIT"
	second := "FBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJD"
	third := "REVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJz"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "escaped newlines",
			in:   `{"key":"` + first + `\n` + second + `\n` + third + `","n":1}`,
			want: `{"key":"[REDACTED:base64-pem]","n":1}`,
		},
		{
			name: "escaped carriage returns",
			in:   `{"key":"` + first + `\r\n` + second + `\r\n","n":1}`,
			want: `{"key":"[REDACTED:base64-pem]\r\n","n":1}`,
		},
		{
			name: "short line after the block kept",
			in:   `{"key":"a<b> ` + first + `\n` + second + `\nusers: x","n":1}`,
			want: `{"key":"a<b> [REDACTED:base64-pem]\nusers: x","n":1}`,
		},
		{
			name: "encoded string",
			in:   `{"r":"{\"key\":\"` + first + `\\n` + second + `\",\"password\":\"hunter2\"}"}`,
			want: `{"r":"{\"key\":\"[REDACTED:base64-pem]\",\"password\":\"[REDACTED:credential-field]\"}"}`,
		},
		{
			name: "two levels of encoded strings",
			in:   `{"r":"{\"s\":\"{\\\"k\\\":\\\"` + first + `\\\\n` + second + `\\\"}\"}"}`,
			want: `{"r":"{\"s\":\"{\\\"k\\\":\\\"[REDACTED:base64-pem]\\\"}\"}"}`,
		},
		{
			name: "escaped slashes and tabs",
			in:   `{"key":"` + first[:20] + `\/` + first[21:] + `\n\t` + `\/` + second[1:] + `\t\n` + third + `","n":1}`,
			want: `{"key":"[REDACTED:base64-pem]","n":1}`,
		},
		{
			name: "cut at the content cap",
			in:   `{"k":"` + first + `\n` + second[:32],
			want: `{"k":"[REDACTED:base64-pem]`,
		},
		{
			name: "other escapes in the string kept as written",
			in:   `["password=hunter2 LS0tLS1CRUdJTiBQ\u0020", "caf\u00e9 ` + first + `\n` + second + `"]`,
			want: `["password=[REDACTED:credential-field]", "caf\u00e9 [REDACTED:base64-pem]"]`,
		},
		{
			name: "raw newlines outside JSON",
			in:   "key: " + first + "\n  " + second + "\nname: x",
			want: "key: [REDACTED:base64-pem]\nname: x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := r.Redact(tc.in)
			if got != tc.want {
				t.Errorf("Redact(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
			if again := r.Redact(got); again != got {
				t.Errorf("not idempotent: %q became %q", got, again)
			}
		})
	}
}
