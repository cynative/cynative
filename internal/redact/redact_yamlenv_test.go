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
