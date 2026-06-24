package redact_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

func TestRedact_TokenAndStructuralRules(t *testing.T) {
	t.Parallel()

	r := redact.New()

	cases := []struct {
		name   string
		in     string
		secret string // substring that must NOT survive
		label  string // placeholder that MUST appear
	}{
		{
			"github pat classic",
			"token=ghp_" + strings.Repeat("a", 36) + " end",
			"ghp_" + strings.Repeat("a", 36),
			"[REDACTED:github-token]",
		},
		{
			"github fine grained",
			"k=github_pat_" + strings.Repeat("A", 82) + "!",
			"github_pat_" + strings.Repeat("A", 82),
			"[REDACTED:github-token]",
		},
		{
			"github fine grained long",
			"k=github_pat_" + strings.Repeat("A", 90) + "!",
			"github_pat_" + strings.Repeat("A", 90),
			"[REDACTED:github-token]",
		},
		{"gitlab", "glpat-" + strings.Repeat("x", 20), "glpat-" + strings.Repeat("x", 20), "[REDACTED:gitlab-token]"},
		{"slack bot", "xoxb-" + strings.Repeat("1", 12), "xoxb-" + strings.Repeat("1", 12), "[REDACTED:slack-token]"},
		{
			"slack app",
			"xapp-1-" + strings.Repeat("A", 20),
			"xapp-1-" + strings.Repeat("A", 20),
			"[REDACTED:slack-token]",
		},
		{
			"google api key",
			"AIza" + strings.Repeat("a", 35),
			"AIza" + strings.Repeat("a", 35),
			"[REDACTED:google-api-key]",
		},
		{
			"google oauth",
			"ya29." + strings.Repeat("z", 30),
			"ya29." + strings.Repeat("z", 30),
			"[REDACTED:google-oauth-token]",
		},
		{"aws akid", "id AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws-access-key-id]"},
		{"jwt", "Bearer eyJhbGci.eyJzdWIi.sig123_-", "eyJhbGci.eyJzdWIi.sig123_-", "[REDACTED:jwt]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := r.Redact(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Errorf("secret survived: %q in %q", tc.secret, got)
			}
			if !strings.Contains(got, tc.label) {
				t.Errorf("missing placeholder %q in %q", tc.label, got)
			}
		})
	}
}

func TestRedact_NearMissNegatives(t *testing.T) {
	t.Parallel()

	r := redact.New()

	negatives := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc user@host",
		"the weight of the github logo is fine",
		"a perfectly ordinary sentence with no secrets",
		`{"not_a_secret_field":"ordinary-value"}`,
		`{"comment":"some ordinary text cut off here`,
	}
	for _, in := range negatives {
		if got := r.Redact(in); got != in {
			t.Errorf("false positive: %q became %q", in, got)
		}
	}
}

func TestRedact_PEMOpenEndedTruncated(t *testing.T) {
	t.Parallel()

	r := redact.New()

	truncated := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA" + strings.Repeat("x", 200)
	got := r.Redact(truncated)
	if strings.Contains(got, "MIIEpAIBAAKCAQEA") {
		t.Errorf("truncated key material survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:pem-private-key]") {
		t.Errorf("missing pem placeholder: %q", got)
	}
}

func TestRedact_CredentialFieldAndSignedURL(t *testing.T) {
	t.Parallel()

	r := redact.New()

	cases := []struct {
		name   string
		in     string
		secret string
		label  string
		keep   string // a substring that MUST remain (key/param preserved)
	}{
		{
			name:   "json access_token",
			in:     `{"access_token":"abc123secretvalue","expires_in":3600}`,
			secret: "abc123secretvalue",
			label:  "[REDACTED:credential-field]",
			keep:   `"access_token":`,
		},
		{
			name:   "json bare token (gitlab trigger)",
			in:     `{"id":10,"description":"x","token":"6d056f63e50fe6f8c5f8f4aa10edb7"}`,
			secret: "6d056f63e50fe6f8c5f8f4aa10edb7",
			label:  "[REDACTED:credential-field]",
			keep:   `"token":`,
		},
		{
			name:   "json gitlab runners_token",
			in:     `{"id":7,"name":"grp","runners_token":"GR1348941abcdefghijklmno"}`,
			secret: "GR1348941abcdefghijklmno",
			label:  "[REDACTED:credential-field]",
			keep:   `"runners_token":`,
		},
		{
			name:   "json gitlab multi-component incoming_email_token",
			in:     `{"id":7,"incoming_email_token":"glimt-abcdefghijklmnop"}`,
			secret: "glimt-abcdefghijklmnop",
			label:  "[REDACTED:credential-field]",
			keep:   `"incoming_email_token":`,
		},
		{
			name:   "json SecretAccessKey mixed case",
			in:     `{"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG","SessionToken":"FQoGZ"}`,
			secret: "wJalrXUtnFEMI/K7MDENG",
			label:  "[REDACTED:credential-field]",
			keep:   `"SecretAccessKey":`,
		},
		{
			name:   "xml secret element",
			in:     "<SecretAccessKey>wJalrXUtnFEMI</SecretAccessKey>",
			secret: "wJalrXUtnFEMI",
			label:  "[REDACTED:credential-field]",
			keep:   "<SecretAccessKey>",
		},
		{
			name:   "signed url signature",
			in:     "https://x/o?X-Amz-Signature=deadbeefcafe&X-Amz-Date=20260613",
			secret: "deadbeefcafe",
			label:  "[REDACTED:signed-url-signature]",
			keep:   "X-Amz-Date=20260613",
		},
		{
			name:   "json value with escaped quote",
			in:     "{\"password\":\"a\\\"bSECRETTAIL\"}",
			secret: "SECRETTAIL",
			label:  "[REDACTED:credential-field]",
			keep:   `"password":`,
		},
		{
			name:   "json truncated value no closing quote",
			in:     `{"a":"x","password":"S3cr3tValueCutHere`,
			secret: "S3cr3tValueCutHere",
			label:  "[REDACTED:credential-field]",
			keep:   `"password":`,
		},
		{
			name:   "xml truncated value no closing tag",
			in:     "<SecretAccessKey>wJalrXUtnFEMIcuthere",
			secret: "wJalrXUtnFEMIcuthere",
			label:  "[REDACTED:credential-field]",
			keep:   "<SecretAccessKey>",
		},
		{
			name:   "json truncated after backslash",
			in:     `{"password":"secretval\`,
			secret: "secretval",
			label:  "[REDACTED:credential-field]",
			keep:   `"password":`,
		},
		{
			name:   "xml truncated at closing tag start",
			in:     "<SecretAccessKey>wJalrXval<",
			secret: "wJalrXval",
			label:  "[REDACTED:credential-field]",
			keep:   "<SecretAccessKey>",
		},
		{
			name:   "json camelCase accessToken",
			in:     `{"accessToken":"camelSecretValue","x":1}`,
			secret: "camelSecretValue",
			label:  "[REDACTED:credential-field]",
			keep:   `"accessToken":`,
		},
		{
			name:   "json camelCase clientSecret",
			in:     `{"clientSecret":"anotherSecret"}`,
			secret: "anotherSecret",
			label:  "[REDACTED:credential-field]",
			keep:   `"clientSecret":`,
		},
		{
			name:   "json camelCase privateKey",
			in:     `{"privateKey":"keymaterialhere"}`,
			secret: "keymaterialhere",
			label:  "[REDACTED:credential-field]",
			keep:   `"privateKey":`,
		},
		{
			name:   "presigned url session token",
			in:     "https://b.s3/o?X-Amz-Security-Token=FQoGZXIvYXdzEY&X-Amz-Date=20260613",
			secret: "FQoGZXIvYXdzEY",
			label:  "[REDACTED:aws-session-token]",
			keep:   "X-Amz-Date=20260613",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := r.Redact(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Errorf("secret survived: %q in %q", tc.secret, got)
			}
			if !strings.Contains(got, tc.label) {
				t.Errorf("missing placeholder %q in %q", tc.label, got)
			}
			if !strings.Contains(got, tc.keep) {
				t.Errorf("key/param not preserved %q in %q", tc.keep, got)
			}
		})
	}
}

func TestRedact_Idempotent(t *testing.T) {
	t.Parallel()

	r := redact.New()
	in := `{"access_token":"abc","k":"ghp_` + strings.Repeat("a", 36) + `"}`
	once := r.Redact(in)
	twice := r.Redact(once)
	if once != twice {
		t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
	}
}

func TestRedactHeader(t *testing.T) {
	t.Parallel()

	r := redact.New()
	h := http.Header{
		"Set-Cookie":     []string{"session=topsecret; Path=/"},
		"Authorization":  []string{"Bearer abc"},
		"Location":       []string{"https://x/o?X-Amz-Signature=keepme&t=1"},
		"X-Custom":       []string{"token=ghp_" + strings.Repeat("a", 36)},
		"X-Oauth-Scopes": []string{"repo, workflow"},
		"Content-Type":   []string{"application/json"},
	}

	r.RedactHeader(h)

	if got := h.Get("Set-Cookie"); got != "[REDACTED:header]" {
		t.Errorf("Set-Cookie not denylisted: %q", got)
	}
	if got := h.Get("Authorization"); got != "[REDACTED:header]" {
		t.Errorf("Authorization not denylisted: %q", got)
	}
	if got := h.Get("Location"); !strings.Contains(got, "X-Amz-Signature=keepme") {
		t.Errorf("Location must be exempt (untouched): %q", got)
	}
	if got := h.Get("X-Custom"); strings.Contains(got, "ghp_") {
		t.Errorf("token in non-denylisted header not content-redacted: %q", got)
	}
	if got := h.Get("X-Oauth-Scopes"); got != "repo, workflow" {
		t.Errorf("x-oauth-scopes must be preserved: %q", got)
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("benign header changed: %q", got)
	}
}

func TestRedactHeader_GitLabCredentialHeaders(t *testing.T) {
	t.Parallel()

	r := redact.New()

	// Canonical and non-canonical casing — Go canonicalizes header keys on Set/Add,
	// but the denylist lookup uses http.CanonicalHeaderKey, so both forms reach the
	// same canonical key and must be blanked.
	h := http.Header{}
	h.Set("Private-Token", "glpat-supersecrettoken")
	h.Set("Job-Token", "CI_JOB_TOKEN_VALUE")
	h.Set("Deploy-Token", "gldt-deploytokenvalue")
	h.Set("X-Gitlab-Static-Object-Token", "static-object-token-value")
	// Underscore variant (Rack folds it onto the hyphenated name): must blank too.
	// "Private_token" is the canonical MIME form of an underscore header.
	h["Private_token"] = []string{"glpat-underscorevariant"}

	r.RedactHeader(h)

	for _, hdr := range []string{"Private-Token", "Job-Token", "Deploy-Token", "X-Gitlab-Static-Object-Token"} {
		if got := h.Get(hdr); got != "[REDACTED:header]" {
			t.Errorf("%s not redacted: %q", hdr, got)
		}
	}
	if got := h["Private_token"][0]; got != "[REDACTED:header]" {
		t.Errorf("underscore Private_token not redacted: %q", got)
	}
}

func TestRedact_ProviderAPIKey(t *testing.T) {
	t.Parallel()

	r := redact.New()
	tests := []struct {
		name string
		in   string
		leak string
	}{
		{
			name: "anthropic in prose",
			in:   "auth failed for sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			leak: "sk-ant-api03-ABCDEF",
		},
		{
			name: "openai legacy",
			in:   "Incorrect API key: sk-ABCDEFGHIJ0123456789abcd provided",
			leak: "sk-ABCDEFGHIJ0123456789",
		},
		{
			name: "openai project",
			in:   "key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX rejected",
			leak: "sk-proj-ABCDEFGHIJ",
		},
		{
			name: "openai service account",
			in:   "auth failed for sk-svcacct-ABCDEFGHIJKLMNOPQRSTUVWX",
			leak: "sk-svcacct-ABCDEFGHIJ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := r.Redact(tt.in)
			if strings.Contains(out, tt.leak) {
				t.Errorf("secret leaked: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:llm-api-key]") {
				t.Errorf("want [REDACTED:llm-api-key], got %q", out)
			}
		})
	}
}

func TestRedact_DoesNotMatchHyphenatedProse(t *testing.T) {
	t.Parallel()

	// "risk-" must NOT be misread as an "sk-" key (\b anchoring).
	in := "the risk-averse-management-framework-recommendation-v2 approach"
	if out := redact.New().Redact(in); out != in {
		t.Errorf("over-redacted prose: %q", out)
	}
}

func TestRedactTrailer_NoLocationExemption(t *testing.T) {
	t.Parallel()

	r := redact.New()
	tr := http.Header{"Location": []string{"https://x/o?X-Amz-Signature=leakedsig&t=1"}}
	r.RedactTrailer(tr)

	if got := tr.Get("Location"); strings.Contains(got, "leakedsig") {
		t.Errorf("Location trailer signature must be redacted (no exemption): %q", got)
	}

	// RedactHeader must still EXEMPT Location (regression guard).
	h := http.Header{"Location": []string{"https://x/o?X-Amz-Signature=keepme&t=1"}}
	r.RedactHeader(h)
	if got := h.Get("Location"); !strings.Contains(got, "keepme") {
		t.Errorf("Location header must stay exempt: %q", got)
	}
}
