package redact_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestRedact_PEMEndsAtStringQuote(t *testing.T) {
	t.Parallel()

	r := redact.New()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "END marker in a later string",
			in:   `{"a":"-----BEGIN PRIVATE KEY-----","b":{"c":"-----END PRIVATE KEY-----"},"r":"{\"password\":\"hunter2\"}"}`,
			want: `{"a":"[REDACTED:pem-private-key]","b":{"c":"-----END PRIVATE KEY-----"},` +
				`"r":"{\"password\":\"[REDACTED:credential-field]\"}"}`,
		},
		{
			name: "no END marker",
			in:   `{"x":"-----BEGIN PRIVATE KEY-----"}`,
			want: `{"x":"[REDACTED:pem-private-key]"}`,
		},
		{
			name: "END marker in the same string",
			in:   `{"k":"-----BEGIN RSA PRIVATE KEY-----\nMIIE\\\/x\n-----END RSA PRIVATE KEY-----\n","n":1}`,
			want: `{"k":"[REDACTED:pem-private-key]\n","n":1}`,
		},
		{
			name: "key in an encoded string",
			in:   `{"r":"{\"k\":\"-----BEGIN PRIVATE KEY-----\\nMIIE\",\"password\":\"hunter2\"}"}`,
			want: `{"r":"{\"k\":\"[REDACTED:pem-private-key]\",\"password\":\"[REDACTED:credential-field]\"}"}`,
		},
		{
			name: "encoded string that is not valid JSON",
			in:   `{"r":"{\"k\":\"-----BEGIN PRIVATE KEY-----\nMIIE\"}","n":1}`,
			want: `{"r":"{\"k\":\"[REDACTED:pem-private-key]","n":1}`,
		},
		{
			name: "escaped whitespace before the end of an encoded string",
			in:   `{"r":"{\"k\":\"-----BEGIN PRIVATE KEY-----\"\n}","n":1}`,
			want: `{"r":"{\"k\":\"[REDACTED:pem-private-key]\"\n}","n":1}`,
		},
		{
			name: "quoted header followed by a comma",
			in:   `{"k":"-----BEGIN RSA PRIVATE KEY-----\nComment: \"a\", b\n\nMIIE\n-----END RSA PRIVATE KEY-----","n":1}`,
			want: `{"k":"[REDACTED:pem-private-key]","n":1}`,
		},
		{
			name: "string without a key kept as written",
			in:   `{"k":"the PRIVATE KEY field \/ \t"}`,
			want: `{"k":"the PRIVATE KEY field \/ \t"}`,
		},
		{
			name: "rest of the string keeps its text",
			in:   `{"k":"a<b> -----BEGIN PRIVATE KEY-----\nMIIE","n":1}`,
			want: `{"k":"a<b> [REDACTED:pem-private-key]","n":1}`,
		},
		{
			name: "key bytes after a string are matched as a whole",
			in:   `"-----BEGIN PRIVATE KEY-----"MIIE-----END PRIVATE KEY-----`,
			want: `"[REDACTED:pem-private-key]`,
		},
		{
			name: "key bytes after a string in an encoded string",
			in:   `"\"-----BEGIN PRIVATE KEY-----\"MIIE-----END PRIVATE KEY-----"`,
			want: `"\"[REDACTED:pem-private-key]"`,
		},
		{
			name: "JSON after prose is matched as a whole",
			in:   `got {"a":"-----BEGIN PRIVATE KEY-----","b":"-----END PRIVATE KEY-----","c":1}`,
			want: `got {"a":"[REDACTED:pem-private-key]","c":1}`,
		},
		{
			name: "escaped quote two levels down",
			in:   `{"r":"{\"s\":\"{\\\"k\\\":\\\"-----BEGIN PRIVATE KEY-----\\\\nMIIE\\\"}\"}"}`,
			want: `{"r":"{\"s\":\"{\\\"k\\\":\\\"[REDACTED:pem-private-key]\\\"}\"}"}`,
		},
		{
			name: "cut at the content cap after a backslash",
			in:   `{"k":"-----BEGIN PRIVATE KEY-----\nMIIE\`,
			want: `{"k":"[REDACTED:pem-private-key]`,
		},
		{
			name: "string closed before whitespace and a brace",
			in:   "{\n  \"k\": \"-----BEGIN EC PRIVATE KEY-----\\nMHcC\\n\"\n}",
			want: "{\n  \"k\": \"[REDACTED:pem-private-key]\"\n}",
		},
		{
			name: "string closed before a bracket",
			in:   `["-----BEGIN PRIVATE KEY-----\nMIIE"]`,
			want: `["[REDACTED:pem-private-key]"]`,
		},
		{
			name: "string closed at the end of content",
			in:   `"-----BEGIN PRIVATE KEY-----\nMIIE"`,
			want: `"[REDACTED:pem-private-key]"`,
		},
		{
			name: "quoted header inside the string",
			in:   `{"k":"-----BEGIN RSA PRIVATE KEY-----\nComment: \"<password>\"\n\nMIIE\n-----END RSA PRIVATE KEY-----","n":1}`,
			want: `{"k":"[REDACTED:pem-private-key]","n":1}`,
		},
		{
			name: "raw quote that ends no string",
			in:   "echo \"-----BEGIN EC PRIVATE KEY-----\" > k\necho \"MHcC\" >> k\necho \"-----END EC PRIVATE KEY-----\" >> k",
			want: "echo \"[REDACTED:pem-private-key]\" >> k",
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

func TestRedact_XMLEndsAtStringQuote(t *testing.T) {
	t.Parallel()

	r := redact.New()
	field := "[REDACTED:credential-field]"

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "closing tag in a later string",
			in:   `{"a":"<password>","b":{"c":"</password>"},"r":"{\"password\":\"hunter2\"}"}`,
			want: `{"a":"<password>` + field + `","b":{"c":"</password>"},"r":"{\"password\":\"` + field + `\"}"}`,
		},
		{
			name: "closing tag in the same string",
			in:   `{"x":"<password>p\"q</password>","n":1}`,
			want: `{"x":"<password>` + field + `</password>","n":1}`,
		},
		{
			name: "tags in an encoded string",
			in:   `{"r":"{\"a\":\"<secret>\",\"b\":\"</secret>\",\"password\":\"hunter2\"}"}`,
			want: `{"r":"{\"a\":\"<secret>` + field + `\",\"b\":\"</secret>\",\"password\":\"` + field + `\"}"}`,
		},
		{
			name: "cut at the content cap",
			in:   `{"a":"<password>","b":"</password>","c":"<token>hunt`,
			want: `{"a":"<password>` + field + `","b":"</password>","c":"<token>` + field,
		},
		{
			name: "string without a credential tag kept as written",
			in:   `{"h":"<b>x</b> \/"}`,
			want: `{"h":"<b>x</b> \/"}`,
		},
		{
			name: "escapes in the string keep their spelling",
			in:   `{"x":"<password>p</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			want: `{"x":"<password>` + field + `</password> [REDACTED:github-token]"}`,
		},
		{
			name: "escaped angle bracket inside the value",
			in:   `{"x":"<password>hunter2\u003cx</password>"}`,
			want: `{"x":"<password>` + field + `</password>"}`,
		},
		{
			name: "escapes in an encoded string",
			in:   `{"r":"{\"x\":\"<password>p</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"}`,
			want: `{"r":"{\"x\":\"<password>` + field + `</password> [REDACTED:github-token]\"}"}`,
		},
		{
			name: "truncated value after a rule removes a later tag",
			in:   `<password>hunter2 sig=abc<xyz`,
			want: `<password>` + field,
		},
		{
			name: "encoded string without a credential tag kept as written",
			in:   `{"r":"{\"h\":\"<b>x</b>\"}\u0020"}`,
			want: `{"r":"{\"h\":\"<b>x</b>\"}\u0020"}`,
		},
		{
			name: "escapes in a string after a bare value",
			in:   `0 "{\"x\":\"<password>p</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"`,
			want: `0 "{\"x\":\"<password>` + field + `</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"`,
		},
		{
			name: "escapes beside an encoded value keep their spelling",
			in:   `{"r":"{\"x\":\"<password>p</password>\",\"y\":\"\u0061\"}"}`,
			want: `{"r":"{\"x\":\"<password>` + field + `</password>\",\"y\":\"\u0061\"}"}`,
		},
		{
			name: "string between the tags is not redacted",
			in:   `["<password>","hunter2","</password>"]`,
			want: `["<password>` + field + `","hunter2","</password>"]`,
		},
		{
			name: "XML document matched as a whole",
			in:   `<a><password>x"y</password></a>`,
			want: `<a><password>` + field + `</password></a>`,
		},
		{
			name: "JSON after prose is matched as a whole",
			in:   `got {"a":"<password>","b":"</password>","c":1}`,
			want: `got {"a":"<password>` + field + `</password>","c":1}`,
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

func TestRedact_XMLBelowNestingBound(t *testing.T) {
	t.Parallel()

	r := redact.New()
	field := "[REDACTED:credential-field]"

	// The strings of four levels are read. A document in a third-level string has
	// its strings read on their own; one in a fourth-level string is matched as it
	// is spelled there, across its strings.
	cases := []struct {
		levels   int
		in, want string
	}{
		{3, `{"a":"<password>","b":"</password>","n":1}`, `{"a":"<password>` + field + `","b":"</password>","n":1}`},
		{4, `{"a":"<password>","b":"</password>","n":1}`, `{"a":"<password>` + field + `</password>","n":1}`},
	}
	for _, tc := range cases {
		in, want := tc.in, tc.want
		for range tc.levels {
			in, want = wrapRaw(in), wrapRaw(want)
		}
		if got := r.Redact(in); got != want {
			t.Errorf("%d levels: Redact(%q)\n got %q\nwant %q", tc.levels, in, got, want)
		}
	}
}

func TestRedact_PEMBelowNestingBound(t *testing.T) {
	t.Parallel()

	r := redact.New()

	// The strings of four levels are read, so the content of the fifth, the object
	// around the key's object, is matched as a whole, to its end. The four levels
	// above it stay intact.
	in := wrapJSON(t, `{"k":"-----BEGIN PRIVATE KEY-----","n":1}`)
	want := `{"r":"{\"k\":\"[REDACTED:pem-private-key]`
	for range 4 {
		in, want = wrapJSON(t, in), wrapJSON(t, want)
	}
	if got := r.Redact(in); got != want {
		t.Errorf("Redact(%q)\n got %q\nwant %q", in, got, want)
	}
}

func TestRedact_PEMSurrogatePairs(t *testing.T) {
	t.Parallel()

	r := redact.New()

	// The first key holds an escaped surrogate pair and the text between the keys
	// two U+FFFD, which a decoder that reads each half alone would confuse.
	bs, fffd := "\\", string(utf8.RuneError)
	in := `"-----BEGIN PRIVATE KEY-----` + bs + `ud83d` + bs + `ude00-----END PRIVATE KEY-----` +
		bs + `ufffd` + bs + `ufffd-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----"`
	want := `"[REDACTED:pem-private-key]` + fffd + fffd + `[REDACTED:pem-private-key]"`
	if got := r.Redact(in); got != want {
		t.Errorf("Redact(%q)\n got %q\nwant %q", in, got, want)
	}
}

func TestRedact_PEMEncodedStringKeepsMembers(t *testing.T) {
	t.Parallel()

	r := redact.New()

	// Each key has no END marker and ends in "]", spelled as an escape, and the
	// member between them holds an escaped surrogate pair. Only the two keys may
	// change in the encoded document.
	bs := "\\"
	esc := bs + "u005d"
	in := wrapJSON(t, `{"a":"-----BEGIN PRIVATE KEY-----x`+esc+`","s":"`+bs+`ud83d`+bs+`ude00",`+
		`"b":"-----BEGIN PRIVATE KEY-----y`+esc+`","n":1}`)
	got := r.Redact(in)

	var outer map[string]string
	if err := json.Unmarshal([]byte(got), &outer); err != nil || len(outer) != 1 {
		t.Fatalf("Redact(%q) = %q, want one string member: %v", in, got, err)
	}
	var inner map[string]any
	if err := json.Unmarshal([]byte(outer["r"]), &inner); err != nil {
		t.Fatalf("encoded string %q is not JSON: %v", outer["r"], err)
	}
	want := map[string]any{
		"a": "[REDACTED:pem-private-key]", "s": string(rune(0x1F600)), "b": "[REDACTED:pem-private-key]", "n": 1.0,
	}
	if !reflect.DeepEqual(inner, want) {
		t.Errorf("encoded string = %v, want %v", inner, want)
	}
	if again := r.Redact(got); again != got {
		t.Errorf("not idempotent: %q became %q", got, again)
	}
}

// wrapRaw returns s as the "r" member of a JSON object, leaving <, > and & as
// written.
func wrapRaw(s string) string {
	var b strings.Builder

	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// Encoding a string into a builder cannot fail.
	_ = enc.Encode(s)

	return `{"r":` + strings.TrimSuffix(b.String(), "\n") + `}`
}

// wrapJSON returns s as the "r" member of a JSON object.
func wrapJSON(t *testing.T, s string) string {
	t.Helper()

	b, err := json.Marshal(map[string]string{"r": s})
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
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
