package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedact_JSONEncodedStrings pins the exact output for credential members
// inside JSON strings (#403): the content is decoded, redacted and written back
// escaped, so the outer document stays valid. Each case also checks that a second
// pass changes nothing.
func TestRedact_JSONEncodedStrings(t *testing.T) {
	t.Parallel()

	const field = "[REDACTED:credential-field]"

	r := redact.New()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "body that is a string holding json",
			in:   `"{\"DB_PASSWORD\":\"hunter2\"}"`,
			want: `"{\"DB_PASSWORD\":\"` + field + `\"}"`,
		},
		{
			name: "member value holding json keeps its other escapes",
			in:   `{"result":"{\"password\":\"a<b&c\",\"x\":\"\\u0041\\n\"}","n":1}`,
			want: `{"result":"{\"password\":\"` + field + `\",\"x\":\"\\u0041\\n\"}","n":1}`,
		},
		{
			name: "array element holding a name value pair",
			in:   `[1,"{\"name\":\"API_KEY\",\"value\":\"k3y\"}"]`,
			want: `[1,"{\"name\":\"API_KEY\",\"value\":\"` + field + `\"}"]`,
		},
		{
			name: "string holding a string holding json",
			in:   `{"r":"\"{\\\"token\\\":\\\"t0k\\\"}\""}`,
			want: `{"r":"\"{\\\"token\\\":\\\"` + field + `\\\"}\""}`,
		},
		{
			name: "string holding yaml lines",
			in:   `{"config.yaml":"a: b\npassword: hunter2\n"}`,
			want: `{"config.yaml":"a: b\npassword: ` + field + `\n"}`,
		},
		{
			name: "escape after a value a rule moved up to its key line keeps its spelling",
			in:   `"token:0\npAsswd:\n 0\n\u0073ig=0\n"`,
			want: `"token:` + field + `\npAsswd: ` + field + `\n\u0073ig=[REDACTED:signed-url-signature]\n"`,
		},
		{
			name: "placeholder already in the content before a replaced value",
			in:   `"{\"password\":\"` + field + `abc\",\"p\":\"\u0073ig=x\"}"`,
			want: `"{\"password\":\"` + field + `\",\"p\":\"\u0073ig=[REDACTED:signed-url-signature]\"}"`,
		},
		{
			name: "surrogate pair outside a replaced value",
			in:   `"{\"password\":\"` + field + `abc\",\"p\":\"\ud83d\ude00 \u0073ig=x\"}"`,
			want: `"{\"password\":\"` + field + `\",\"p\":\"\ud83d\ude00 \u0073ig=[REDACTED:signed-url-signature]\"}"`,
		},
		{
			name: "characters sharing a last byte around a shell command",
			in:   `"[{\"password\":\"` + field + `x\"},[\"sh\",\"-c\",\"é '--password=abc Ω '--password=` + field + `'\"]]"`,
			want: `"[{\"password\":\"` + field + `\"},[\"sh\",\"-c\",\"é '--password=` + field + `'\"]]"`,
		},
		{
			name: "shell quote a rule closes at the end of a string holding json",
			in:   `"[\"sh\",\"-c\",\"app \\\"--password=a b \u00e9 x"`,
			want: `"[\"sh\",\"-c\",\"app \\\"--password=` + field + `\\\""`,
		},
		{
			name: "shell quote a rule closes inside a string holding json",
			in:   `"[\"sh\",\"-c\",\"app \\\"--password=a b\",\"\u0078\"]"`,
			want: `"[\"sh\",\"-c\",\"app \\\"--password=` + field + `\\\"\",\"\u0078\"]"`,
		},
		{
			name: "escape after a shell quote a rule closes keeps its spelling",
			in:   `"[\"sh\",\"-c\",\"\\\"--password=x\",\"\u0073ig=y\"]"`,
			want: `"[\"sh\",\"-c\",\"\\\"--password=` + field + `\\\"\",\"\u0073ig=[REDACTED:signed-url-signature]\"]"`,
		},
		{
			name: "surrogate pair after a shell quote a rule closes",
			in:   `"[\"sh\",\"-c\",\"\\\"--password=x\",\"\ud83d\ude00\",{\"password\":\"y\"}]"`,
			want: `"[\"sh\",\"-c\",\"\\\"--password=` + field + `\\\"\",\"\ud83d\ude00\",{\"password\":\"` +
				field + `\"}]"`,
		},
		{
			name: "escape after a single shell quote a rule closes keeps its spelling",
			in:   `"[\"sh\",\"-c\",\"'--password=x\",\"\u0073ig=y\"]"`,
			want: `"[\"sh\",\"-c\",\"'--password=` + field + `'\",\"\u0073ig=[REDACTED:signed-url-signature]\"]"`,
		},
		{
			name: "placeholders the rules leave alone keep their spelling",
			in:   `"\u005bREDACTED:jwt]\n[REDACTED:jwt]"`,
			want: `"\u005bREDACTED:jwt]\n[REDACTED:jwt]"`,
		},
		{
			name: "cut string the rules leave alone keeps its tail",
			in:   `"x\n[REDACTED:jwt]\u00`,
			want: `"x\n[REDACTED:jwt]\u00`,
		},
		{
			name: "rules read the content again after a value in a string is replaced",
			in:   `["sh","-c","password: foo \"\n--token secret\""]`,
			want: `["sh","-c","password: ` + field + `\n--token ` + field + `"]`,
		},
		{
			name: "spaces between replaced values stay",
			in:   `"\u0065yJa.eyJb \u0065yJa.eyJb \u0065yJa.eyJb"`,
			want: `"[REDACTED:jwt] [REDACTED:jwt] [REDACTED:jwt]"`,
		},
		{
			name: "quotes between replaced values stay",
			in:   `"\u0065yJa.eyJb'\u0065yJa.eyJb'\u0065yJa.eyJb"`,
			want: `"[REDACTED:jwt]'[REDACTED:jwt]'[REDACTED:jwt]"`,
		},
		{
			name: "escapes around a replaced value keep their spelling",
			in:   `["password=x\n\u003c<"]`,
			want: `["password=` + field + `\n\u003c<"]`,
		},
		{
			name: "token spelled with an escape",
			in:   `["echo \u0067hp_` + strings.Repeat("a", 36) + `"]`,
			want: `["echo [REDACTED:github-token]"]`,
		},
		{
			name: "shell command inside a string holding json",
			in:   `"[\"sh\",\"-c\",\"app \\\"--password=a b\\\" x\"]"`,
			want: `"[\"sh\",\"-c\",\"app \\\"--password=` + field + `\\\" x\"]"`,
		},
		{
			name: "string after a number too large for a float",
			in:   `[1e1000,"{\"password\":\"hunter2\"}"]`,
			want: `[1e1000,"{\"password\":\"` + field + `\"}"]`,
		},
		{
			name: "signature spelled with escapes keeps their spelling",
			in:   `"\u0073ig=x\n"`,
			want: `"\u0073ig=[REDACTED:signed-url-signature]\n"`,
		},
		{
			name: "xml element spelled with an escape keeps it",
			in:   `"\u003cpassword>x"`,
			want: `"\u003cpassword>` + field + `"`,
		},
		{
			name: "text between replaced values keeps its spelling",
			in:   `["a\nAPI_KEY=k1\n\u0062 \u0073ig=zz\nPASSWORD=p2\ntail"]`,
			want: `["a\nAPI_KEY=` + field + `\n\u0062 \u0073ig=[REDACTED:signed-url-signature]\nPASSWORD=` +
				field + `\ntail"]`,
		},
		{
			name: "space a rule adds before a value",
			in:   `["token: x\npassword:\n  y\nend: \u0041"]`,
			want: `["token: ` + field + `\npassword: ` + field + `\nend: \u0041"]`,
		},
		{
			name: "string cut off at the content cap",
			in:   `{"r":"{\"password\":\"hunt`,
			want: `{"r":"{\"password\":\"` + field,
		},
		{
			name: "string cut off after a lone backslash",
			in:   `{"r":"{\"password\":\"hunt\`,
			want: `{"r":"{\"password\":\"` + field,
		},
		{
			name: "string cut off inside a unicode escape",
			in:   `{"r": "{\"password\":\"hunt\u00`,
			want: `{"r": "{\"password\":\"` + field,
		},
		{
			name: "cut string with nothing to redact",
			in:   `{"r":"{\"a\":\"b`,
			want: `{"r":"{\"a\":\"b`,
		},
		{
			name: "cut string with no escape",
			in:   `{"a":"x\n","r":"abc`,
			want: `{"a":"x\n","r":"abc`,
		},
		{
			name: "closed string after a syntax error",
			in:   `{"a" "b\"c"}`,
			want: `{"a" "b\"c"}`,
		},
		{
			name: "syntax error outside a string",
			in:   `{"a":"b\"c",}`,
			want: `{"a":"b\"c",}`,
		},
		{
			name: "escaped string with nothing to redact",
			in:   `{"a":"x\ty","b":true,"c":null}`,
			want: `{"a":"x\ty","b":true,"c":null}`,
		},
		{
			name: "string without an escape is read only as raw text",
			in:   `{"note":"password=abc"}`,
			want: `{"note":"password=abc"}`,
		},
		{
			name: "text that is not json",
			in:   `a\"password\":\"hunter2\"`,
			want: `a\"password\":\"hunter2\"`,
		},
		{
			name: "empty content",
			in:   ``,
			want: ``,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := r.Redact(tc.in)
			if got != tc.want {
				t.Fatalf("Redact(%q)\n got  %q\n want %q", tc.in, got, tc.want)
			}
			if again := r.Redact(got); again != got {
				t.Fatalf("second Redact changed %q to %q", got, again)
			}
		})
	}
}

// TestRedact_JSONEncodedNestingBound pins how many string levels Redact reads
// into: four, so a member encoded four times is redacted and one encoded five
// times is left as it is.
func TestRedact_JSONEncodedNestingBound(t *testing.T) {
	t.Parallel()

	wrap := func(s string, n int) string {
		for range n {
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			s = string(b)
		}

		return s
	}
	const (
		in   = `{"password":"hunter2"}`
		want = `{"password":"[REDACTED:credential-field]"}`
	)

	r := redact.New()
	if got := r.Redact(wrap(in, 4)); got != wrap(want, 4) {
		t.Errorf("four levels: got %q, want %q", got, wrap(want, 4))
	}
	if got := r.Redact(wrap(in, 5)); got != wrap(in, 5) {
		t.Errorf("five levels: got %q, want it unchanged", got)
	}
}

// TestRedact_SigningParamStopsAtEscapedQuote pins that a signing or session
// param value ends before a backslash that escapes a quote (#410), so the
// placeholder never takes the backslash and leaves the quote to close the JSON
// string early. Any other escape stays part of the value.
func TestRedact_SigningParamStopsAtEscapedQuote(t *testing.T) {
	t.Parallel()

	const (
		field = "[REDACTED:credential-field]"
		sig   = "[REDACTED:signed-url-signature]"
		token = "[REDACTED:aws-session-token]"
		bs    = "\x5c"
	)

	r := redact.New()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "array element ending in an escaped quote",
			in:   `["sig=x\"tail","{\"DB_PASSWORD\":\"hunter2\"}"]`,
			want: `["sig=` + sig + `\"tail","{\"DB_PASSWORD\":\"` + field + `\"}"]`,
		},
		{
			name: "member value ending in an escaped quote",
			in:   `{"u":"https://e.test/o?sig=abc\"","password":"p"}`,
			want: `{"u":"https://e.test/o?sig=` + sig + `\"","password":"` + field + `"}`,
		},
		{
			name: "escaped backslash before the closing quote",
			in:   `{"u":"sig=ab\\","n":1}`,
			want: `{"u":"sig=` + sig + `","n":1}`,
		},
		{
			name: "escaped backslash then an escaped quote",
			in:   `{"u":"sig=ab\\\"c"}`,
			want: `{"u":"sig=` + sig + `\"c"}`,
		},
		{
			name: "other escapes stay in a value outside a json document",
			in:   `response={"u":"X-Amz-Security-Token=ab` + bs + `/cd` + bs + `u002bef+gh"}`,
			want: `response={"u":"X-Amz-Security-Token=` + token + `"}`,
		},
		{
			name: "backslash before a line break stays",
			in:   "sig=ab" + bs + "\npassword: x\n",
			want: "sig=" + sig + bs + "\npassword: " + field + "\n",
		},
		{
			name: "backslash before an ampersand stays",
			in:   "sig=ab" + bs + "&t=1",
			want: "sig=" + sig + bs + "&t=1",
		},
		{
			name: "plain text value keeps every character",
			in:   `X-Amz-Signature=ab+cd/ef=` + "\n",
			want: `X-Amz-Signature=` + sig + "\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := r.Redact(tc.in)
			if got != tc.want {
				t.Fatalf("Redact(%q)\n got  %q\n want %q", tc.in, got, tc.want)
			}
			if again := r.Redact(got); again != got {
				t.Fatalf("second Redact changed %q to %q", got, again)
			}
		})
	}
}
