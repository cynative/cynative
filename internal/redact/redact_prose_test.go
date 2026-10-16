package redact_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedact_JSONAfterText pins that the structural JSON passes read a JSON value
// that follows other text (#420), such as the body of an HTTP dump after its
// status line and headers, and that a brace or quote in text that opens no JSON
// value redacts nothing. Each case also checks that a second pass changes
// nothing.
func TestRedact_JSONAfterText(t *testing.T) {
	t.Parallel()

	const field = "[REDACTED:credential-field]"

	r := redact.New()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "object after a word",
			in:   `got {"DB_PASSW\u004fRD":"hunter2"}`,
			want: `got {"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "body of an http dump",
			in:   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + `[{"n\u0061me":"API_KEY","value":"k3y"}]`,
			want: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + `[{"n\u0061me":"API_KEY","value":"` + field + `"}]`,
		},
		{
			name: "braces in text before the object",
			in:   `see {name} and [1] then {"DB_PASSW\u004fRD":"hunter2"}`,
			want: `see {name} and [1] then {"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "object after a value broken by text",
			in:   `{"a":1} oops {"DB_PASSW\u004fRD":"hunter2"} tail`,
			want: `{"a":1} oops {"DB_PASSW\u004fRD":"` + field + `"} tail`,
		},
		{
			name: "truncated object after text",
			in:   `got {"DB_PASSW\u004fRD":"hunt`,
			want: `got {"DB_PASSW\u004fRD":"` + field,
		},
		{
			name: "encoded string after text",
			in:   `result: "{\"DB_PASSWORD\":\"hunter2\"}"`,
			want: `result: "{\"DB_PASSWORD\":\"` + field + `\"}"`,
		},
		{
			name: "string with an escaped quote before the object",
			in:   `"a\"b" x {"DB_PASSW\u004fRD":"hunter2"}`,
			want: `"a\"b" x {"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "invalid escape before an encoded string",
			in:   `"a\q\"b" "{\"password\":\"p\"}"`,
			want: `"a\q\"b" "{\"password\":\"` + field + `\"}"`,
		},
		{
			name: "string never closed after an invalid escape",
			in:   `"{\"token: x\":\"y\",\"t\\u006fken\":\"HEAD\nTAIL\"}\q`,
			want: `"{\"token: x\":\"y\",\"t\\u006fken\":\"` + field,
		},
		{
			name: "encoded string after a quoted label",
			in:   `got "result": "{\"DB_PASSWORD\":\"hunter2\"}"`,
			want: `got "result": "{\"DB_PASSWORD\":\"` + field + `\"}"`,
		},
		{
			name: "text with braces and no json",
			in:   `func f() { if x { return "{" } }`,
			want: `func f() { if x { return "{" } }`,
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

// TestRedact_JSONAfterTextIsLinear pins that an encoded-pass read stopped at a
// syntax error starts again after the strings it took and the one it stopped in,
// never inside one, and that a read stopped in a string that is never closed does
// not start again at all: each escaped quote could open a new string and read the rest
// again. Starting inside the string, 12 KB of the first shape took ten seconds;
// these are 48 to 64 KB, and a linear pass takes milliseconds.
func TestRedact_JSONAfterTextIsLinear(t *testing.T) {
	t.Parallel()

	const (
		repeats = 16 << 10
		limit   = 10 * time.Second
	)

	quotes := strings.Repeat(`a\"`, repeats)
	invalid := strings.Repeat(`\q\"`, repeats)
	for name, in := range map[string]string{
		"closed string then text":            `"` + quotes + `" x`,
		"cut off string":                     `{"k":"v","r":"` + quotes,
		"invalid escapes in a closed string": `"` + invalid + `" x`,
		"invalid escapes in a cut off one":   `"` + invalid,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			start := time.Now()
			redact.New().Redact(in)
			if took := time.Since(start); took > limit {
				t.Fatalf("Redact of %d bytes took %s, want under %s", len(in), took, limit)
			}
		})
	}
}
