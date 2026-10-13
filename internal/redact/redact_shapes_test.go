package redact_test

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedact_ConfigurationCredentialShapes pins the exact output for the three
// configuration shapes the JSON key rule alone missed: a prefixed JSON key, a
// name/value pair and a command-line flag (#307). Each case also checks that a
// second pass changes nothing, which a value one rule exposes to another breaks.
func TestRedact_ConfigurationCredentialShapes(t *testing.T) {
	t.Parallel()

	const field = "[REDACTED:credential-field]"

	r := redact.New()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "json prefixed password key",
			in:   `{"DB_PASSWORD":"hunter2"}`,
			want: `{"DB_PASSWORD":"` + field + `"}`,
		},
		{
			name: "json lambda environment variables",
			in:   `{"Environment":{"Variables":{"DB_PASSWORD":"hunter2","API_TOKEN":"abc123def456ghi789"}}}`,
			want: `{"Environment":{"Variables":{"DB_PASSWORD":"` + field + `","API_TOKEN":"` + field + `"}}}`,
		},
		{
			name: "json prefixed camel case secret",
			in:   `{"webhookSecret":"s3cr3t","stripeApiKey":"k3y"}`,
			want: `{"webhookSecret":"` + field + `","stripeApiKey":"` + field + `"}`,
		},
		{
			name: "json prefixed key truncated",
			in:   `{"DB_PASSWORD":"hunter`,
			want: `{"DB_PASSWORD":"` + field,
		},
		{
			name: "json name value pair",
			in:   `{"environment":[{"name":"DB_PASSWORD","value":"hunter2"},{"name":"DB_HOST","value":"db.internal"}]}`,
			want: `{"environment":[{"name":"DB_PASSWORD","value":"` + field + `"},{"name":"DB_HOST","value":"db.internal"}]}`,
		},
		{
			name: "json name value pair spaced",
			in:   `{"env": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]}`,
			want: `{"env": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "` + field + `"}]}`,
		},
		{
			name: "json name value pair capitalized keys",
			in:   `[{"Name":"ADMIN_TOKEN","Value":"tok"}]`,
			want: `[{"Name":"ADMIN_TOKEN","Value":"` + field + `"}]`,
		},
		{
			name: "json value name pair",
			in:   `[{"value":"hunter2","name":"DB_PASSWORD"}]`,
			want: `[{"value":"` + field + `","name":"DB_PASSWORD"}]`,
		},
		{
			name: "json name value pair escaped quote",
			in:   `[{"name":"DB_PASSWORD","value":"a\"bTAIL"}]`,
			want: `[{"name":"DB_PASSWORD","value":"` + field + `"}]`,
		},
		{
			name: "json name value pair truncated",
			in:   `[{"name":"DB_PASSWORD","value":"hunter`,
			want: `[{"name":"DB_PASSWORD","value":"` + field,
		},
		{
			name: "json name value pair truncated after backslash",
			in:   `[{"name":"DB_PASSWORD","value":"hunter\`,
			want: `[{"name":"DB_PASSWORD","value":"` + field,
		},
		{
			name: "yaml name value pair",
			in:   "env:\n  - name: DB_PASSWORD\n    value: hunter2\n  - name: DB_HOST\n    value: db.internal\n",
			want: "env:\n  - name: DB_PASSWORD\n    value: " + field + "\n  - name: DB_HOST\n    value: db.internal\n",
		},
		{
			name: "yaml name value pair quoted",
			in:   "- name: \"API_KEY\"\n  value: \"k3y\"\r\n",
			want: "- name: \"API_KEY\"\n  value: " + field + "\r\n",
		},
		{
			name: "yaml name value pair crlf",
			in:   "- name: DB_PASSWORD\r\n  value: hunter2\r\n",
			want: "- name: DB_PASSWORD\r\n  value: " + field + "\r\n",
		},
		{
			name: "yaml name value pair keeps a token label",
			in:   "- name: GH_TOKEN\n  value: ghp_" + strings.Repeat("a", 36) + "\n",
			want: "- name: GH_TOKEN\n  value: [REDACTED:github-token]\n",
		},
		{
			name: "flag as separate argument",
			in:   `{"command":["/app","--api-key","sk-live-abcdefghij","--port","8080"]}`,
			want: `{"command":["/app","--api-key","` + field + `","--port","8080"]}`,
		},
		{
			name: "flags joined and separate",
			in:   `{"args":["--token","hunter2","--password=hunter2","--db-passwd=x"]}`,
			want: `{"args":["--token","` + field + `","--password=` + field + `","--db-passwd=` + field + `"]}`,
		},
		{
			name: "flag spaced array",
			in:   `["--client-secret", "s3cr3t"]`,
			want: `["--client-secret", "` + field + `"]`,
		},
		{
			name: "json name value pair with a field between",
			in:   `[{"name":"DB_PASSWORD","type":"PLAINTEXT","value":"opaque"}]`,
			want: `[{"name":"DB_PASSWORD","type":"PLAINTEXT","value":"` + field + `"}]`,
		},
		{
			name: "json value name pair with a field between",
			in:   `[{"value":"opaque","secure":false,"name":"DB_PASSWORD"}]`,
			want: `[{"value":"` + field + `","secure":false,"name":"DB_PASSWORD"}]`,
		},
		{
			name: "json passwd and passphrase keys",
			in:   `{"DB_PASSWD":"a","sshPassphrase":"b"}`,
			want: `{"DB_PASSWD":"` + field + `","sshPassphrase":"` + field + `"}`,
		},
		{
			name: "boolean flag before a credential flag",
			in:   `["--generate-secret","--password","x"]`,
			want: `["--generate-secret","--password","` + field + `"]`,
		},
		{
			name: "separate flag value with a single leading dash",
			in:   `["--token","-abc"]`,
			want: `["--token","` + field + `"]`,
		},
		{
			name: "json name value pair redacts the first value member",
			in:   `{"name":"DB_PASSWORD","value":"hunter2","type":"PLAINTEXT","Value":"public"}`,
			want: `{"name":"DB_PASSWORD","value":"` + field + `","type":"PLAINTEXT","Value":"public"}`,
		},
		{
			name: "json truncated value after a backslash and newline",
			in:   "{\"password\":\"sig=x\\\nTAIL",
			want: `{"password":"` + field,
		},
		{
			name: "repeated flags",
			in:   `["--token","a","--token","b","--password=c","--password=d"]`,
			want: `["--token","` + field + `","--token","` + field + `","--password=` + field + `","--password=` + field + `"]`,
		},
		{
			name: "flag access key and private key",
			in:   `["--aws-secret-access-key=opaque","--private-key","k"]`,
			want: `["--aws-secret-access-key=` + field + `","--private-key","` + field + `"]`,
		},
		{
			name: "flag truncated",
			in:   `["--passphrase","hunter`,
			want: `["--passphrase","` + field,
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

// TestRedact_ConfigurationShapeNegatives pins what the #307 rules must leave
// alone: pagination cursors (a prefixed "token" key would break paging), a
// non-credential name/value pair, flags that do not name a credential, and a
// flag-shaped string that is not an array element.
func TestRedact_ConfigurationShapeNegatives(t *testing.T) {
	t.Parallel()

	r := redact.New()
	negatives := []string{
		`{"nextPageToken":"CgwI","items":[]}`,
		`{"pageToken":"CgwI"}`,
		`{"NextToken":"eyAiYSI6IDEgfQ","Functions":[]}`,
		`{"ContinuationToken":"1ueGcxLPRx1Tr"}`,
		`{"name":"DB_HOST","value":"db.internal"}`,
		`{"name":"PASSWORD_FILE_PATH","value":"/run/secrets/db"}`,
		`{"passwordLastUsed":"2026-01-01","isSecret":true}`,
		"- name: DB_HOST\n  value: db.internal\n",
		`["--token-file","/var/run/token","--verbose"]`,
		`["--secret-name","prod-db"]`,
		`["--no-generate-secret","--client-name","example"]`,
		`[{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}},{"value":"x"}]`,
		`{"command":["sleep","3600"]}`,
		`{"text":"--token","public":"data"}`,
		`{"pageToken":"--page-token=CgwI"}`,
		`{"name":"DB_HOST","value":"--api-key=public"}`,
	}
	for _, in := range negatives {
		if got := r.Redact(in); got != in {
			t.Errorf("false positive: %q became %q", in, got)
		}
	}
}
