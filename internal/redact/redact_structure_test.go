package redact_test

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestRedact_StructuredCredentialShapes pins the exact output for the shapes the
// line and key regexes alone missed (#401): a YAML pair with a comment or another
// field between its members, a multi-line YAML value, a JSON name spelled with
// escapes or repeated, a credential flag inside a shell command string, and a
// flag value that itself starts with "--". Each case also checks that a second
// pass changes nothing.
func TestRedact_StructuredCredentialShapes(t *testing.T) {
	t.Parallel()

	const field = "[REDACTED:credential-field]"

	pat := "ghp_" + strings.Repeat("a", 36)
	r := redact.New()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "yaml pair with a comment on the name line",
			in:   "- name: DB_PASSWORD # db password\n  value: hunter2\n",
			want: "- name: DB_PASSWORD # db password\n  value: " + field + "\n",
		},
		{
			name: "yaml value name pair with a comment on the name line",
			in:   "- value: hunter2\n  name: 'DB_PASSWORD' # db\r\n",
			want: "- value: " + field + "\n  name: 'DB_PASSWORD' # db\r\n",
		},
		{
			name: "yaml pair with a comment line and a field between",
			in:   "env:\n  - name: DB_PASSWORD\n    # from vault\n    type: PLAINTEXT\n    value: hunter2\n  - name: DB_HOST\n    value: db\n",
			want: "env:\n  - name: DB_PASSWORD\n    # from vault\n    type: PLAINTEXT\n    value: " + field +
				"\n  - name: DB_HOST\n    value: db\n",
		},
		{
			name: "yaml pair in a mapping that is not a sequence item",
			in:   "secretEnv:\n  name: API_KEY\n  value: k3y\nother: x\n",
			want: "secretEnv:\n  name: API_KEY\n  value: " + field + "\nother: x\n",
		},
		{
			name: "yaml pair with a block scalar value",
			in:   "- name: DB_PASSWORD\n  value: |\n    hunter2\n    more\n- name: DB_HOST\n  value: db\n",
			want: "- name: DB_PASSWORD\n  value: " + field + "\n- name: DB_HOST\n  value: db\n",
		},
		{
			name: "yaml value name pair with a block scalar value",
			in:   "- value: >-\n    hunter2\n  name: DB_PASSWORD\n",
			want: "- value: " + field + "\n  name: DB_PASSWORD\n",
		},
		{
			name: "yaml pair with a quoted value continued at a lower indent",
			in:   "- value: \"first\nTAIL\"\n  name: DB_PASSWORD\n",
			want: "- value: " + field + "\n  name: DB_PASSWORD\n",
		},
		{
			name: "yaml block scalar keeps a trailing blank line",
			in:   "  token: >-\n    a\n\n    b\n\n  public: x\n",
			want: "  token: " + field + "\n\n  public: x\n",
		},
		{
			name: "yaml block scalar crlf",
			in:   "password: |\r\n  a\r\n  b\r\nx: y\r\n",
			want: "password: " + field + "\r\nx: y\r\n",
		},
		{
			name: "yaml double quoted value continued at the root",
			in:   "password: \"first\\\" \nTAIL\"\nnext: keep\n",
			want: "password: " + field + "\nnext: keep\n",
		},
		{
			name: "yaml single quoted value continued",
			in:   "  db_password: 'it''s\n    more' # c\n  x: y\n",
			want: "  db_password: " + field + " # c\n  x: y\n",
		},
		{
			name: "yaml unclosed quote stops at the indentation",
			in:   "password: \"first\n  second\nnext: keep\n",
			want: "password: " + field + "\nnext: keep\n",
		},
		{
			name: "yaml quoted value with lines after the closing quote",
			in:   "password: \"\"\n 00\nx: y\n",
			want: "password: " + field + "\nx: y\n",
		},
		{
			name: "yaml plain value continued",
			in:   "- password: abc\n    def\n  x: y\n",
			want: "- password: " + field + "\n  x: y\n",
		},
		{
			name: "yaml value on the next line",
			in:   "password:\n  hunter2\nx: y\n",
			want: "password: " + field + "\nx: y\n",
		},
		{
			name: "yaml continued value after a token label",
			in:   "password: " + pat + "\n  tail\n",
			want: "password: " + field + "\n",
		},
		{
			name: "yaml block scalar swallows a credential key inside it",
			in:   "password: |\n  first\n  api_key: |\n    tail\npublic: keep\n",
			want: "password: " + field + "\npublic: keep\n",
		},
		{
			name: "yaml value on the next line after a blank line",
			in:   "password: # c\n\n  hunter2\nx: y\n",
			want: "password: " + field + "\nx: y\n",
		},
		{
			name: "yaml pair with a nested mapping before the value",
			in:   "- name: DB_PASSWORD\n  meta:\n    a: b\n  value: x\n",
			want: "- name: DB_PASSWORD\n  meta:\n    a: b\n  value: " + field + "\n",
		},
		{
			name: "yaml value name pair with a nested mapping between",
			in:   "- value: x\n  meta:\n    a: b\n  name: DB_PASSWORD\n",
			want: "- value: " + field + "\n  meta:\n    a: b\n  name: DB_PASSWORD\n",
		},
		{
			name: "yaml re-read after a regex rewrote a closing quote",
			in:   "0: \"\ntoken:\n 0ApikeY:\"",
			want: "0: \"\ntoken: " + field,
		},
		{
			name: "yaml pair inside a block scalar",
			in:   "data:\n  config.yaml: |\n    - name: DB_PASSWORD\n      value: synthetic-secret\n",
			want: "data:\n  config.yaml: |\n    - name: DB_PASSWORD\n      value: " + field + "\n",
		},
		{
			name: "yaml pair with an indented comment line between",
			in:   "- name: DB_PASSWORD\n    # comment\n  value: synthetic-secret\n",
			want: "- name: DB_PASSWORD\n    # comment\n  value: " + field + "\n",
		},
		{
			name: "yaml value on the next line after a comment line",
			in:   "password:\n# comment\n  synthetic-secret\nnext: public\n",
			want: "password: " + field + "\nnext: public\n",
		},
		{
			name: "yaml quoted value starting on the next line",
			in:   "password:\n  \"first\nsynthetic-tail\"\nnext: public\n",
			want: "password: " + field + "\nnext: public\n",
		},
		{
			name: "yaml block scalar with a line starting with a hash",
			in:   "password: |\n  a\n  # b\nx: y\n",
			want: "password: " + field + "\nx: y\n",
		},
		{
			name: "yaml continued value after a placeholder",
			in:   "password: [REDACTED:jwt]\n  tail\n",
			want: "password: " + field + "\n",
		},
		{
			name: "yaml block scalar after an anchor",
			in:   "password: &pw |\n  # synthetic-secret\nnext: public\n",
			want: "password: " + field + "\nnext: public\n",
		},
		{
			name: "yaml quoted value after a tag",
			in:   "password: !!str \"first\nsynthetic-tail\"\nnext: public\n",
			want: "password: " + field + "\nnext: public\n",
		},
		{
			name: "yaml pair value with an anchor",
			in:   "- name: DB_PASSWORD\n  value: &pw |\n    # s\n",
			want: "- name: DB_PASSWORD\n  value: " + field + "\n",
		},
		{
			name: "yaml pair with the name on the next line",
			in:   "- name:\n    DB_PASSWORD # c\n  value: synthetic-secret\n",
			want: "- name:\n    DB_PASSWORD # c\n  value: " + field + "\n",
		},
		{
			name: "json escaped key",
			in:   `{"DB_PASSW\u004fRD":"hunter2","public":"x"}`,
			want: `{"DB_PASSW\u004fRD":"` + field + `","public":"x"}`,
		},
		{
			name: "json escaped key truncated",
			in:   `{"DB_PASSW\u004fRD":"hunter2`,
			want: `{"DB_PASSW\u004fRD":"` + field,
		},
		{
			name: "json escaped pair name and member",
			in:   `[{"n\u0061me":"DB_PASSW\u004fRD","v\u0061lue":"hunter2"}]`,
			want: `[{"n\u0061me":"DB_PASSW\u004fRD","v\u0061lue":"` + field + `"}]`,
		},
		{
			name: "json duplicate value after the name",
			in:   `{"name":"DB_PASSWORD","value":"a","value":"b"}`,
			want: `{"name":"DB_PASSWORD","value":"` + field + `","value":"` + field + `"}`,
		},
		{
			name: "json duplicate value before the name",
			in:   `{"value":"a", "value" : "b","name":"DB_PASSWORD"}`,
			want: `{"value":"` + field + `", "value" : "` + field + `","name":"DB_PASSWORD"}`,
		},
		{
			name: "json duplicate name",
			in:   `{"name":"DB_PASSWORD","value":"a","name":"DB_HOST","value":"b"}`,
			want: `{"name":"DB_PASSWORD","value":"` + field + `","name":"DB_HOST","value":"` + field + `"}`,
		},
		{
			name: "json pair with a nested object and number between",
			in:   `{"items":[{"name":"DB_PASSWORD","meta":{"a":[1,2e999]},"value":"x"}]}`,
			want: `{"items":[{"name":"DB_PASSWORD","meta":{"a":[1,2e999]},"value":"` + field + `"}]}`,
		},
		{
			name: "json pair truncated after its name",
			in:   `{"name":"DB_PASSWORD","meta":{},"value":"hunt`,
			want: `{"name":"DB_PASSWORD","meta":{},"value":"` + field,
		},
		{
			name: "shell command flag",
			in:   `{"command":["sh","-c","app --token x --port 80"]}`,
			want: `{"command":["sh","-c","app --token ` + field + ` --port 80"]}`,
		},
		{
			name: "shell command joined flag with a quoted value",
			in:   `["/bin/bash","-ec","app --password='a b' && run"]`,
			want: `["/bin/bash","-ec","app --password=` + field + ` && run"]`,
		},
		{
			name: "shell command escaped double quoted and backslash values",
			in:   `["sh", "-c", "app --db-password \"a \\\" b\" --api-key a\\ b\tnext"]`,
			want: `["sh", "-c", "app --db-password ` + field + ` --api-key ` + field + `\tnext"]`,
		},
		{
			name: "shell command value with a single leading dash",
			in:   `["sh","-c","app --token -abc"]`,
			want: `["sh","-c","app --token ` + field + `"]`,
		},
		{
			name: "shell command truncated",
			in:   `["sh","-c","app --token hunt`,
			want: `["sh","-c","app --token ` + field,
		},
		{
			name: "shell command truncated after a backslash",
			in:   `["sh","-c","app --token hunt\`,
			want: `["sh","-c","app --token ` + field + `\`,
		},
		{
			name: "shell command with an unclosed single quote",
			in:   `["sh","-c","app --token 'abc"]`,
			want: `["sh","-c","app --token ` + field + `"]`,
		},
		{
			name: "shell command that is itself a joined flag",
			in:   `["sh","-c","--token=x"]`,
			want: `["sh","-c","--token=` + field + `"]`,
		},
		{
			name: "shell command joined flag before a space at the cut",
			in:   `["sh","-c","--pAsswd=x `,
			want: `["sh","-c","--pAsswd=` + field + ` `,
		},
		{
			name: "flag before a shell command element",
			in:   `["sh","-c","--token","x"]`,
			want: `["sh","-c","--token","` + field + `"]`,
		},
		{
			name: "shell command flag spelled with quotes and a backslash",
			in:   `["sh","-c","app \"--password\" a; app --pass\"word\" b; app --pass\\word c"]`,
			want: `["sh","-c","app \"--password\" ` + field + `; app --pass\"word\" ` + field + `; app --pass\\word ` + field + `"]`,
		},
		{
			name: "shell command value with a carriage return",
			in:   `["sh","-c","app --password first\rsynthetic-tail"]`,
			want: `["sh","-c","app --password ` + field + `"]`,
		},
		{
			name: "shell command keeps escapes and operators outside the value",
			in:   `["sh","-c","app --password x; echo \u0067hp_` + strings.Repeat("a", 36) + `"]`,
			want: `["sh","-c","app --password ` + field + `; echo \u0067hp_` + strings.Repeat("a", 36) + `"]`,
		},
		{
			name: "shell command joined flag with an escaped quoted value",
			in:   `["sh","-c","app --password=\"a b\"z\u0020next"]`,
			want: `["sh","-c","app --password=` + field + `\u0020next"]`,
		},
		{
			name: "shell command read up to an invalid escape",
			in:   `["sh","-c","app --token x \q --password y"]`,
			want: `["sh","-c","app --token ` + field + ` \q --password y"]`,
		},
		{
			name: "shell command read up to an escape cut at the cap",
			in:   `["sh","-c","app --token x\u00`,
			want: `["sh","-c","app --token ` + field + `\u00`,
		},
		{
			name: "shell command joined flag inside quotes",
			in:   `["sh","-c","app \"--password=a b\" next '--token=c d' e"]`,
			want: `["sh","-c","app \"--password=` + field + `\" next '--token=` + field + `' e"]`,
		},
		{
			name: "shell command joined flag with a quoted empty value at the cut",
			in:   `,"sh","-c","--pAsswd\"=\" `,
			want: `,"sh","-c","--pAsswd\"=` + field + `\" `,
		},
		{
			name: "flag array read after an env rule removed a quote",
			in:   "pAsswd=,\"\r,\"--pAsswd=x",
			want: "pAsswd=" + field + "\r,\"--pAsswd=" + field,
		},
		{
			name: "shell command flag joined across a backslash newline",
			in:   `["sh","-c","app --pass\\\nword a; app \"--pass\\\nword\" b; app --token \\\n c"]`,
			want: `["sh","-c","app --pass\\\nword ` + field + `; app \"--pass\\\nword\" ` + field +
				`; app --token \\\n ` + field + `"]`,
		},
		{
			name: "flag spelled with json escapes",
			in:   `["--passw\u006frd","a","--passw\u006frd=b\u0020c"]`,
			want: `["--passw\u006frd","` + field + `","--passw\u006frd=` + field + `"]`,
		},
		{
			name: "shell spelled with json escapes",
			in:   `["/bin\/sh","-c","app --password a"],["\u0073h","-\u0063","app --password b"]`,
			want: `["/bin\/sh","-c","app --password ` + field + `"],["\u0073h","-\u0063","app --password ` + field + `"]`,
		},
		{
			name: "shell command with an empty quoted value",
			in:   `["sh","-c","app --password \"\""]`,
			want: `["sh","-c","app --password ` + field + `"]`,
		},
		{
			name: "flag value starting with two dashes",
			in:   `["--password","--x"]`,
			want: `["--password","` + field + `"]`,
		},
		{
			name: "flag value spelled like a credential flag",
			in:   `["--password","--token"]`,
			want: `["--password","` + field + `"]`,
		},
		{
			name: "flag value that is a joined flag with an empty value",
			in:   `["--token","--pAsswd="]`,
			want: `["--token","` + field + `"]`,
		},
		{
			name: "flag value starting with two dashes before another flag",
			in:   `["--generate-secret","--password","--x"]`,
			want: `["--generate-secret","` + field + `","` + field + `"]`,
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

// TestRedact_StructuredShapeNegatives pins what the #401 passes must leave alone:
// a nested mapping or list under a credential-named YAML key, a pair split across
// two mappings, escaped pagination cursors, a non-credential duplicate pair, a
// command that is not run by a shell, and shell flags that name no credential.
func TestRedact_StructuredShapeNegatives(t *testing.T) {
	t.Parallel()

	r := redact.New()
	negatives := []string{
		"volumes:\n- name: db\n  secret:\n    secretName: db-creds\n",
		"token:\n  - a\n",
		"password:\n\n",
		"password:\nnext: x\n",
		"items:\n  - name: DB_PASSWORD # c\nvalue: public\n",
		"- name: DB_PASSWORD\n- value: public\n",
		"- name: DB_HOST # c\n  value: db.internal\n",
		"name: DB_PASSWORD\n  value: nested\n",
		`{"n\u0065xtPageToken":"CgwI","items":[]}`,
		`{"name":"DB_HOST","value":"a","value":"b"}`,
		`{"name":"DB_PASSWORD","valueFrom":{"value":"x"}}`,
		`{"value":1,"name":"DB_PASSWORD","nested":{"value":"x"}}`,
		`{"a":"\q","DB_PASSWORD":1}`,
		`{"DB_PASSW\u004fRD" "x`,
		"secret:\n  # comment\n  secretName: public-reference\n",
		"secret:\n  \"secretName\": public-reference\n",
		"token:\n  [public-reference]\n",
		"token: [\n  public-reference\n]\nnext: public\n",
		`["sh","-c","echo ok # --token public"]`,
		`["sh","-c","app --password"]`,
		`["sh","-c","app --token \u00zz"]`,
		"secret:\n  café: public\n",
		"password:\n  foo/bar: public\n",
		"- name: &n\n  value: public\n",
		"name:\n  DB_PASSWORD\n  more\nvalue: public\n",
		`["echo","app --token x"]`,
		`["sh","-c","app --token-file /t --verbose"]`,
		`["sh","-c","app --password"]`,
		`["sh","-c",1]`,
		`[1,"-c","app --token x"]`,
		`{"sh":"-c","x":"app --token x"}`,
		`["--password"]`,
		`["--password",1]`,
		`["--token","[REDACTED:github-token]"]`,
		`["--no-generate-secret","--client-name","example"]`,
	}
	for _, in := range negatives {
		if got := r.Redact(in); got != in {
			t.Errorf("false positive: %q became %q", in, got)
		}
	}
}

// TestRedactPreservingLocation_StructuralPass redacts an escaped JSON key in a
// body that also carries a preserved Location, so the stash must not break the
// structural JSON pass.
func TestRedactPreservingLocation_StructuralPass(t *testing.T) {
	t.Parallel()

	in := `{"Location":["https://e.test/x?sig=abc"],"DB_PASSW\u004fRD":"hunter2"}`
	want := `{"Location":["https://e.test/x?sig=abc"],"DB_PASSW\u004fRD":"[REDACTED:credential-field]"}`

	if got := redact.New().RedactPreservingLocation(in); got != want {
		t.Fatalf("RedactPreservingLocation(%q)\n got %q\nwant %q", in, got, want)
	}
}

// TestRedactPreservingLocation_SuppliedSentinel redacts content that already holds
// the sentinel delimiter like Redact does, so a supplied sentinel cannot move a
// restored URL elsewhere.
func TestRedactPreservingLocation_SuppliedSentinel(t *testing.T) {
	t.Parallel()

	in := "{\"public\":\"\ue000cynative-loc-0\ue000\",\"Location\":[\"https://e.test/x?sig=abc\"]}"
	want := "{\"public\":\"\ue000cynative-loc-0\ue000\",\"Location\":[\"https://e.test/x?sig=[REDACTED:signed-url-signature]\"]}"

	r := redact.New()
	if got := r.RedactPreservingLocation(in); got != want {
		t.Fatalf("RedactPreservingLocation(%q)\n got %q\nwant %q", in, got, want)
	}
}
