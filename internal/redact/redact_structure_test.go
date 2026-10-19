package redact_test

import (
	"strconv"
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
	// deep is a command six shells deep with no credential flag in it; the "--"
	// lets the command pass run.
	deep := "x --"
	for range 6 {
		deep = "sh -c '" + strings.ReplaceAll(deep, "'", `'\''`) + "'"
	}
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
			name: "yaml unclosed quote runs to the end of content",
			in:   "x: y\npassword: \"first\n  second\nnext: keep\n",
			want: "x: y\npassword: " + field,
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
			name: "yaml quoted value on the next line holding a colon",
			in:   "password:\n  \"synthetic: secret\"\n- name:\n    DB_PASSWORD\n  value:\n    'a: b'\n",
			want: "password: " + field + "\n- name:\n    DB_PASSWORD\n  value: " + field + "\n",
		},
		{
			name: "yaml quoted value with properties on the next line",
			in:   "password:\n  &pw \"synthetic: secret\"\n- name: DB_PASSWORD\n  value:\n    !!str 'first\ntail: x'\ntoken:\n  &a\n  plain\n",
			want: "password: " + field + "\n- name: DB_PASSWORD\n  value: " + field + "\ntoken: " + field + "\n",
		},
		{
			name: "yaml quoted keys",
			in:   "\"password\": |\n  a\n- \"name\": DB_PASSWORD\n  \"value\": b\n- 'name': 'API_KEY'\n  'value': 'c'\n",
			want: "\"password\": " + field + "\n- \"name\": DB_PASSWORD\n  \"value\": " + field +
				"\n- 'name': 'API_KEY'\n  'value': " + field + "\n",
		},
		{
			name: "pretty printed json pair keeps its quotes",
			in:   "{\n  \"name\": \"DB_PASSWORD\",\n  \"value\": \"x\",\n  \"n\": 1\n}",
			want: "{\n  \"name\": \"DB_PASSWORD\",\n  \"value\": \"" + field + "\",\n  \"n\": 1\n}",
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
			name: "json escaped key after NaN",
			in:   `{"x":NaN,"DB_PASSW\u004fRD":"hunter2"}`,
			want: `{"x":NaN,"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "json pair after Infinity and -Infinity",
			in:   `{"a":[Infinity,-Infinity],"n\u0061me":"DB_PASSWORD","value":"hunter2"}`,
			want: `{"a":[Infinity,-Infinity],"n\u0061me":"DB_PASSWORD","value":"` + field + `"}`,
		},
		{
			name: "json escaped key after NaN in an encoded string",
			in:   `{"b":"{\"x\":NaN,\"DB_PASSW\\u004fRD\":\"hunter2\"}"}`,
			want: `{"b":"{\"x\":NaN,\"DB_PASSW\\u004fRD\":\"` + field + `\"}"}`,
		},
		{
			name: "json NaN after strings that end in escapes",
			in:   `{"a":"\\","b":"\"","x":NaN,"DB_PASSW\u004fRD":"hunter2"}`,
			want: `{"a":"\\","b":"\"","x":NaN,"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "json object after NaN inside a string a read past NaN takes",
			in:   `[NaN,"a {"DB_PASSW\u004fRD":"v"}`,
			want: `[NaN,"a {"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "json object after top-level 1NaN inside a string",
			in:   `{}1NaN"a {"DB_PASSW\u004fRD":"v"}`,
			want: `{}1NaN"a {"DB_PASSW\u004fRD":"` + field + `"}`,
		},
		{
			name: "json key that spells NaN",
			in:   `{"xNaN_s\u0065cret":"hunter2"}`,
			want: `{"xNaN_s\u0065cret":"` + field + `"}`,
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
			name: "shell names that share a run of options",
			in:   `["sh","--rcfile","sh","-o","bash","-c","app --token x","sh","--rcfile","sh","-x","--token","y"]`,
			want: `["sh","--rcfile","sh","-o","bash","-c","app --token ` + field + `","sh","--rcfile","sh","-x","--token","` + field + `"]`,
		},
		{
			// The first shell's options hold a flag's value and the second's do not;
			// the second decides, so the command is read only as shell words.
			name: "the last shell name before a command decides how it is read",
			in:   `["sh","--password","-o","sh","-c","--token=a b"]`,
			want: `["sh","--password","` + field + `","sh","-c","--token=` + field + ` b"]`,
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
			in:   `["sh","-c","app --password x; echo \u0067o"]`,
			want: `["sh","-c","app --password ` + field + `; echo \u0067o"]`,
		},
		{
			name: "shell command with a token spelled with an escape",
			in:   `["sh","-c","app --password x; echo \u0067hp_` + strings.Repeat("a", 36) + `"]`,
			want: `["sh","-c","app --password ` + field + `; echo [REDACTED:github-token]"]`,
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
			want: `["sh","-c","app --token ` + field,
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
			name: "flag value cut at a bad escape after a placeholder",
			in:   `["--password","[REDACTED:credential-field]\qsecret","--token=[REDACTED:jwt]\u+041"]`,
			want: `["--password","` + field + `","--token=` + field + `"]`,
		},
		{
			name: "shell value cut at a bad escape after a placeholder",
			in:   `["sh","-c","app --token [REDACTED:jwt]\qsecret"]`,
			want: `["sh","-c","app --token ` + field + `"]`,
		},
		{
			name: "shell command whose shell name is a flag value",
			in:   `["--pAsswd","sh","-c","--token= "],["--password","sh","-c","app --token secret"]`,
			want: `["--pAsswd","` + field + `","-c","--token=` + field + `"],` +
				`["--password","` + field + `","-c","app --token ` + field + `"]`,
		},
		{
			// A value a shell may expand runs to the end of the command (#404).
			name: "shell command value with a command substitution",
			in: `["sh","-c","app --password=$(printf '%s' \"a)\" | (cat)) b; x --token ` + "`cat f`" +
				` y; z --token $(z"]`,
			want: `["sh","-c","app --password=` + field + `"]`,
		},
		{
			name: "shell command substitution edge 1",
			in:   "[\"sh\", \"-c\", \"a --token `x\\\\`y` b; c --token $(e \\\\) \\\"q\\\\\\\"r) \\\" s) d; e --token $(f \\\"open\"]",
			want: "[\"sh\", \"-c\", \"a --token [REDACTED:credential-field]\"]",
		},
		{
			name: "shell command started inside a shell command",
			in:   `["sh","-c","bash -c 'app --password hunter2' && echo ok"]`,
			want: `["sh","-c","bash -c ` + field + ` && echo ok"]`,
		},
		{
			name: "shell command started three shells deep",
			in:   `["sh","-c","sh -c \"bash -ec 'app --token=x' --\"; echo ok"]`,
			want: `["sh","-c","sh -c ` + field + `; echo ok"]`,
		},
		{
			name: "shell command nested past the depth bound",
			in:   `["sh","-c",` + strconv.Quote(deep) + `]`,
			want: `["sh","-c","sh -c ` + field + `"]`,
		},
		{
			name: "shell command flag inside a command substitution",
			in:   `["sh","-c","echo $(app --password hunter2) done"]`,
			want: `["sh","-c","echo $(app --password ` + field + `) done"]`,
		},
		{
			name: "shell command flag inside a backquoted substitution",
			in:   "[\"sh\",\"-c\",\"echo `app --token hunter2` done\"]",
			want: `["sh","-c","echo ` + field + `"]`,
		},
		{
			name: "shell command value in a process substitution",
			in:   `["sh","-c","app --password <(printf hunter2) next"]`,
			want: `["sh","-c","app --password ` + field + `"]`,
		},
		{
			name: "shell command value after a redirection",
			in:   `["sh","-c","app --password  < /run/secret next"]`,
			want: `["sh","-c","app --password  ` + field + `"]`,
		},
		{
			name: "shell command value with a parameter expansion",
			in:   `["sh","-c","app --password=${X:-hunter 2} next"]`,
			want: `["sh","-c","app --password=` + field + `"]`,
		},
		{
			name: "shell command value with ANSI-C quoting",
			in:   `["sh","-c","app --password=$'hunter\\' 2' next"]`,
			want: `["sh","-c","app --password=` + field + `"]`,
		},
		{
			name: "shell command expanded value inside double quotes",
			in:   `["sh","-c","app \"--token=$T x\" next"]`,
			want: `["sh","-c","app \"--token=` + field + `\""]`,
		},
		{
			name: "yaml double-quoted key",
			in:   "\"password\": hunter2 # c\n",
			want: "\"password\": " + field + " # c\n",
		},
		{
			name: "yaml double-quoted key spelled with escapes",
			in:   "\"pass\\x77or\\u0064\": hunter2\n'api_key': 'it''s'\n",
			want: "\"pass\\x77or\\u0064\": " + field + "\n'api_key': " + field + "\n",
		},
		{
			name: "yaml pair whose name is spelled with escapes",
			in:   "- name: \"DB_PASS\\x57ORD\"\n  value: hunter2\n",
			want: "- name: \"DB_PASS\\x57ORD\"\n  value: " + field + "\n",
		},
		{
			name: "yaml explicit key",
			in:   "? password\n: hunter2\n- ? \"api\\x5fkey\"\n  # c\n  :\n    hunter2\n    more\nnext: x\n",
			want: "? password\n: " + field + "\n- ? \"api\\x5fkey\"\n  # c\n  : " + field + "\nnext: x\n",
		},
		{
			name: "yaml flow mapping pair in a sequence",
			in:   "env:\n- {name: DB_PASSWORD, value: hunter2}\n- {name: DB_HOST, value: db}\n",
			want: "env:\n- {name: DB_PASSWORD, value: " + field + "}\n- {name: DB_HOST, value: db}\n",
		},
		{
			name: "yaml flow mappings over lines",
			in:   "env: [{value: 'hunter2',\n  # c\n  name: DB_PASSWORD}, {password: \"a\n b\", token: [a]}]\n",
			want: "env: [{value: " + field + ",\n  # c\n  name: DB_PASSWORD}, {password: " + field + ", token: [a]}]\n",
		},
		{
			name: "yaml flow one-pair mapping, properties and an explicit key",
			in:   "x: [password: &a !t hunter2 # c\n , {? api_key : k}]\n",
			want: "x: [password: &a !t " + field + " # c\n , {? api_key : " + field + "}]\n",
		},
		{
			name: "yaml flow mapping cut off",
			in:   "x: {name: DB_PASSWORD, secret: \"a, value: hunt",
			want: "x: {name: DB_PASSWORD, secret: " + field,
		},
		{
			name: "yaml flow mapping closed by the wrong bracket",
			in:   "x: {name: DB_PASSWORD, value: hunter2]\n",
			want: "x: {name: DB_PASSWORD, value: " + field + "]\n",
		},
		{
			name: "yaml flow mapping cut off in a comment",
			in:   "x: {name: DB_PASSWORD, value: hunter2 # c",
			want: "x: {name: DB_PASSWORD, value: " + field + " # c",
		},
		{
			name: "quoted key with an escape only YAML defines",
			in:   "\"pass\\x77ord\": \"hunter2\"\nx: {\"api\\x5fkey\": \"k\"}\n",
			want: "\"pass\\x77ord\": " + field + "\nx: {\"api\\x5fkey\": " + field + "}\n",
		},
		{
			name: "shell options after the command option",
			in:   `["sh","-c","-e","--","app --token x"]`,
			want: `["sh","-c","-e","--","app --token ` + field + `"]`,
		},
		{
			name: "flag that is an option's argument before the command",
			in:   `["sh","-c","-o","--token","x y","+O","--password","z"]`,
			want: `["sh","-c","-o","--token","` + field + `","+O","--password","` + field + `"]`,
		},
		{
			name: "nested shell options after the command option",
			in:   `["sh","-c","bash -c -o pipefail -- 'app --password x'; bash -ce"]`,
			want: `["sh","-c","bash -c -o pipefail -- ` + field + `; bash -ce"]`,
		},
		{
			name: "nested shell whose command word overlaps an expanded value",
			in:   `["sh","-c","echo sh -c --password=$(printf hunter2)"]`,
			want: `["sh","-c","echo sh -c ` + field + `"]`,
		},
		{
			name: "flow mapping mixing plain and JSON-string keys",
			in:   "x: {name: DB_PASSWORD, \"value\": \"a\"}\ny: {public: b, \"pass\\u0077ord\": \"c\", \"pageToken\": \"d\"}\n",
			want: "x: {name: DB_PASSWORD, \"value\": \"" + field + "\"}\ny: {public: b, \"pass\\u0077ord\": \"" + field +
				"\", \"pageToken\": \"d\"}\n",
		},
		{
			name: "yaml block value under an escaped JSON-string key",
			in:   "a: b\n\"pass\\u0077ord\": \"c\",\n\"token\": 12\n",
			want: "a: b\n\"pass\\u0077ord\": \"" + field + "\",\n\"token\": 12\n",
		},
		{
			name: "flow collections after explicit, value and document markers",
			in:   "? env\n: {password: a}\n--- {token: b}\n? [api_key: c]\n",
			want: "? env\n: {password: " + field + "}\n--- {token: " + field + "}\n? [api_key: " + field + "]\n",
		},
		{
			name: "flow value after a verbatim tag",
			in:   "x: {password: !<tag:yaml.org,2002:str> a}\n",
			want: "x: {password: !<tag:yaml.org,2002:str> " + field + "}\n",
		},
		{
			name: "flow name joined over lines with an escaped line break",
			in:   "x: {name: \"DB_PASS\\\n  WORD\", value: a}\ny: {name: \"API_\\\r\n\tKEY\", value: b}\n",
			want: "x: {name: \"DB_PASS\\\n  WORD\", value: " + field + "}\ny: {name: \"API_\\\r\n\tKEY\", value: " + field + "}\n",
		},
		{
			name: "shell option run that takes an argument",
			in:   `["bash","-c","-eo","pipefail","app --password a","bash","-ceo","pipefail","app --token b"]`,
			want: `["bash","-c","-eo","pipefail","app --password ` + field + `","bash","-ceo","pipefail","app --token ` + field + `"]`,
		},
		{
			name: "json object at the start of a line with a constant JSON does not define",
			in:   `{"x":-NaN,"DB_PASSW\u004fRD":"v","password":NaN}`,
			want: `{"x":-NaN,"DB_PASSW\u004fRD":"` + field + `","password":` + field + `}`,
		},
		{
			name: "prefixed token under a JSON-string key with a value that is not a JSON string",
			in:   "{\n  \"authToken\": |\n    a\n}\n\"authToken\": b\nx: {\"authToken\": c, \"pageToken\": \"d\"}\n",
			want: "{\n  \"authToken\": " + field + "\n}\n\"authToken\": " + field + "\nx: {\"authToken\": " + field +
				", \"pageToken\": \"d\"}\n",
		},
		{
			name: "shell option run taking two arguments",
			in:   `["bash","-coO","pipefail","extglob","app --password a"]`,
			want: `["bash","-coO","pipefail","extglob","app --password ` + field + `"]`,
		},
		{
			name: "joined spans followed by an empty one",
			in:   `["sh","-c","echo sh -c '--password=$(printf hunter2)' --token="]`,
			want: `["sh","-c","echo sh -c ` + field + `"]`,
		},
		{
			name: "shell value with an operator right after it",
			in:   `["sh","-c","app --password=<(printf a) next; b"]`,
			want: `["sh","-c","app --password=` + field + `"]`,
		},
		{
			name: "shell value with an operator right after a separate value",
			in:   `["sh","-c","app --token x>(y) next"]`,
			want: `["sh","-c","app --token ` + field + `"]`,
		},
		{
			name: "command substitutions inside double quotes",
			in:   "[\"sh\",\"-c\",\"echo \\\"$X$(app --token a)\\\" and \\\"`app --password b`\\\" done\"]",
			want: `["sh","-c","echo ` + field + `"]`,
		},
		{
			name: "flow comments after a property and after a comma",
			in:   "x: {name: &n # c\n DB_PASSWORD, value: a}\ny: {name: DB_PASSWORD,# c\n value: b}\n",
			want: "x: {name: &n # c\n DB_PASSWORD, value: " + field + "}\ny: {name: DB_PASSWORD,# c\n value: " + field + "}\n",
		},
		{
			name: "flow collection under a plain key holding a slash or a space",
			in:   "config/app.yaml: {password: a}\napp config: [token: b]\n",
			want: "config/app.yaml: {password: " + field + "}\napp config: [token: " + field + "]\n",
		},
		{
			name: "explicit quoted key over several lines",
			in:   "? \"pass\\\n  word\" # c\n: a\n? 'api_key'\n: b\n",
			want: "? \"pass\\\n  word\" # c\n: " + field + "\n? 'api_key'\n: " + field + "\n",
		},
		{
			name: "flow value spelled with a leading hash right after the colon",
			in:   "{\"password\":#a}\nx: {\"token\":#b, c: d}\n",
			want: "{\"password\":" + field + "}\nx: {\"token\":" + field + ", c: d}\n",
		},
		{
			name: "flow comment right after a key or a collection",
			in:   "x: {\"password\"#c\n: a}\ny: {k: [b]#c\n password: c}\n",
			want: "x: {\"password\"#c\n: " + field + "}\ny: {k: [b]#c\n password: " + field + "}\n",
		},
		{
			name: "flow hash that opens no comment hides nothing after it",
			in:   "x: {a: \"b\"#, password: c}\ny: {d: e,#f, token: g}\n",
			want: "x: {a: \"b\"#, password: " + field + "}\ny: {d: e,#f, token: " + field + "}\n",
		},
		{
			name: "command substitution whose quotes nest inside the word's",
			in:   `["sh","-c","echo \"$(app --password \"sword fish\")\" done"]`,
			want: `["sh","-c","echo ` + field + `"]`,
		},
		{
			name: "command substitution with a quoted argument before the flag",
			in:   `["sh","-c","echo \"$(app \"a b\" --password c)\" done"]`,
			want: `["sh","-c","echo ` + field + `"]`,
		},
		{
			name: "flow collection under a plain key holding a hash",
			in:   "config/app#v1.yaml: {password: a}\n",
			want: "config/app#v1.yaml: {password: " + field + "}\n",
		},
		{
			name: "json pair with an unquoted value",
			in:   `{"name":"DB_PASSWORD","value":hunter2}`,
			want: `{"name":"DB_PASSWORD","value":` + field + `}`,
		},
		{
			name: "shell command substitution edge 2",
			in:   "[\"sh\", \"-c\", \"g --token `zz\"]",
			want: "[\"sh\", \"-c\", \"g --token [REDACTED:credential-field]\"]",
		},
		{
			name: "shell command substitution edge 3",
			in:   "[\"sh\", \"-c\", \"h --token $(i 'open\"]",
			want: "[\"sh\", \"-c\", \"h --token [REDACTED:credential-field]\"]",
		},
		{
			name: "flag value starting with two dashes before a positional argument",
			in:   `["app","--password","--hunter2","input.txt"],["sh","-c","app --password --hunter2 input.txt"]`,
			want: `["app","--password","` + field + `","input.txt"],["sh","-c","app --password ` + field + ` input.txt"]`,
		},
		{
			name: "shell command after other shell options",
			in:   `["sh","-x","-c","app --password a"],["bash","--noprofile","-o","pipefail","-ec","app --token b"]`,
			want: `["sh","-x","-c","app --password ` + field + `"],` +
				`["bash","--noprofile","-o","pipefail","-ec","app --token ` + field + `"]`,
		},
		{
			name: "flag hyphens spelled with json escapes",
			in:   `["\u002d\u002Dpassword","a"],["sh","-c","app \u002d\u002dtoken b"]`,
			want: `["\u002d\u002Dpassword","` + field + `"],["sh","-c","app \u002d\u002dtoken ` + field + `"]`,
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
		// Text before each object keeps the YAML flow pass off it, so these pin the
		// JSON object pass alone.
		`got {"x":-NaN,"DB_PASSW\u004fRD":"v"}`,
		`got {"x":1NaN,"DB_PASSW\u004fRD":"v"}`,
		`got {"x":NaN1,"DB_PASSW\u004fRD":"v"}`,
		`got {"x":nan,"DB_PASSW\u004fRD":"v"}`,
		"{\n  \"nextPageToken\": \"a\",\n  \"n\\u0065xtToken\": \"b\"\n}\nx: {\"pageToken\": \"c\"}\n",
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
		`["sh","-x","app --token x"]`,
		"{\n  \"name\": \"DB_PASSWORD\",\n  \"value\": 123\n}",
		`["sh","-o"]`,
		`["sh",""]`,
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
		"x: {name: DB_HOST, value: public, token: [a, b], secret: {k: v}}\n",
		"x: [name: DB_PASSWORD, value: public]\n",
		"x: {name: DB_PASSWORD, nested: {value: public}}\n",
		"x: {password: [REDACTED:jwt], api_key: \"[REDACTED:jwt]\", key: a:b}\n",
		"? public\n: value\n? password\n  : nested\n",
		"\"pass\\qword\": public\n",
		"x: [REDACTED:jwt]\n",
		"? \n: x\n",
		"? 'pass: x\n  # c\n",
		"? \"password\" x\n: public\n",
		"Note: see {\"a\": 1} and [b: c]\n",
		"a #b: {password: public}\n",
		`["sh","-c","echo '$(cat x)' $(date) ` + "`date`" + ` --page x"]`,
		"x: {password: &a}\n",
		"? password # a: b\n# c\n",
		"- name: \"DB_PASSWORD\\\"\n  value: public\n",
		"\"pass\\2word\": public\n\"\\x4\": a\n\"\\xZZ\": b\n\"\\UFFFFFFFF\": c\n\"\\N\\_\\L\\P\": d\n",
		`["sh","-c","app --password=[REDACTED:jwt] && sh -c 'app --token [REDACTED:jwt]'"]`,
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
