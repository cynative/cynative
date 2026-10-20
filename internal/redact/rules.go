package redact

import "regexp"

// placeholder renders a type-labeled redaction marker.
func placeholder(label string) string { return "[REDACTED:" + label + "]" }

// rule is one redaction pattern: run re only when one of keywords is present
// (a cheap pre-gate over multi-MiB bodies), then ReplaceAllString with repl.
// For whole-match rules repl is the literal placeholder; for capture rules repl
// is a template using ${1}/${2} so the surrounding key/param is preserved. A
// structural rule sets fn instead of re and rewrites the content itself.
type rule struct {
	keywords []string
	re       *regexp.Regexp
	repl     string
	fn       func(string) string
}

// contentRules returns the body/value redaction rules in application order.
// Whole-match token & structural rules first, then value-substitution rules.
func contentRules() []rule {
	return []rule{
		// PEM private key, through the END marker or to the end of the JSON string
		// or content it sits in (see pemKeys).
		{keywords: []string{"PRIVATE KEY"}, fn: newPEMKeys().apply},
		// Base64-encoded PEM block (kubeconfig client-key-data, k8s secret data, …):
		// "LS0tLS1CRUdJTi" is the base64 of the "-----BEGIN " marker, a stable,
		// low-false-positive prefix, so a base64'd private key is caught whatever
		// the surrounding key name, which the keyword-based field rules cannot see.
		// The trailing group consumes newline-wrapped continuation lines so a base64
		// block split at 64 columns is redacted whole, not just its first line.
		{
			keywords: []string{"LS0tLS1CRUdJTi"},
			// Continuation lines require ≥32 base64 chars so a following short token
			// (a "users:" / "name:" key line) is not swallowed, while real 64-column
			// wrapped lines are. A final partial line <32 chars may be left, which is
			// a non-reconstructable key tail. Inside a JSON string a line break or tab
			// is spelled \n, \r or \t and "/" may be spelled \/, with more
			// backslashes in a string encoded inside another, so a run of backslashes
			// before one of those letters is read as that character (#419). The
			// \uXXXX spelling of these characters is not read.
			re: regexp.MustCompile(`LS0tLS1CRUdJTi(?:[A-Za-z0-9+/=]|\\+/)+` +
				`(?:(?:[ \t]|\\+t)*(?:\r?\n|(?:\\+r)?\\+n)(?:[ \t]|\\+t)*(?:[A-Za-z0-9+/=]|\\+/){32,})*`),
			repl: placeholder("base64-pem"),
		},
		// JWT: signature segment optional so a payload-truncated token is still redacted.
		{
			keywords: []string{"eyJ"},
			re:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?`),
			repl:     placeholder("jwt"),
		},
		{
			keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
			re:       regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82,})`),
			repl:     placeholder("github-token"),
		},
		{
			keywords: []string{"glpat-"},
			re:       regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
			repl:     placeholder("gitlab-token"),
		},
		{
			keywords: []string{"xox", "xapp-"},
			re:       regexp.MustCompile(`(?:xox[baprse]-|xapp-)[A-Za-z0-9-]{10,}`),
			repl:     placeholder("slack-token"),
		},
		{
			keywords: []string{"AIza"},
			re:       regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
			repl:     placeholder("google-api-key"),
		},
		{
			keywords: []string{"ya29."},
			re:       regexp.MustCompile(`ya29\.[A-Za-z0-9_-]{20,}`),
			repl:     placeholder("google-oauth-token"),
		},
		{
			keywords: []string{"AKIA", "ASIA", "AROA", "AIDA"},
			re:       regexp.MustCompile(`(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}`),
			repl:     placeholder("aws-access-key-id"),
		},
		// OpenAI / Anthropic API keys echoed in provider error prose (a bare
		// token, not a credential-named field). High precision: \b-anchored so
		// "risk-" is never matched; the distinctive sk-ant-/sk-proj-/sk-svcacct-
		// prefixes allow -/_ in the body, while a bare sk- requires 20+ alphanumerics.
		{
			keywords: []string{"sk-"},
			re: regexp.MustCompile(
				`\bsk-(?:ant-[A-Za-z0-9_-]{20,}|proj-[A-Za-z0-9_-]{20,}|svcacct-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})`,
			),
			repl: placeholder("llm-api-key"),
		},
	}
}

// credentialRules returns value-substitution rules: a credential-named JSON/XML
// field, a name/value pair whose name is a credential, a credential flag in a
// command array, or a signing query param keeps its key/param and gets its
// value replaced. The structural passes that follow the regexes read the content
// the regexes left, so a second Redact reads the same structure; FuzzRedact checks
// that it changes nothing.
func credentialRules() []rule {
	// Every multi-word name takes an optional '_' or '-' between words, so snake_case
	// (secret_access_key), kebab-case (api-key), Pascal/camelCase (SecretAccessKey,
	// accessToken) and the no-separator apikey all match under the (?i:) flag. Single words (secret/password) stay literal.
	// `(?:[a-z0-9]+_)+token` catches the whole snake_case "*_token" family GitLab
	// returns to owners/admins — including MULTI-component names (runners_token,
	// registration_token, incoming_email_token, …) that a single-component pattern
	// would miss — which the bare `token` alternative alone would not match.
	const credName = `access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|passwd|passphrase|secret[_-]?access[_-]?key|session[_-]?token|api[_-]?key|apikey|private[_-]?key|(?:[a-z0-9]+_)+token|token` //nolint:lll // single indivisible alternation
	// signingValue is a signing or session query param value: up to '&', a quote
	// or whitespace, where a backslash is taken only together with the character
	// after it. A backslash before a character that ends the value, or at the end
	// of the content, is left out, so the value is [^&"'\s]+ minus that one
	// backslash, and a value that is only that backslash does not match. Taking
	// the backslash of a JSON \" would let the quote end the string (#410).
	const signingValue = `(?:[^&"'\s\\]|\\[^&"'\s])+`
	// keyEnd is a JSON key or variable name that ENDS in a credential word, so
	// DB_PASSWORD, webhookSecret and stripeApiKey match the way the YAML and env
	// rules already allow. Bare "token" takes no prefix: nextPageToken, pageToken
	// and NextToken are pagination cursors the model has to send back.
	const keyEnd = `[\w.-]*(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|passwd|passphrase|secret[_-]?access[_-]?key|session[_-]?token|api[_-]?key|apikey|private[_-]?key)|(?:[a-z0-9]+_)+token|token`
	// flagArg is a command-line flag whose name ends in a credential word
	// (--token, --db-password, --api-key, ...), with any hyphenated prefix. Unlike
	// keyEnd it lets "token" take a prefix: a --page-token in a workload's args is
	// configuration, not a cursor the model sends back, so redacting it costs little.
	const flagArg = `--[\w-]*(?i:token|password|passwd|passphrase|secret|api[-_]?key|secret[-_]?access[-_]?key|private[-_]?key|bearer)`
	// jsonValue is the body of a JSON string, consuming any escape (a backslash
	// before a newline too) so the value isn't cut short; jsonEnd closes it or, for
	// a value truncated at the content cap, takes the end of content after an
	// optional lone backslash. jsonFields is a lazy run of scalar members
	// ("type":"PLAINTEXT") between a name and its value: lazy so the first "value"
	// member is the one redacted, and made of strings and bare scalars only, so in
	// valid JSON it never leaves the object.
	const (
		jsonValue  = `(?:(?s:\\.)|[^"\\])*`
		jsonEnd    = `(?:(")|\\?\z)`
		jsonFields = `(?:\s*,\s*"` + jsonValue + `"\s*:\s*(?:"` + jsonValue + `"|[\w.+-]+))*?`
	)

	m := newMatchers(credName, keyEnd, flagArg)

	return []rule{
		// YAML name/value pairs ("- name: DB_PASSWORD" with a "value:" sibling, in either
		// order, with comments or other fields between) and values that run over several
		// lines under a credential-named key (block scalars, continued quoted or plain
		// scalars). Indentation decides both, which RE2 cannot compare.
		{keywords: []string{":"}, fn: m.yaml},
		{ // JSON: "key":"value", closed or truncated to end-of-content. One rule for
			// both, since the prefixed key makes each pass over a large body costly.
			re:   regexp.MustCompile(`("(?i:` + keyEnd + `)"\s*:\s*")` + jsonValue + jsonEnd),
			repl: `${1}` + placeholder("credential-field") + `${2}`,
		},
		{ // JSON name/value pair: {"name":"DB_PASSWORD","value":"..."}, the shape of
			// ECS, Batch and CodeBuild container environments and Kubernetes pod env.
			re: regexp.MustCompile(
				`((?i:"name")\s*:\s*"(?i:` + keyEnd + `)"` + jsonFields + `\s*,\s*(?i:"value")\s*:\s*")` +
					jsonValue + jsonEnd,
			),
			repl: `${1}` + placeholder("credential-field") + `${2}`,
		},
		{ // JSON value/name pair: the same pair with "value" first.
			re: regexp.MustCompile(
				`((?i:"value")\s*:\s*")` + jsonValue +
					`("` + jsonFields + `\s*,\s*(?i:"name")\s*:\s*"(?i:` + keyEnd + `)")`,
			),
			repl: `${1}` + placeholder("credential-field") + `${2}`,
		},
		{ // XML: <key>value</key>, ending at the end of the JSON string it sits in
			// (see xmlFields). The closing tag's name is not checked.
			keywords: []string{"<"},
			fn:       xmlFields{re: regexp.MustCompile(`(<(?i:` + credName + `)>)[^<]*(</[A-Za-z0-9_:.-]+>)`)}.apply,
		},
		{ // YAML: "key: value" line — key ENDS in a credential name, so DB_/AWS_/client-
			// prefixes are allowed, plus an optional "- " sequence-item marker. Line-
			// anchored so a prose "token:" mid-line is not matched. The value's first
			// char excludes '[' so an already-redacted "[REDACTED:…]" (a token-shape
			// rule fired first) keeps its precise label and inline lists are skipped.
			// Covers kubeconfig / k8s-manifest piped input. This rule replaces the key
			// line only; the YAML pass above and below removes the lines a multi-line
			// value continues on. NOT covered: a high-entropy value under a key whose
			// name is not a credential word (the deliberate no-entropy boundary).
			re: regexp.MustCompile(
				`(?m)^([ \t]*(?:-[ \t]+)?[\w.-]*(?i:` + credName + `)[ \t]*:[ \t]*)([^\s\[][^\r\n]*)`,
			),
			repl: `${1}` + placeholder("credential-field"),
		},
		{ // env: "KEY=value" line — same key vocabulary (AWS_SECRET_ACCESS_KEY,
			// DB_PASSWORD, API_TOKEN, …), an optional shell "export " prefix, and the
			// same '[' exclusion. Covers .env / shell piped input.
			re: regexp.MustCompile(
				`(?m)^([ \t]*(?:export[ \t]+)?[\w.-]*(?i:` + credName + `)[ \t]*=[ \t]*)([^\s\[][^\r\n]*)`,
			),
			repl: `${1}` + placeholder("credential-field"),
		},
		{ // Signed-URL signature query param (bodies only; never the exempt Location header).
			re:   regexp.MustCompile(`((?i:X-Amz-Signature|X-Goog-Signature|Signature|sig)=)` + signingValue),
			repl: `${1}` + placeholder("signed-url-signature"),
		},
		{ // AWS presigned-URL session token (temp-credential calls embed it as a query param).
			re:   regexp.MustCompile(`((?i:X-Amz-Security-Token)=)` + signingValue),
			repl: `${1}` + placeholder("aws-session-token"),
		},
		{ // XML credential value that runs, with no '<' in it, to the end of content
			// or of the JSON string it sits in; allow an optional trailing < so a value
			// cut at the start of a closing tag (e.g. <SecretAccessKey>val<) still redacts.
			keywords: []string{"<"},
			fn:       xmlFields{re: regexp.MustCompile(`(<(?i:` + credName + `)>)[^<]*<?\z`)}.apply,
		},
		// The structural passes below read what the regexes left, so a second Redact
		// finds the same structure this one leaves: a regex that drops a quote or a
		// ',"' can change where a quoted value ends or where an array run starts.
		// A credential flag in a command array, joined ("--password=v") or with its
		// value in the next element, and one in the command string of ["sh","-c",...].
		// A flag's hyphens may be spelled as JSON escapes.
		{keywords: []string{"--", `\u002d`, `\u002D`}, fn: m.commands},
		// The YAML pass again.
		{keywords: []string{":"}, fn: m.yaml},
		{fn: m.objects},
	}
}

// denylistedHeaders are response headers whose value is replaced wholesale
// (they carry credential material, not data the model needs to read).
func denylistedHeaders() map[string]struct{} {
	return map[string]struct{}{
		"Set-Cookie":                   {},
		"Authorization":                {},
		"Proxy-Authorization":          {},
		"X-Amz-Security-Token":         {},
		"X-Ms-Authorization-Auxiliary": {},
		"Private-Token":                {},
		"Job-Token":                    {},
		"Deploy-Token":                 {},
		"X-Gitlab-Static-Object-Token": {},
	}
}
