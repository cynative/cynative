package redact

import "regexp"

// placeholder renders a type-labeled redaction marker.
func placeholder(label string) string { return "[REDACTED:" + label + "]" }

// rule is one redaction pattern: run re only when one of keywords is present
// (a cheap pre-gate over multi-MiB bodies), then ReplaceAllString with repl.
// For whole-match rules repl is the literal placeholder; for capture rules repl
// is a template using ${1}/${2} so the surrounding key/param is preserved.
type rule struct {
	keywords []string
	re       *regexp.Regexp
	repl     string
}

// contentRules returns the body/value redaction rules in application order.
// Whole-match token & structural rules first, then value-substitution rules.
func contentRules() []rule {
	return []rule{
		// PEM private key: match through the END marker, or to end-of-content
		// when it is absent (truncation-safe — no key bytes leak at the cap).
		{
			keywords: []string{"PRIVATE KEY"},
			re: regexp.MustCompile(
				`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`,
			),
			repl: placeholder("pem-private-key"),
		},
		// Base64-encoded PEM block (kubeconfig client-key-data, k8s secret data, …):
		// "LS0tLS1CRUdJTi" is the base64 of the "-----BEGIN " marker — a stable,
		// low-false-positive prefix — so a base64'd private key is caught whatever
		// the surrounding key name, which the keyword-based field rules cannot see.
		// The trailing group consumes newline-wrapped continuation lines so a base64
		// block split at 64 columns is redacted whole, not just its first line.
		{
			keywords: []string{"LS0tLS1CRUdJTi"},
			// Continuation lines require ≥32 base64 chars so a following short token
			// (a "users:" / "name:" key line) is not swallowed, while real 64-column
			// wrapped lines are. A final partial line <32 chars may be left, which is
			// a non-reconstructable key tail.
			re:   regexp.MustCompile(`LS0tLS1CRUdJTi[A-Za-z0-9+/=]+(?:[ \t]*\r?\n[ \t]*[A-Za-z0-9+/=]{32,})*`),
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
// field or a signing query param keeps its key/param and gets its value
// replaced, so the surrounding document stays well-formed.
func credentialRules() []rule {
	// Every multi-word name is underscore-optional so snake_case (secret_access_key),
	// Pascal/camelCase (SecretAccessKey, accessToken), and the no-separator apikey all
	// match under the (?i:) flag. Single words (secret/password) stay literal.
	// `(?:[a-z0-9]+_)+token` catches the whole snake_case "*_token" family GitLab
	// returns to owners/admins — including MULTI-component names (runners_token,
	// registration_token, incoming_email_token, …) that a single-component pattern
	// would miss — which the bare `token` alternative alone would not match.
	const credName = `access_?token|refresh_?token|id_?token|client_?secret|secret|password|secret_?access_?key|session_?token|api_?key|apikey|private_?key|(?:[a-z0-9]+_)+token|token` //nolint:lll // single indivisible alternation

	return []rule{
		{ // JSON: "key":"value" (consume escaped \" so the value isn't cut short).
			re:   regexp.MustCompile(`("(?i:` + credName + `)"\s*:\s*")(?:\\.|[^"\\])*(")`),
			repl: `${1}` + placeholder("credential-field") + `${2}`,
		},
		{ // XML: <key>value</key>.
			re:   regexp.MustCompile(`(<(?i:` + credName + `)>)[^<]*(</[A-Za-z0-9_:.-]+>)`),
			repl: `${1}` + placeholder("credential-field") + `${2}`,
		},
		{ // YAML: "key: value" line — key ENDS in a credential name, so DB_/AWS_/client-
			// prefixes are allowed, plus an optional "- " sequence-item marker. Line-
			// anchored so a prose "token:" mid-line is not matched. The value's first
			// char excludes '[' so an already-redacted "[REDACTED:…]" (a token-shape
			// rule fired first) keeps its precise label and inline lists are skipped.
			// Covers kubeconfig / k8s-manifest piped input. NOT covered (RE2 cannot do
			// indentation-relative matching): YAML block scalars ("token: |" + indented
			// value) — documented residual; nor a high-entropy value under a key whose
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
			re:   regexp.MustCompile(`((?i:X-Amz-Signature|X-Goog-Signature|Signature|sig)=)[^&"'\s]+`),
			repl: `${1}` + placeholder("signed-url-signature"),
		},
		{ // AWS presigned-URL session token (temp-credential calls embed it as a query param).
			re:   regexp.MustCompile(`((?i:X-Amz-Security-Token)=)[^&"'\s]+`),
			repl: `${1}` + placeholder("aws-session-token"),
		},
		{ // JSON credential value truncated to end-of-content (no closing quote);
			// allow an optional trailing lone backslash so a value cut right after
			// an escape (e.g. "secret\) still redacts.
			re:   regexp.MustCompile(`("(?i:` + credName + `)"\s*:\s*")(?:\\.|[^"\\])*\\?\z`),
			repl: `${1}` + placeholder("credential-field"),
		},
		{ // XML credential value truncated to end-of-content (no closing tag);
			// allow an optional trailing < so a value cut at the start of a closing
			// tag (e.g. <SecretAccessKey>val<) still redacts.
			re:   regexp.MustCompile(`(<(?i:` + credName + `)>)[^<]*<?\z`),
			repl: `${1}` + placeholder("credential-field"),
		},
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
