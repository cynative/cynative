// Package redact replaces secret-shaped content in HTTP responses with
// type-labeled [REDACTED:<type>] placeholders before they reach the model.
// It is a pure stdlib leaf: it imports only the standard library, so nothing it
// depends on can create an import cycle.
package redact

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Redactor replaces secret-shaped content with [REDACTED:<type>] placeholders.
// Build one with New; it holds compiled regexes and is safe for concurrent use
// (Redact/RedactHeader/RedactTrailer/RedactPreservingLocation only read them).
type Redactor struct {
	rules      []rule
	headerDeny map[string]struct{}
	locDump    *regexp.Regexp
	locJSON    *regexp.Regexp
}

// New builds a Redactor with the production rule set and header denylist.
func New() *Redactor {
	return &Redactor{
		rules:      append(contentRules(), credentialRules()...),
		headerDeny: denylistedHeaders(),
		// Location header in the two serialized forms cynative produces: an
		// httputil.DumpResponse line ("Location: <url>") and a JSON-marshaled
		// http.Header field ("Location":["<url>"]). The value is captured so it can
		// be preserved across redaction (see RedactPreservingLocation). It must look
		// like a redirect target — absolute (https?://), scheme-relative (//host) or
		// root-relative (/path) — and is bounded to a single non-whitespace token, so
		// a bare secret on a coincidental "Location:" line (or trailing junk after the
		// URL) is still redacted rather than preserved.
		locDump: regexp.MustCompile(`(?im)^(location:[ \t]*)((?:https?://|//|/)\S*)`),
		locJSON: regexp.MustCompile(`(?i)("location"\s*:\s*\[\s*")((?:https?://|//|/)[^"]*)(")`),
	}
}

// Redact replaces every secret-shaped substring in s with its type placeholder.
// Placeholders contain no secret-shaped substrings, so Redact is idempotent.
func (r *Redactor) Redact(s string) string {
	for _, ru := range r.rules {
		if !gated(s, ru.keywords) {
			continue
		}
		s = ru.re.ReplaceAllString(s, ru.repl)
	}

	return s
}

// RedactPreservingLocation redacts s like Redact but leaves redirect Location
// URLs intact, mirroring RedactHeader's Location exemption so signed GitHub/S3
// download redirects survive backstop redaction and stay followable.
// It is for tool-result content at the sandbox and
// model-egress boundaries; on content with no Location it equals Redact.
func (r *Redactor) RedactPreservingLocation(s string) string {
	var saved []string

	stash := func(prefix, value, suffix string) string {
		saved = append(saved, value)

		return prefix + locationSentinel(len(saved)-1) + suffix
	}

	s = r.locDump.ReplaceAllStringFunc(s, func(m string) string {
		g := r.locDump.FindStringSubmatch(m)

		return stash(g[1], g[2], "")
	})
	s = r.locJSON.ReplaceAllStringFunc(s, func(m string) string {
		g := r.locJSON.FindStringSubmatch(m)

		return stash(g[1], g[2], g[3])
	})

	s = r.Redact(s)

	for i, url := range saved {
		s = strings.Replace(s, locationSentinel(i), url, 1)
	}

	return s
}

// locationSentinel is a placeholder carrying no rule keyword or secret-shaped
// content (NUL delimiters never occur in HTTP text), so a stashed Location URL
// passes through Redact untouched and is restored verbatim.
func locationSentinel(i int) string {
	return "\x00cynative-loc-" + strconv.Itoa(i) + "\x00"
}

// RedactHeader rewrites h in place. A denylisted header's values become
// [REDACTED:header]; the Location header is left untouched (redirect-following
// depends on signed Location URLs); every other header value
// is content-redacted via Redact (so a token in an arbitrary header is caught).
func (r *Redactor) RedactHeader(h http.Header) {
	r.redactFields(h, true)
}

// RedactTrailer rewrites trailer fields in place like RedactHeader but WITHOUT
// the Location exemption: a Location trailer cannot be used for redirect-following,
// so a signed URL or token in it must be redacted, not preserved.
func (r *Redactor) RedactTrailer(h http.Header) {
	r.redactFields(h, false)
}

// redactFields is the shared field-redaction loop; exemptLocation controls the
// header-only Location carve-out.
func (r *Redactor) redactFields(h http.Header, exemptLocation bool) {
	for name, vals := range h {
		canon := http.CanonicalHeaderKey(name)
		if exemptLocation && canon == "Location" {
			continue
		}
		// Normalize '_' to '-' for the denylist lookup: a Rack-style backend folds an
		// underscore credential header (e.g. Private_Token) onto the hyphenated name,
		// matching the request-side rejection — so its response form must blank too.
		// Re-canonicalize after the swap so the '-' separators title-case to the
		// canonical denylist keys (Private_token -> Private-token -> Private-Token).
		if _, deny := r.headerDeny[http.CanonicalHeaderKey(strings.ReplaceAll(canon, "_", "-"))]; deny {
			for i := range vals {
				vals[i] = "[REDACTED:header]"
			}

			continue
		}
		for i := range vals {
			vals[i] = r.Redact(vals[i])
		}
	}
}

// gated reports whether any pre-gate keyword is present (or there are none).
func gated(s string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}

	return false
}
