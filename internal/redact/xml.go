package redact

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// xmlFields is an XML credential element rule that matches inside each JSON
// string on its own, so a value ends where its string does. A match over the raw
// content would run from a tag in one string to a closing tag in a later one and
// replace the structure between them, and the passes that read that structure
// would miss what follows (#418). A real XML value can hold a quote, so the rule
// cannot just stop at one. A secret in a separate string between the two tags is
// no longer redacted with them.
//
// re captures the opening tag as group 1 and may capture the closing tag as group
// 2; the value between them is replaced. Only the value's bytes change, as they
// are spelled, so every escape around it keeps its spelling and the rules that
// already ran read the same text a second Redact reads.
type xmlFields struct {
	re *regexp.Regexp
}

// apply redacts the element values in s, reading JSON strings maxNesting levels
// deep. Content with a JSON syntax error is matched as a whole.
func (p xmlFields) apply(s string) string {
	spans, ok := p.strings(s, maxNesting-1)
	if !ok {
		spans = p.matches(s, 0)
	}

	return applySpans(s, spans)
}

// strings returns a span for each element value in the JSON strings of s and
// reports whether s reads as a run of JSON values with no syntax error. A string
// whose decoded body reads that way too is read the same way, depth levels
// deeper, and any other string is matched over its body as written. When the
// JSON ends early, as at the content cap, the token cut off there is matched as
// written, to the end of content.
func (p xmlFields) strings(s string, depth int) ([]span, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var spans []span

	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			if _, bad := errors.AsType[*json.SyntaxError](err); bad {
				return nil, false
			}

			return append(spans, p.matches(s[before:], before)...), true
		}
		if v, ok := tok.(string); !ok || !strings.Contains(v, "<") {
			continue
		}
		q := before + strings.IndexByte(s[before:], '"')
		spans = append(spans, p.body(s[q+1:int(dec.InputOffset())-1], q+1, depth)...)
	}
}

// body returns the spans for the element values in body, the body of a JSON
// string at offset at. A body that holds JSON, which has an escaped quote, is
// decoded and read as JSON, and each span found in the decoded text is moved back
// onto the bytes it was decoded from. A value starts after a '>' and ends before
// a '<', a quote or the end of the body, so it never starts or ends inside an
// escape.
func (p xmlFields) body(body string, at, depth int) []span {
	if depth > 0 && strings.Contains(body, `\`) {
		d, raw := decodeJSONString(body)
		if inner, ok := p.strings(d, depth-1); ok {
			for i, sp := range inner {
				inner[i] = span{at + raw[sp.start], at + raw[sp.end], sp.repl}
			}

			return inner
		}
	}

	return p.matches(body, at)
}

// closeTag is where the closing tag's start sits in a submatch index slice.
const closeTag = 4

// matches returns a span for the value of each element in s, at offset at.
func (p xmlFields) matches(s string, at int) []span {
	var out []span

	for _, m := range p.re.FindAllStringSubmatchIndex(s, -1) {
		end := m[1]
		if len(m) > closeTag {
			end = m[closeTag]
		}
		out = append(out, span{at + m[3], at + end, placeholder("credential-field")})
	}

	return out
}
