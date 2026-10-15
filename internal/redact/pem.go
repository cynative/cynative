package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// pemKeys redacts PEM private keys. A key matches through its END marker, or to
// the end of the text it is read in when that is absent, so a key cut off at the
// content cap is redacted to the end. In JSON that text is the string the key sits
// in: a match over the raw content would run past the string's closing quote and
// replace the structure after it, and the passes that read that structure would
// miss what follows (#413). A key that goes on past its string, into later JSON
// tokens, is redacted only up to that string's end.
type pemKeys struct {
	re *regexp.Regexp
}

// newPEMKeys builds the PEM private key pass.
func newPEMKeys() pemKeys {
	return pemKeys{
		re: regexp.MustCompile(
			`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`,
		),
	}
}

// apply redacts the keys in s, reading JSON strings maxNesting levels deep.
func (p pemKeys) apply(s string) string { return p.redact(s, maxNesting) }

// redact redacts the keys inside the JSON strings of s, depth levels deep, then
// matches what is left as a whole.
func (p pemKeys) redact(s string, depth int) string {
	if depth > 0 {
		s = p.strings(s, depth-1)
	}

	return p.re.ReplaceAllString(s, placeholder("pem-private-key"))
}

// strings redacts the keys in each JSON string of s, matching each in the string's
// decoded value, so a key ends where its string does. A string the pass changes is
// written back whole, re-encoded, so its other text keeps its value but not always
// its escapes. When the decoder reports a syntax error nothing is written back and
// the match over the whole content decides, since raw key bytes may follow the
// string that holds BEGIN. JSON that ends early, as at the content cap, is written
// back, and a string cut off there is matched to its end.
func (p pemKeys) strings(s string, depth int) string {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var spans []span

	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			if _, bad := errors.AsType[*json.SyntaxError](err); bad {
				return s
			}

			return applySpans(s, spans)
		}
		// Only a string that names a key is read again, which bounds the cost.
		v, ok := tok.(string)
		if !ok || !strings.Contains(v, "PRIVATE KEY") {
			continue
		}
		if red := p.redact(v, depth); red != v {
			q := before + strings.IndexByte(s[before:], '"')
			spans = append(spans, span{q, int(dec.InputOffset()), encodeString(red)})
		}
	}
}

// encodeString spells v as a JSON string, leaving <, > and & as written.
func encodeString(v string) string {
	var b bytes.Buffer

	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// Encoding a string into a buffer cannot fail.
	_ = enc.Encode(v)

	return strings.TrimSuffix(b.String(), "\n")
}
