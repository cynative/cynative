package redact

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// encoded redacts the decoded content of each JSON string in s that holds an
// escape. A JSON document carried inside a string, such as an HTTP body that is
// itself a string or an audit field that stores JSON, has its quotes escaped, so
// the rules cannot read its members until the string is decoded. Only the parts
// the rules replaced are written back, escaped, and the text around them keeps its
// exact spelling (edits says when it cannot), so a second Redact reads the raw
// text this one read. Only a string with an escape is redacted again, since one
// without cannot hide a quoted member. A JSON value can start anywhere in s (see
// jsonStarts). The decoder stops at the first error, and a string that is never
// closed after it is read to the end of content.
func (r *Redactor) encoded(s string, depth int) string {
	if !strings.Contains(s, `\`) {
		return s
	}

	var spans []span

	jsonStarts(s, `{["`, func(start int) (int, bool) {
		found, resume, end := r.encodedFrom(s, start, depth)
		spans = append(spans, found...)

		return resume, end
	})

	return applySpans(s, spans)
}

// encodedFrom reads JSON values from s[start:] like objectsFrom and returns the
// spans for the strings it redacts.
func (r *Redactor) encodedFrom(s string, start, depth int) ([]span, int, bool) {
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	dec.UseNumber()

	var spans []span

	for {
		before := start + int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			next := skipToken(s, before)

			return r.openString(s, before, depth, spans), next, next < 0
		}
		if _, ok := tok.(string); !ok {
			continue
		}
		q := before + strings.IndexByte(s[before:], '"')
		body := s[q+1 : start+int(dec.InputOffset())-1]
		if strings.Contains(body, `\`) {
			d, raw := decodeJSONString(body)
			spans, _ = r.rewrite(d, raw, q+1, depth, spans)
		}
	}
}

// openString adds the spans for a string that starts where the decoder stopped and
// is never closed, such as one cut off at the content cap. Its body is decoded up
// to the first invalid or incomplete escape; when the rules change that, the bytes
// from there to the end of content are dropped too, so none of them is kept.
func (r *Redactor) openString(s string, before, depth int, spans []span) []span {
	rest := tokenAt(s, before)
	body, end := openBody(rest)
	if end >= 0 || !strings.Contains(body, `\`) {
		return spans
	}
	at := len(s) - len(rest) + 1
	d, raw := decodeJSONString(body)
	spans, changed := r.rewrite(d, raw, at, depth, spans)
	if changed {
		spans = append(spans, span{at + raw[len(d)], len(s), ""})
	}

	return spans
}

// rewrite redacts d, the decoded body of a JSON string at offset at, and adds a
// span for each part of the body the rules replaced. raw maps each byte of d, and
// its end, to its offset in the body. It reports whether the rules changed d.
func (r *Redactor) rewrite(d string, raw []int, at, depth int, spans []span) ([]span, bool) {
	red := r.redact(d, depth)
	if red == d {
		return spans, false
	}
	es := edits(r.marks, d, red)
	for _, e := range es {
		spans = append(spans, span{at + raw[e.start], at + raw[e.end], escapeJSON(e.repl)})
	}

	return spans, len(es) > 0
}

// edit is one part of decoded content, d[start:end], that redaction replaced with
// repl.
type edit struct {
	start, end int
	repl       string
}

// edits aligns red, the redaction of d, with d and returns the parts of d the rules
// replaced, one for each run of placeholders in red. The text before a run keeps
// its place as far as it matches d. The run ends where the text after it, up to the
// next run and without what a rule may add next to a placeholder (see place),
// next occurs in d. The last run, and one whose following text cannot be placed,
// ends where the characters d and red both end with start; the text of red up to
// there is written as one edit, which loses its spelling and holds every run left.
func edits(marks *regexp.Regexp, d, red string) []edit {
	var out []edit

	i, j := 0, 0
	// An empty run at the end of red stands for its end, so the last run has one
	// after it.
	runs := append(marks.FindAllStringIndex(red, -1), []int{len(red), len(red)})
	for n := 0; ; n++ {
		run := runs[n]
		c := commonPrefix(d[i:], red[j:run[0]])
		i, j = i+c, j+c
		k, end := -1, run[1]
		if n+2 < len(runs) {
			var quote int
			k, quote = place(d[i:], red[end:runs[n+1][0]])
			end += quote
		}
		if k < 0 {
			x := commonSuffix(d[i:], red[j:])

			return append(out, edit{i, len(d) - x, red[j : len(red)-x]})
		}
		out = append(out, edit{i, i + k, red[j:end]})
		i, j = i+k, end
	}
}

// place returns where lit, the text between two placeholder runs, next occurs in
// rest, or -1, and how many of its leading bytes belong to the run before. lit is
// looked for as written first. When it is not there, what a rule may add next to
// a placeholder comes off: the space the YAML pass writes before a value it moves
// up to its key line, and the quote the shell pass writes after a value to close
// the quote it was in.
func place(rest, lit string) (int, int) {
	if k := strings.Index(rest, lit); k >= 0 {
		return k, 0
	}
	lit = strings.TrimRight(lit, " ")
	for _, q := range []string{`\"`, "'"} {
		if t, ok := strings.CutPrefix(lit, q); ok {
			return strings.Index(rest, t), len(q)
		}
	}

	return strings.Index(rest, lit), 0
}

// commonPrefix returns the length of the longest prefix a and b share.
func commonPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}

	return n
}

// commonSuffix returns the length of the longest run of whole characters of a that
// b also ends with. A byte that does not start a valid character counts as one.
func commonSuffix(a, b string) int {
	n := 0
	for {
		_, size := utf8.DecodeLastRuneInString(a[:len(a)-n])
		if size == 0 || !strings.HasSuffix(b[:len(b)-n], a[len(a)-n-size:len(a)-n]) {
			return n
		}
		n += size
	}
}

// tokenAt returns s from the token a read stopped at, the one after before past
// any blanks and one ':' or ','.
func tokenAt(s string, before int) string {
	rest := strings.TrimLeft(s[before:], " \t\r\n")
	if rest != "" && (rest[0] == ':' || rest[0] == ',') {
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
	}

	return rest
}

// skipToken returns where to look for a JSON value after a read that stopped at
// before: after the token there when it is a string, so no escaped quote in it
// starts a new read, and at the token otherwise. It returns -1 when the string
// openString reads is never closed, which leaves nothing after it to read (and a
// read inside it could cross the spans openString wrote).
func skipToken(s string, before int) int {
	if _, end := openBody(tokenAt(s, before)); end < 0 {
		return -1
	}
	tok := strings.TrimLeft(s[before:], " \t\r\n")
	_, end := openBody(tok)

	return len(s) - len(tok) + end
}

// openBody reads the JSON string that opens rest. It returns how far rest the
// string runs, through its closing quote, which is 0 when rest opens no string;
// when the string is never closed, it returns -1 and the string's body, without a
// lone backslash at the end of content.
func openBody(rest string) (string, int) {
	if !strings.HasPrefix(rest, `"`) {
		return "", 0
	}
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			if i+1 == len(rest) {
				return rest[1:i], -1
			}
			i++
		case '"':
			return "", i + 1
		}
	}

	return rest[1:], -1
}

// escapeJSON spells v as the body of a JSON string.
func escapeJSON(v string) string {
	// Marshaling a string cannot fail.
	b, _ := json.Marshal(v)

	return string(b[1 : len(b)-1])
}
