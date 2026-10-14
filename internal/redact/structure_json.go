package redact

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ---- command lines -----------------------------------------------------------

// element is one JSON string array element: its content is s[start:end], and stop
// is the offset past its closing quote, or the end of content when it is truncated.
type element struct {
	start, end, stop int
	closed           bool
}

// wordValue names a credential value in a word list: the word at index, from
// offset on.
type wordValue struct{ index, offset int }

// flagValues finds the credential values in a command line: the part after '=' of
// a joined "--password=v", and the word after a separate "--password". A next word
// starting with "--" is read as another flag, not a value, only when a word that
// does not start with '-' follows it, the way a flag that takes a value would.
func (m matchers) flagValues(words []string) []wordValue {
	var out []wordValue

	for i, w := range words {
		if loc := m.joined.FindStringIndex(w); loc != nil {
			out = append(out, wordValue{i, loc[1]})

			continue
		}
		if !m.flag.MatchString(w) || i+1 >= len(words) {
			continue
		}
		if strings.HasPrefix(words[i+1], "--") && i+2 < len(words) && !strings.HasPrefix(words[i+2], "-") {
			continue
		}
		out = append(out, wordValue{i + 1, 0})
	}

	return out
}

// commands redacts credential values in runs of JSON string array elements, and
// in the command string a shell runs with "-c".
func (m matchers) commands(s string) string {
	var spans []span

	for pos := 0; ; {
		loc := m.runStart.FindStringIndex(s[pos:])
		if loc == nil {
			return applySpans(s, spans)
		}
		elems, end := m.run(s, pos+loc[1]-1)
		spans = append(spans, m.commandSpans(s, elems)...)
		pos = max(end, pos+loc[1])
	}
}

// run reads the string elements from the quote at q on, stopping before one that
// is an object key. It returns them with the offset where reading stopped.
func (m matchers) run(s string, q int) ([]element, int) {
	var out []element

	for {
		g := m.element.FindStringSubmatchIndex(s[q:])
		e := element{start: q + 1, end: q + g[3], stop: q + g[1], closed: g[4] >= 0}
		if !e.closed {
			return append(out, element{e.start, e.end, len(s), false}), len(s)
		}
		if m.keyColon.MatchString(s[e.stop:]) {
			return out, e.stop
		}
		out = append(out, e)
		sep := m.separator.FindStringIndex(s[e.stop:])
		if sep == nil {
			return out, e.stop
		}
		q = e.stop + sep[1] - 1
	}
}

func (m matchers) commandSpans(s string, elems []element) []span {
	words := make([]string, len(elems))
	for i, e := range elems {
		words[i] = s[e.start:e.end]
	}

	// A shell command element is read as words by shellSpans only, so the two
	// readings never disagree about where its values end.
	var out []span

	shell := make(map[int]bool)
	for i := 2; i < len(elems); i++ {
		if m.shell.MatchString(words[i-2]) && m.shellFlag.MatchString(words[i-1]) {
			shell[i] = true
			out = append(out, m.shellSpans(s, elems[i])...)
		}
	}
	for _, v := range m.flagValues(words) {
		e := elems[v.index]
		if !shell[v.index] && !m.done(words[v.index][v.offset:]) {
			out = append(out, span{e.start + v.offset, e.stop - boolInt(e.closed), placeholder("credential-field")})
		}
	}

	return out
}

// shellSpans decodes a shell command element, redacts the credential values among
// its words and re-encodes it when anything changed.
func (m matchers) shellSpans(s string, e element) []span {
	var cmd string
	if json.Unmarshal([]byte(`"`+s[e.start:e.end]+`"`), &cmd) != nil {
		return nil
	}
	bounds := shellWords(cmd)
	words := make([]string, len(bounds))
	for i, b := range bounds {
		words[i] = cmd[b[0]:b[1]]
	}

	var parts []span

	for _, v := range m.flagValues(words) {
		b := bounds[v.index]
		if !m.done(cmd[b[0]+v.offset : b[1]]) {
			parts = append(parts, span{b[0] + v.offset, b[1], placeholder("credential-field")})
		}
	}
	if len(parts) == 0 {
		return nil
	}

	return []span{{e.start, e.stop - boolInt(e.closed), jsonStringBody(applySpans(cmd, parts))}}
}

// shellWords splits a POSIX shell command into words, honoring single quotes,
// double quotes with backslash escapes and a backslash outside quotes. Each word
// is a [start, end) pair of offsets.
func shellWords(d string) [][2]int {
	var out [][2]int

	i := 0
	for {
		for i < len(d) && isShellSpace(d[i]) {
			i++
		}
		if i >= len(d) {
			return out
		}
		start := i
		for i < len(d) && !isShellSpace(d[i]) {
			i = shellChar(d, i)
		}
		out = append(out, [2]int{start, min(i, len(d))})
	}
}

// escapeWidth is a backslash and the byte it escapes.
const escapeWidth = 2

// shellChar returns the offset after the character, quoted string or escape that
// starts at d[i].
func shellChar(d string, i int) int {
	switch d[i] {
	case '\'':
		if j := strings.IndexByte(d[i+1:], '\''); j >= 0 {
			closing := i + 1 + j

			return closing + 1
		}

		return len(d)
	case '"':
		for i++; i < len(d) && d[i] != '"'; i++ {
			if d[i] == '\\' {
				i++
			}
		}

		return i + 1
	case '\\':
		return i + escapeWidth
	}

	return i + 1
}

func isShellSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func boolInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// jsonStringBody encodes v as the body of a JSON string, without its quotes.
func jsonStringBody(v string) string {
	var b bytes.Buffer

	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // A string always encodes; Encode cannot fail on one.
	out := strings.TrimSuffix(b.String(), "\n")

	return out[1 : len(out)-1]
}

// ---- JSON objects ------------------------------------------------------------

// member is one object member whose value is a string, with the value's content
// span.
type member struct {
	key, val   string
	start, end int
}

// object is one open JSON object: its string members so far, and the key whose
// value comes next.
type object struct {
	members   []member
	key       string
	wantValue bool
}

// objects redacts, in every JSON object, the string value of each member whose
// decoded name is a credential name, and every "value" member of an object whose
// "name" member is one. Decoding the names catches spellings with escapes and
// repeated members, which the line regexes cannot see. The decoder reads values
// one after another, so NDJSON is covered too; at the first syntax error it stops,
// and a credential value cut off there is redacted to the end of content.
func (m matchers) objects(s string) string {
	t := strings.TrimLeft(s, " \t\r\n")
	if t == "" || t[0] != '{' && t[0] != '[' {
		return s
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var (
		stack []*object // nil marks an array
		spans []span
	)

	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			spans = m.truncated(s, before, stack, spans)
			for _, o := range stack {
				spans = m.objectSpans(o, spans)
			}

			return applySpans(s, spans)
		}

		var top *object
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}

		switch v := tok.(type) {
		case json.Delim:
			stack, spans = m.delim(v, top, stack, spans)
		case string:
			switch {
			case top == nil:
			case !top.wantValue:
				top.key, top.wantValue = v, true
			default:
				q := before + strings.IndexByte(s[before:], '"')
				top.members = append(top.members, member{top.key, v, q + 1, int(dec.InputOffset()) - 1})
				top.wantValue = false
			}
		default:
			if top != nil {
				top.wantValue = false
			}
		}
	}
}

// delim opens or closes an object or array, collecting a closed object's spans.
func (m matchers) delim(d json.Delim, top *object, stack []*object, spans []span) ([]*object, []span) {
	switch d {
	case '{', '[':
		if top != nil {
			top.wantValue = false
		}
		var o *object
		if d == '{' {
			o = &object{}
		}

		return append(stack, o), spans
	case '}':
		spans = m.objectSpans(top, spans)
	}

	return stack[:len(stack)-1], spans
}

// named reports whether o has a "name" member whose value is a credential name.
func (m matchers) named(o *object) bool {
	for _, mb := range o.members {
		if strings.EqualFold(mb.key, "name") && m.keyEnd.MatchString(mb.val) {
			return true
		}
	}

	return false
}

func (m matchers) objectSpans(o *object, spans []span) []span {
	if o == nil {
		return spans
	}
	named := m.named(o)
	for _, mb := range o.members {
		if (m.keyEnd.MatchString(mb.key) || named && strings.EqualFold(mb.key, "value")) && !m.done(mb.val) {
			spans = append(spans, span{mb.start, mb.end, placeholder("credential-field")})
		}
	}

	return spans
}

// truncated adds the span for a string value the decoder stopped inside, when the
// member it belongs to is a credential.
func (m matchers) truncated(s string, before int, stack []*object, spans []span) []span {
	if len(stack) == 0 {
		return spans
	}
	o := stack[len(stack)-1]
	rest, colon := strings.CutPrefix(strings.TrimLeft(s[before:], " \t\r\n"), ":")
	rest = strings.TrimLeft(rest, " \t\r\n")
	if o == nil || !o.wantValue || !colon || !strings.HasPrefix(rest, `"`) {
		return spans
	}
	if m.keyEnd.MatchString(o.key) || strings.EqualFold(o.key, "value") && m.named(o) {
		spans = append(spans, span{len(s) - len(rest) + 1, len(s), placeholder("credential-field")})
	}

	return spans
}
