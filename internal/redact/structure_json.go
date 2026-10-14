package redact

import (
	"encoding/json"
	"slices"
	"strconv"
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
// a joined "--password=v", and the word after a separate "--password", whatever
// that word looks like. A flag starting with "--no-" negates an option and takes
// no value. A word taken as a value that is itself a credential flag is still read
// as one, so its own value is found too.
func (m matchers) flagValues(words []string) []wordValue {
	var out []wordValue

	for i, w := range words {
		if loc := m.joined.FindStringIndex(w); loc != nil {
			out = append(out, wordValue{i, loc[1]})

			continue
		}
		if m.flag.MatchString(w) && i+1 < len(words) && !strings.HasPrefix(w, "--no-") {
			out = append(out, wordValue{i + 1, 0})
		}
	}

	return out
}

// shellCommand returns the index of the command a shell named at words[i] runs, or
// -1: the word after the option that holds 'c', past any other options and the
// argument of those that take one.
func (m matchers) shellCommand(words []string, i int) int {
	for j := i + 1; j < len(words) && words[j] != "" && strings.IndexByte("-+", words[j][0]) >= 0; j++ {
		switch {
		case m.shellFlag.MatchString(words[j]):
			return j + 1
		case m.shellArgOption.MatchString(words[j]):
			j++
		}
	}

	return -1
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

// commandSpans reads the elements decoded, so a flag or a shell name spelled with
// JSON escapes is still recognized; raws maps a decoded element back to its raw
// bytes, and is nil for an element with no escape.
func (m matchers) commandSpans(s string, elems []element) []span {
	words := make([]string, len(elems))
	raws := make([][]int, len(elems))
	for i, e := range elems {
		words[i] = s[e.start:e.end]
		if strings.IndexByte(words[i], '\\') >= 0 {
			words[i], raws[i] = decodeJSONString(words[i])
		}
	}

	// A shell command element is read as words by shellSpans, and only so, unless
	// its shell name or one of the options before it is itself a flag's value. That name is replaced, so a
	// second Redact reads the element as a plain array element; it is read both
	// ways here, the array reading first so its wider span wins, and the second
	// Redact finds nothing left.
	values := m.flagValues(words)
	taken := make(map[int]bool, len(values))
	for _, v := range values {
		taken[v.index] = taken[v.index] || v.offset == 0
	}

	var out, shellOut []span

	shell := make(map[int]bool)
	for i := range elems {
		if !m.shell.MatchString(words[i]) {
			continue
		}
		// Only a shell name starts the scan, so each run of options is read once.
		if c := m.shellCommand(words, i); c > i && c < len(elems) {
			shell[c] = !slices.Contains(takenIn(taken, i, c), true)
			shellOut = append(shellOut, m.shellSpans(s, elems[c])...)
		}
	}
	for _, v := range values {
		e, off := elems[v.index], v.offset
		if raws[v.index] != nil {
			off = raws[v.index][off]
		}
		// A value decoded only up to a bad escape is not done even when that prefix
		// is a placeholder: the bytes after the escape are part of it too.
		done := m.done(words[v.index][v.offset:]) && !cut(raws[v.index], e)
		if !shell[v.index] && !done {
			out = append(out, span{e.start + off, e.stop - boolInt(e.closed), placeholder("credential-field")})
		}
	}

	return append(out, shellOut...)
}

// shellSpans finds the credential values among the words of a shell command
// element and returns the raw spans that hold them. Only those bytes change; the
// rest of the element keeps its exact spelling, escapes included.
func (m matchers) shellSpans(s string, e element) []span {
	cmd, raw := decodeJSONString(s[e.start:e.end])
	partial := cut(raw, e)
	words := shellWords(cmd)
	texts := make([]string, len(words))
	for i, w := range words {
		texts[i] = w.text
	}

	var out []span

	for _, v := range m.flagValues(texts) {
		w := words[v.index]
		start, repl := w.start, placeholder("credential-field")
		if v.offset > 0 {
			// A joined value starts after the '='. When the '=' is inside quotes, the
			// span takes the closing quote too, so the replacement closes them again.
			start = w.at[v.offset-1] + 1
			repl += closeShellQuote(w.quote[v.offset-1])
		}
		// A word that runs into a bad escape also takes the bytes after it.
		end := e.start + raw[w.end]
		if partial && w.end == len(cmd) {
			end = e.stop - boolInt(e.closed)
		} else if m.done(w.text[v.offset:]) {
			continue
		}
		out = append(out, span{e.start + raw[start], end, repl})
	}

	return out
}

// jsonEscapes maps the byte after a backslash to the byte it stands for.
const jsonEscapes = "\"\"\\\\//b\bf\fn\nr\rt\t"

const (
	// escapeWidth is a backslash and the byte it escapes.
	escapeWidth = 2
	// hexWidth is the four hex digits of a \u escape.
	hexWidth = 4
)

// decodeJSONString decodes the body of a JSON string up to its first invalid or
// incomplete escape (one cut off at the content cap), so the words before it are
// still read. raw maps each byte of the result, and its end, to the offset in the
// body where that byte's character starts. Each \u escape is decoded on its own,
// so a surrogate pair becomes two U+FFFD; only the ASCII bytes around it matter
// to the words read from it.
func decodeJSONString(body string) (string, []int) {
	var b strings.Builder

	raw := make([]int, 0, len(body)+1)
	for i := 0; i < len(body); {
		if body[i] != '\\' {
			b.WriteByte(body[i])
			raw = append(raw, i)
			i++

			continue
		}
		dec, n, ok := decodeEscape(body[i:])
		if !ok {
			return b.String(), append(raw, i)
		}
		b.WriteString(dec)
		for range len(dec) {
			raw = append(raw, i)
		}
		i += n
	}

	return b.String(), append(raw, len(body))
}

// decodeEscape decodes the escape at the start of esc, returning the text it
// stands for and its length. An element's body never ends in a lone backslash
// (the element pattern takes a backslash only with the byte after it), so esc
// holds at least two bytes.
func decodeEscape(esc string) (string, int, bool) {
	if esc[1] == 'u' {
		if len(esc) < escapeWidth+hexWidth {
			return "", 0, false
		}
		v, err := strconv.ParseUint(esc[escapeWidth:escapeWidth+hexWidth], 16, 16)

		return string(rune(v)), escapeWidth + hexWidth, err == nil
	}
	for k := 0; k < len(jsonEscapes); k += 2 {
		if jsonEscapes[k] == esc[1] {
			return jsonEscapes[k+1 : k+2], escapeWidth, true
		}
	}

	return "", 0, false
}

// shellWord is one word of a shell command: its bounds in the command, its text
// with quotes and escapes removed, and for each byte of the text the offset it
// came from and the quote it was inside (0 for none).
type shellWord struct {
	start, end int
	text       string
	at         []int
	quote      []byte
	quoted     bool   // the word held quotes, so an empty text is still a word
	buf        []byte // the text while it is read
}

// closeShellQuote spells the quote q closes inside a JSON string.
func closeShellQuote(q byte) string {
	switch q {
	case '"':
		return `\"`
	case '\'':
		return "'"
	}

	return ""
}

// shellWords splits a POSIX shell command into words. Quotes, backslashes and
// backslash-newline line joins are removed the way the shell removes them, so a
// flag spelled "--pass"word, --pass\word or --pass\ followed by a newline and
// word is read as --password. Unquoted ; & | < > ( ) end a word and a # at the
// start of a word comments out the rest of the line. Expansions, here documents
// and other syntax are not interpreted.
func shellWords(d string) []shellWord {
	var out []shellWord

	for i := 0; ; {
		for i < len(d) && strings.IndexByte(shellBlank, d[i]) >= 0 {
			i++
		}
		switch {
		case i >= len(d):
			return out
		case d[i] == '#':
			_, rest, _ := strings.Cut(d[i:], "\n")
			i = len(d) - len(rest)
		case strings.IndexByte(shellOperators, d[i]) >= 0:
			i++
		default:
			w := shellWord{start: i}
			i = w.read(d, i)
			w.end = i
			if w.text != "" || w.quoted {
				out = append(out, w)
			}
		}
	}
}

const (
	shellBlank     = " \t\n"
	shellOperators = ";&|<>()"
)

// read consumes one word from d[i:] and returns the offset after it.
func (w *shellWord) read(d string, i int) int {
	for i < len(d) && strings.IndexByte(shellBlank+shellOperators, d[i]) < 0 {
		switch d[i] {
		case '\'':
			i = w.single(d, i+1)
		case '"':
			i = w.double(d, i+1)
		case '\\':
			// A backslash before a newline joins the lines; before anything else it
			// quotes that byte.
			if i+1 < len(d) && d[i+1] != '\n' {
				w.add(d, i+1, 0)
			}
			i += escapeWidth
		default:
			w.add(d, i, 0)
			i++
		}
	}
	w.text = string(w.buf)

	return min(i, len(d))
}

// single reads a single-quoted string from d[i:], after its opening quote, and
// returns the offset after its closing quote.
func (w *shellWord) single(d string, i int) int {
	w.quoted = true
	for ; i < len(d) && d[i] != '\''; i++ {
		w.add(d, i, '\'')
	}

	return i + 1
}

// double reads a double-quoted string from d[i:], after its opening quote, and
// returns the offset after its closing quote. A backslash quotes $ ` " \ and
// joins a line; before anything else it is kept.
func (w *shellWord) double(d string, i int) int {
	w.quoted = true
	for ; i < len(d) && d[i] != '"'; i++ {
		if d[i] == '\\' && i+1 < len(d) && d[i+1] == '\n' {
			i++ // the loop steps past the newline

			continue
		}
		if d[i] == '\\' && i+1 < len(d) && strings.IndexByte("$`\"\\", d[i+1]) >= 0 {
			i++
		}
		w.add(d, i, '"')
	}

	return i + 1
}

// add appends d[j] to the word's text, read inside quote q.
func (w *shellWord) add(d string, j int, q byte) {
	w.buf = append(w.buf, d[j])
	w.at = append(w.at, j)
	w.quote = append(w.quote, q)
}

// takenIn returns whether each of the words from i up to c is a flag's value.
func takenIn(taken map[int]bool, i, c int) []bool {
	out := make([]bool, 0, c-i)
	for k := i; k < c; k++ {
		out = append(out, taken[k])
	}

	return out
}

// cut reports whether decodeJSONString stopped before the end of e's body. raw is
// nil for an element with no escape, which decodes whole.
func cut(raw []int, e element) bool {
	return raw != nil && raw[len(raw)-1] < e.end-e.start
}

func boolInt(b bool) int {
	if b {
		return 1
	}

	return 0
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
