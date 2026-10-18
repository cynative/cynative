package redact

import (
	"encoding/json"
	"io"
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

// commandFrom returns the index of the command a shell runs when its options
// start at words[j]: the first word after the option that holds 'c', the arguments
// it takes for each 'o' or 'O' it also holds (see optionArgs), and the options
// that follow it (see
// afterOptions), past any other options and the argument of those that take one. That is len(words) when no word is left, and
// -1 when the options end without one. For one word
// list the answer depends only on j, so memo keeps it for every option the scan
// reads, and a later scan that reaches one of them stops there. Each option is
// matched once however many shell names share its run.
func (m matchers) commandFrom(words []string, memo map[int]int, j int) int {
	var path []int

	c := -1
	for ; j < len(words) && words[j] != "" && strings.IndexByte("-+", words[j][0]) >= 0; j++ {
		if known, ok := memo[j]; ok {
			c = known

			break
		}
		path = append(path, j)
		if m.shellFlag.MatchString(words[j]) {
			c = m.afterOptions(words, j+1+m.optionArgs(words[j]))

			break
		}
		j += m.optionArgs(words[j])
	}
	for _, p := range path {
		memo[p] = c
	}

	return c
}

// afterOptions returns the index of the first word from words[j] on that is not
// a short option, the argument of one that takes one, or a "--", which ends the
// options and is skipped too. A shell reads those after the option that holds
// 'c' before it takes the command.
func (m matchers) afterOptions(words []string, j int) int {
	for ; j < len(words); j++ {
		if words[j] == "--" {
			return j + 1
		}
		if !m.shortOption.MatchString(words[j]) {
			return j
		}
		j += m.optionArgs(words[j])
	}

	return min(j, len(words))
}

// optionArgs returns how many of the words after shell option w are its
// arguments: one for --rcfile and --init-file, and one for each 'o' or 'O' in a
// run of short options, since each names a shell option in turn.
func (m matchers) optionArgs(w string) int {
	if w == "--rcfile" || w == "--init-file" {
		return 1
	}
	if !m.shortOption.MatchString(w) {
		return 0
	}

	return strings.Count(w, "o") + strings.Count(w, "O")
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
	// it, its shell name or one of the options before it is itself a flag's value.
	// That word is replaced, so a
	// second Redact reads the element as a plain array element; it is read both
	// ways here, the array reading first so its wider span wins, and the second
	// Redact finds nothing left.
	values := m.flagValues(words)
	taken := make(map[int]bool, len(values))
	for _, v := range values {
		taken[v.index] = taken[v.index] || v.offset == 0
	}

	shell, shellOut := m.shellCommands(s, elems, words, taken)

	var out []span

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

// shellCommands finds the command element each shell name runs and reads it as
// words. shell reports, for each command element, whether it is read only so.
// Several shell names can reach one command; the last one decides how it is read,
// and its words are read once. Most arrays name no shell, so the scan state is
// built at the first shell name.
func (m matchers) shellCommands(s string, elems []element, words []string, taken map[int]bool) (map[int]bool, []span) {
	var (
		before []int
		shell  map[int]bool
		memo   map[int]int
		out    []span
	)

	for i := range elems {
		if !m.shell.MatchString(words[i]) {
			continue
		}
		if before == nil {
			before, shell, memo = takenBefore(taken, len(elems)), make(map[int]bool), make(map[int]int)
		}
		if c := m.commandFrom(words, memo, i+1); c > i && c < len(elems) {
			_, seen := shell[c]
			shell[c] = before[c+1] == before[i]
			if !seen {
				out = append(out, m.shellSpans(s, elems[c])...)
			}
		}
	}

	return shell, out
}

// shellSpans finds the credential values among the words of a shell command
// element and returns the raw spans that hold them. Only those bytes change; the
// rest of the element keeps its exact spelling, escapes included.
func (m matchers) shellSpans(s string, e element) []span {
	cmd, raw := decodeJSONString(s[e.start:e.end])
	partial := cut(raw, e)
	words := shellWords(cmd)
	texts := wordTexts(words)

	// end maps a word's end in cmd to the raw content. A word that runs into a bad
	// escape, and a value read to the end of the command, also take the bytes after
	// it.
	end := func(off int, toEnd bool) int {
		if toEnd || partial && off == len(cmd) {
			return e.stop - boolInt(e.closed)
		}

		return e.start + raw[off]
	}

	var out []span

	for _, v := range m.shellValues(cmd, words, texts) {
		if !v.toEnd && (!partial || v.end != len(cmd)) && m.done(v.text) {
			continue
		}
		repl := placeholder("credential-field") + closeShellQuote(v.quote)
		out = append(out, span{e.start + raw[v.start], end(v.end, v.toEnd), repl})
	}
	for _, c := range m.nestedCommands(texts) {
		if m.nestedCredential(texts[c], maxShellNesting) {
			out = append(
				out,
				span{e.start + raw[words[c].start], end(words[c].end, false), placeholder("credential-field")},
			)
		}
	}

	return out
}

// maxShellNesting bounds how many shells started inside a shell command are read.
// A shell command nested deeper than that is redacted whole.
const maxShellNesting = 4

// shellValue is one credential value in a shell command: cmd[start:end], read as
// text. A value that a shell may expand (it holds $, a backquote, '<', '>' or '(',
// or follows a '<', '>' or '(' operator) can run past the word it starts in, so it
// is read to the end of the command. quote is the quote the value starts inside,
// which its replacement closes again.
type shellValue struct {
	start, end int
	text       string
	quote      byte
	toEnd      bool
}

// shellValues finds the credential values among the words of shell command cmd.
func (m matchers) shellValues(cmd string, words []shellWord, texts []string) []shellValue {
	var out []shellValue

	for _, v := range m.flagValues(texts) {
		w := words[v.index]
		sv := shellValue{start: w.start, end: w.end, text: w.text[v.offset:]}
		if v.offset > 0 {
			sv.start, sv.quote = w.at[v.offset-1]+1, w.quote[v.offset-1]
		} else if prev := words[v.index-1].end; strings.ContainsAny(cmd[prev:w.start], shellExpanding) {
			gap := cmd[prev:w.start]
			sv.start, sv.toEnd = prev+len(gap)-len(strings.TrimLeft(gap, shellBlank)), true
		}
		if sv.toEnd || strings.ContainsAny(cmd[sv.start:w.end], shellExpanding+"$`") {
			sv.end, sv.toEnd = len(cmd), true
		}
		out = append(out, sv)
	}

	return out
}

// shellExpanding is the operators that open a redirection, a process
// substitution or a subshell, after which the next word is not a flag's value.
const shellExpanding = "<>("

// nestedCommands returns the index of each word a shell named in texts runs as a
// command.
func (m matchers) nestedCommands(texts []string) []int {
	var out []int

	memo := make(map[int]int)
	for i, t := range texts {
		if !m.shell.MatchString(t) {
			continue
		}
		if c := m.commandFrom(texts, memo, i+1); c > i && c < len(texts) {
			out = append(out, c)
		}
	}

	return out
}

// nestedCredential reports whether shell command cmd, run by a shell inside
// another shell command, holds a credential value that is not yet replaced, here
// or in a shell it starts in turn. Past depth levels any shell it starts counts.
func (m matchers) nestedCredential(cmd string, depth int) bool {
	words := shellWords(cmd)
	texts := wordTexts(words)
	for _, v := range m.shellValues(cmd, words, texts) {
		if v.toEnd || !m.done(v.text) {
			return true
		}
	}
	for _, c := range m.nestedCommands(texts) {
		if depth == 0 || m.nestedCredential(texts[c], depth-1) {
			return true
		}
	}

	return false
}

// wordTexts returns the text of each word.
func wordTexts(words []shellWord) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = w.text
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

	raw := make([]int, 0, len(body))
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

// takenBefore counts, for each index up to n, the words before it that are a
// flag's value, so a range of words holds one exactly when its two ends differ.
func takenBefore(taken map[int]bool, n int) []int {
	out := make([]int, n+1)
	for k := range n {
		out[k+1] = out[k] + boolInt(taken[k])
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
// repeated members, which the line regexes cannot see. A JSON value can start
// anywhere in the content, such as the body of an HTTP dump after its headers, so
// a read starts at each '{' or '[' no earlier read took (see jsonStarts). The decoder reads values one
// after another, so NDJSON is covered too, and a credential value cut off at a
// syntax error is redacted to the end of content.
//
// Content that holds NaN or Infinity is read twice, with the constants rejected,
// as Go's decoder does, and read as values (see constReader), and the spans of
// both reads are kept. Reading past a constant finds the members after it, but it
// can also take a '{' inside a string that a read stopped at the constant would
// have started from, so neither read alone finds everything. Spans from the two
// reads cannot partly overlap, so applySpans drops only duplicates: each is the
// content of a member's string value, whose opening quote follows a colon and so
// is never an escaped quote inside a string the other read took, and the content
// holds no unescaped quote unless it runs to the end of content.
func (m matchers) objects(s string) string {
	var spans []span

	read := func(constants bool) {
		jsonStarts(s, "{[", func(start int) (int, bool) {
			found, resume := m.objectsFrom(s, start, constants)
			spans = append(spans, found...)

			return resume, false
		})
	}
	read(false)
	if strings.Contains(s, "NaN") || strings.Contains(s, "Infinity") {
		read(true)
	}

	return applySpans(s, spans)
}

// jsonStarts calls read for each offset in s where a byte of starts may begin a
// JSON value and no earlier read took it. read returns the offset to look from
// next, at or after the token it stopped at, and whether nothing after that is
// left to read; the next start is after this one either way. A later read never
// starts inside a string an earlier read took: text before a value can open a
// string that the value's first quote closes, as in x {"a {"key":"v"}, but each
// escaped quote in that string could start a new read over the rest, and a rule
// that redacts the string can remove the escape, so a second Redact would read
// differently.
func jsonStarts(s, starts string, read func(start int) (int, bool)) {
	for pos := 0; ; {
		k := strings.IndexAny(s[pos:], starts)
		if k < 0 {
			return
		}
		next, done := read(pos + k)
		if done {
			return
		}
		pos = max(next, pos+k+1)
	}
}

// objectsFrom reads JSON values from s[start:] up to the first syntax error or the
// end of content, and returns the spans of their credential members and where to
// look for the next JSON value. With constants, NaN, Infinity and -Infinity are
// read as values (see constReader).
func (m matchers) objectsFrom(s string, start int, constants bool) ([]span, int) {
	var src io.Reader = strings.NewReader(s[start:])
	if constants {
		src = &constReader{s: s[start:]}
	}
	dec := json.NewDecoder(src)
	dec.UseNumber()

	var (
		stack []*object // nil marks an array
		spans []span
	)

	for {
		before := start + int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			spans = m.truncated(s, before, stack, spans)
			for _, o := range stack {
				spans = m.objectSpans(o, spans)
			}

			return spans, before
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
				top.members = append(top.members, member{top.key, v, q + 1, start + int(dec.InputOffset()) - 1})
				top.wantValue = false
			}
		default:
			if top != nil {
				top.wantValue = false
			}
		}
	}
}

// constReader reads s with each NaN, Infinity and -Infinity outside a JSON string
// spelled as an empty array of the same length, so offsets do not move. Go's
// decoder rejects the three, and a read that stopped at one would not pair the
// members after it, while Python's json reads them as numbers (the connector
// audit's prepass reads JSON with it). "Outside a string" is as read from the
// start of s. An array cannot run into the bytes around it the way a number can,
// so inside an object or array 1NaN, NaN1 and -NaN stay errors, as they are for
// Python; between top-level values both read 1NaN and NaN1 as two values.
type constReader struct {
	s, pend    string
	i          int
	inStr, esc bool
}

func (r *constReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && (r.pend != "" || r.i < len(r.s)) {
		if r.pend == "" {
			r.pend = r.next()
		}
		c := copy(p[n:], r.pend)
		r.pend = r.pend[c:]
		n += c
	}
	if r.pend == "" && r.i == len(r.s) {
		return n, io.EOF
	}

	return n, nil
}

// next returns what the reader passes on for the bytes at i: a constant's array,
// or the next byte.
func (r *constReader) next() string {
	rest := r.s[r.i:]
	if !r.inStr {
		for _, c := range [...]string{"NaN", "Infinity", "-Infinity"} {
			if strings.HasPrefix(rest, c) {
				r.i += len(c)

				return "[" + strings.Repeat(" ", len(c)-len("[]")) + "]"
			}
		}
	}
	switch b := rest[0]; {
	case r.esc:
		r.esc = false
	case r.inStr && b == '\\':
		r.esc = true
	case b == '"':
		r.inStr = !r.inStr
	}
	r.i++

	return rest[:1]
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
