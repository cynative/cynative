package redact

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// The structural passes cover credential shapes a single regex cannot see: a YAML
// value whose extent depends on indentation, a JSON object whose members repeat or
// spell their names with escapes, and a command line whose flags and values are
// separate array elements or words of one shell string. Each pass collects byte
// spans and rebuilds the content once.

// span is one byte range of the content to replace with repl.
type span struct {
	start, end int
	repl       string
}

// applySpans rebuilds s with every span replaced. A span that starts inside an
// earlier one is dropped, and so is an empty span at the end of the previous one,
// which would add a second placeholder there. Every pass that produces two such
// spans produces the outer one first, so the bytes of the dropped one are covered.
func applySpans(s string, spans []span) string {
	if len(spans) == 0 {
		return s
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var b strings.Builder

	last, prev := 0, -1
	for _, sp := range spans {
		if sp.start < last || sp.start == prev && sp.end == sp.start {
			continue
		}
		prev = sp.end
		b.WriteString(s[last:sp.start])
		b.WriteString(sp.repl)
		last = sp.end
	}
	b.WriteString(s[last:])

	return b.String()
}

// matchers holds the compiled patterns the structural passes share.
type matchers struct {
	// direct is a whole YAML key ending in a credential word, read as the YAML line rule reads it.
	direct *regexp.Regexp
	// keyEnd is a whole JSON key or pair name ending in a credential word.
	keyEnd *regexp.Regexp
	// flag is a whole credential flag; joined is one with "=" and its value after it.
	flag, joined *regexp.Regexp
	// yamlKey splits a "key: value" line into its indentation and "- " markers and its
	// key; mappingLine is any unquoted line that holds a mapping key, whatever the
	// key's spelling, and quotedKey a line that opens with a quoted key; props is
	// the anchor and tag properties that may open a value.
	yamlKey, mappingLine, quotedKey, props *regexp.Regexp
	// block is a YAML block scalar indicator.
	block *regexp.Regexp
	// placeholder is a value an earlier rule already replaced, kept for its label.
	placeholder *regexp.Regexp
	// shell is a shell program, shellFlag the option that makes it run its next
	// argument as a command, and shellArgOption an option that takes the next
	// argument as its own.
	shell, shellFlag, shellArgOption *regexp.Regexp
	// runStart opens a JSON array element, element reads one string element (closed,
	// or truncated to end of content), separator leads to the next string element and
	// keyColon marks an object key.
	runStart, element, separator, keyColon *regexp.Regexp
}

func newMatchers(credName, keyEnd, flagArg string) matchers {
	return matchers{
		direct: regexp.MustCompile(`^[\w.-]*(?i:` + credName + `)$`),
		keyEnd: regexp.MustCompile(`^(?i:` + keyEnd + `)$`),
		flag:   regexp.MustCompile(`^(?:` + flagArg + `)$`),
		joined: regexp.MustCompile(`^(?:` + flagArg + `)=`),
		yamlKey: regexp.MustCompile(
			`^([ \t]*(?:-[ \t]+)*)([\w.-]+|"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')[ \t]*:(?:[ \t]+|$)`,
		),
		mappingLine:    regexp.MustCompile(`:(?:[ \t]|[ \t]*$)`),
		quotedKey:      regexp.MustCompile(`^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')[ \t]*:(?:[ \t]|$)`),
		props:          regexp.MustCompile(`^(?:[&!][^ \t]*(?:[ \t]+|$))*`),
		block:          regexp.MustCompile(`^[|>][0-9+-]*$`),
		placeholder:    regexp.MustCompile(`^\[REDACTED:[a-z0-9-]+\]$`),
		shell:          regexp.MustCompile(`^(?:[\w./-]*/)?(?:sh|bash|dash|ash|ksh|zsh)$`),
		shellFlag:      regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`),
		shellArgOption: regexp.MustCompile(`^(?:[-+][oO]|--rcfile|--init-file)$`),
		runStart:       regexp.MustCompile(`[\[,]\s*"`),
		element:        regexp.MustCompile(`^"((?:(?s:\\.)|[^"\\])*)(")?`),
		separator:      regexp.MustCompile(`^\s*,\s*"`),
		keyColon:       regexp.MustCompile(`^\s*:`),
	}
}

// done reports whether v is already a lone redaction placeholder.
func (m matchers) done(v string) bool { return m.placeholder.MatchString(v) }

// ---- YAML -------------------------------------------------------------------

// yamlLine is one line of content, without its line break or a trailing '\r'.
type yamlLine struct{ start, end int }

// yamlEntry is one line of the YAML pass: a "key: value" line with the extent of
// its value, or any other non-blank, non-comment line, kept for its indentation.
type yamlEntry struct {
	key   string // empty for a line that is not "key: value"
	col   int    // the key's column after any "- " markers, or the line's indentation
	item  bool   // the line opens a sequence item
	colon int    // offset just past the ':'
	start int    // offset of the value's first byte, its properties included
	first int    // offset of the scalar itself: after any properties, or on a later line
	end   int    // offset just past the value's last byte; equal to start when empty
	below bool   // the value starts on a later line, so the replacement needs a space
	multi bool   // the value runs past its key line
	json  bool   // the key is double-quoted, as a pretty-printed JSON member's is
}

func splitLines(s string) []yamlLine {
	var out []yamlLine

	start := 0
	for {
		nl := strings.IndexByte(s[start:], '\n')
		if nl < 0 {
			out = append(out, yamlLine{start, start + len(strings.TrimSuffix(s[start:], "\r"))})

			return out
		}
		out = append(out, yamlLine{start, start + len(strings.TrimSuffix(s[start:start+nl], "\r"))})
		start += nl + 1
	}
}

func indentOf(t string) int { return len(t) - len(strings.TrimLeft(t, " \t")) }

func blankOrComment(t string) bool {
	t = strings.TrimLeft(t, " \t")

	return t == "" || t[0] == '#'
}

// yaml redacts multi-line values under credential-named keys, and the "value"
// member of each mapping whose "name" member is a single-line credential name.
// A mapping is read from its indentation (see mappings), keys of the form yamlKey
// accepts.
func (m matchers) yaml(s string) string {
	entries := m.yamlEntries(s, splitLines(s))
	ids := mappings(entries)

	named := make(map[int]bool)
	for i, e := range entries {
		if strings.EqualFold(e.key, "name") && m.keyEnd.MatchString(nameValue(s, e)) {
			named[ids[i]] = true
		}
	}

	var spans []span

	for i, e := range entries {
		if named[ids[i]] && strings.EqualFold(e.key, "value") || e.multi && m.direct.MatchString(e.key) {
			spans = m.yamlValue(s, e, spans)
		}
	}

	return applySpans(s, spans)
}

// nameValue returns the scalar of a "name" entry when it is a single line,
// unquoted and without a comment, or "" otherwise.
func nameValue(s string, e yamlEntry) string {
	if e.end <= e.first || strings.Contains(s[e.first:e.end], "\n") {
		return ""
	}

	return unquote(strings.TrimRight(stripComment(s[e.first:e.end]), " \t\r"))
}

// yamlValue adds the span that replaces e's value, unless it has none or an
// earlier rule already replaced it.
//
// Under a double-quoted key a value that parses as a JSON scalar, with the comma
// that may follow it, is a pretty-printed JSON member: the JSON passes read it, and
// replacing it here would drop its quotes and break the document.
func (m matchers) yamlValue(s string, e yamlEntry, spans []span) []span {
	if e.end == e.start || m.done(s[e.start:e.end]) ||
		e.json && json.Valid([]byte(strings.TrimSuffix(s[e.first:e.end], ","))) {
		return spans
	}
	if e.below {
		return append(spans, span{e.colon, e.end, " " + placeholder("credential-field")})
	}

	return append(spans, span{e.start, e.end, placeholder("credential-field")})
}

// yamlEntries reads every non-blank, non-comment line. The value of a key the
// pass acts on (a credential-named key, "name" or "value") is read to its end and
// the lines it runs over are skipped; any other key's lines are read as entries
// too, so a pair inside an embedded document (a ConfigMap's "config.yaml: |") is
// still found.
func (m matchers) yamlEntries(s string, lines []yamlLine) []yamlEntry {
	var out []yamlEntry

	for i := 0; i < len(lines); i++ {
		text := s[lines[i].start:lines[i].end]
		if blankOrComment(text) {
			continue
		}
		g := m.yamlKey.FindStringSubmatchIndex(text)
		if g == nil {
			out = append(out, yamlEntry{col: indentOf(text)})

			continue
		}
		e := yamlEntry{
			key:   unquote(text[g[4]:g[5]]),
			json:  text[g[4]] == '"',
			col:   g[3],
			item:  strings.Contains(text[:g[3]], "-"),
			colon: lines[i].start + g[5] + strings.IndexByte(text[g[5]:], ':') + 1,
			start: lines[i].start + g[1],
		}
		e.end = e.start
		if m.direct.MatchString(e.key) || strings.EqualFold(e.key, "name") || strings.EqualFold(e.key, "value") {
			i = m.extent(s, lines, i, &e)
		}
		out = append(out, e)
	}

	return out
}

// extent sets e's value end and returns the index of the value's last line. A
// value that is empty on its key line (after any anchor or tag) continues on a
// later line only as a scalar; a nested mapping, sequence or flow collection
// there, or a flow collection on the key line, is not a value this pass replaces.
func (m matchers) extent(s string, lines []yamlLine, i int, e *yamlEntry) int {
	e.first = e.start + len(m.props.FindString(s[e.start:lines[i].end]))
	line := i
	if v := s[e.first:lines[i].end]; v == "" || v[0] == '#' {
		if line = m.scalarBelow(s, lines, i, e.col); line < 0 {
			return i
		}
		e.below = true
		e.first = lines[line].start + indentOf(s[lines[line].start:lines[line].end])
		if p := len(m.props.FindString(s[e.first:lines[line].end])); e.first+p < lines[line].end {
			e.first += p
		}
	} else if (v[0] == '[' || v[0] == '{') && !strings.HasPrefix(v, "[REDACTED:") {
		return i
	}
	v := s[e.first:lines[line].end]
	last := continuation(s, lines, line, e.col, m.block.MatchString(strings.TrimSpace(stripComment(v))))
	e.multi = last > i
	e.end = lines[last].end

	switch {
	case v[0] == '"' || v[0] == '\'':
		if q := closeQuote(s, e.first); q >= 0 {
			// Lines indented past the key after the closing quote are not valid YAML,
			// but they belong to this value as they would to a plain one.
			closing := lineOf(lines, line, q)
			last = continuation(s, lines, closing, e.col, false)
			e.end = q + 1
			if last > closing {
				e.end = lines[last].end
			}
			e.multi = last > i
		} else {
			// A quote that never closes (a value cut at the content cap) holds the rest
			// of the content, whatever its indentation.
			last = len(lines) - 1
			e.end, e.multi = lines[last].end, last > i
		}
	case !e.multi:
		e.end = e.first + len(strings.TrimRight(stripComment(v), " \t"))
	}

	return last
}

// continuation returns the index of the last line after line i that is indented
// past col. Blank lines between such lines are included and blank lines after the
// last one left out; so are comment lines, except in a block scalar, where a line
// starting with '#' is content.
func continuation(s string, lines []yamlLine, i, col int, block bool) int {
	last := i

	for j := i + 1; j < len(lines); j++ {
		text := s[lines[j].start:lines[j].end]
		if strings.TrimLeft(text, " \t") == "" || !block && blankOrComment(text) {
			continue
		}
		if indentOf(text) <= col {
			break
		}
		last = j
	}

	return last
}

// scalarBelow returns the index of the line an empty value on line i continues
// on, or -1. That is the next line that is neither blank nor a comment, when it is
// indented past col and does not open a block sequence ("-"), a mapping (a line
// with ": " or ending in ':', which a plain scalar line cannot hold) or a flow
// collection ('[' or '{'). Only that line is read, so a nested mapping costs
// nothing here.
func (m matchers) scalarBelow(s string, lines []yamlLine, i, col int) int {
	for j := i + 1; j < len(lines); j++ {
		text := s[lines[j].start:lines[j].end]
		if blankOrComment(text) {
			continue
		}
		t := strings.TrimLeft(text, " \t")
		if indentOf(text) <= col || t == "-" || strings.HasPrefix(t, "- ") || strings.IndexByte("[{", t[0]) >= 0 ||
			m.mappingKey(t) {
			return -1
		}

		return j
	}

	return -1
}

// mappingKey reports whether line t, without its indentation, holds a mapping
// key. Anchor and tag properties come off first. A quoted line is a key only
// when ':' follows its closing quote, since the quotes can hold ": " themselves;
// any other line is one when it holds ": " or ends in ':', which a plain scalar
// line cannot.
func (m matchers) mappingKey(t string) bool {
	if t = t[len(m.props.FindString(t)):]; t == "" {
		return false
	}
	if t[0] == '"' || t[0] == '\'' {
		return m.quotedKey.MatchString(t)
	}

	return m.mappingLine.MatchString(stripComment(t))
}

// closeQuote returns the offset of the quote that closes the YAML scalar opened at
// s[start], or -1. A double-quoted scalar escapes with '\', a single-quoted one by
// doubling the quote.
func closeQuote(s string, start int) int {
	q := s[start]

	for i := start + 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}

	return -1
}

// lineOf returns the index of the line holding offset off, searching from line i.
func lineOf(lines []yamlLine, i, off int) int {
	for i+1 < len(lines) && lines[i+1].start <= off {
		i++
	}

	return i
}

// stripComment drops a " #" comment from a plain scalar.
func stripComment(v string) string {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return v[:i]
		}
	}

	return v
}

// unquote strips one pair of matching YAML quotes.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}

	return v
}

// mappings returns, for each entry, the index of the first entry of the mapping
// it belongs to, or -1 for a line that is not "key: value". A mapping is the
// entries at one key column, from the "- " line that opens a sequence item to the
// next one, with lines indented further between them; a less indented line or a
// line at that column that is not "key: value" ends it.
func mappings(es []yamlEntry) []int {
	ids := make([]int, len(es))

	var stack []int // the first entry of each open mapping, innermost last

	for i, e := range es {
		for len(stack) > 0 {
			top := es[stack[len(stack)-1]]
			if top.col < e.col || top.col == e.col && e.key != "" && !e.item {
				break
			}
			stack = stack[:len(stack)-1]
		}
		ids[i] = -1
		if e.key == "" {
			continue
		}
		if len(stack) == 0 || es[stack[len(stack)-1]].col != e.col {
			stack = append(stack, i)
		}
		ids[i] = stack[len(stack)-1]
	}

	return ids
}
