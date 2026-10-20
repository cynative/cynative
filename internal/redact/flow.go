package redact

import (
	"encoding/json"
	"strings"
)

// ---- YAML flow collections ----------------------------------------------------

// flows redacts the scalar value of each credential-named key in a YAML flow
// collection ({password: x}, or [password: x], a one-pair mapping), and the
// "value" member of each flow mapping whose "name" member is a credential name. A
// collection is read where a block value or a sequence item may start: after a
// line's indentation and "- " markers, or after a "key: " on the line. A JSON
// document is a flow collection too: under a key that is a JSON string, a
// double-quoted value has its content replaced and keeps its quotes, and any
// other JSON scalar is left as it is, as the JSON passes leave it, unless a tag
// comes before it.
//
// The lines a collection runs over are not read again, except for one found only
// because properties come before its key ("!!str x: {...}"): the lines after its
// first are still read as they were before such collections were read at all,
// and only another one of its kind is skipped inside it.
func (m matchers) flows(s string, lines []yamlLine) flowResult {
	var out flowResult

	next, propped := 0, 0
	for _, l := range lines {
		if l.start < next {
			continue
		}
		text := s[l.start:l.end]
		if at := m.flowStart(text, false); at >= 0 {
			p := flowParser{m: m, s: s, i: l.start + at}
			next = p.parse()
			out.add(&p, l.start+at, next)
		} else if at = m.flowStart(text, true); at >= 0 && l.start >= propped {
			p := flowParser{m: m, s: s, i: l.start + at}
			propped = p.parse()
			out.add(&p, l.start+at, propped)
		}
	}

	return out
}

// flowResult is what flows read: the spans of credential values, and the extent
// of each collection, sorted by start.
type flowResult struct {
	spans  []span
	ranges []yamlLine
}

// add records what p read in the collection from start to end.
func (r *flowResult) add(p *flowParser, start, end int) {
	r.spans = append(r.spans, p.spans...)
	r.ranges = append(r.ranges, yamlLine{start, end})
}

// flowStart returns the offset in line text of the flow collection it opens, or
// -1; with keyProps, properties may also come before the key.
func (m matchers) flowStart(text string, keyProps bool) int {
	at := len(m.flowLead.FindString(text))
	if keyProps {
		at += len(m.flowProps.FindString(text[at:]))
	}
	at += len(m.flowKey.FindString(text[at:]))
	at += len(m.flowProps.FindString(text[at:]))
	if at == len(text) || text[at] != '{' && text[at] != '[' || m.placeholderAt(text, at) > 0 {
		return -1
	}

	return at
}

// placeholderAt returns the length of the redaction placeholder at s[i], or 0.
func (m matchers) placeholderAt(s string, i int) int {
	return len(m.placeholderPrefix.FindString(s[i:]))
}

// flowParser reads one flow collection from s[i] on.
type flowParser struct {
	m      matchers
	s      string
	i      int
	frames []*flowFrame
	spans  []span
}

// flowFrame is one open flow collection. An entry is a node, or a key node, a ':'
// and a value node; key is the last key read, and value is set once its ':' is.
type flowFrame struct {
	key     string
	values  []span // the mapping's "value" members
	mapping bool
	keyJSON bool
	value   bool
	named   bool // the mapping's "name" member is a credential name
}

// parse reads the collection and returns the offset after it. A collection that
// is cut off at the end of content, or closed by the wrong bracket, ends there,
// and the pairs of every mapping still open count.
func (p *flowParser) parse() int {
	for {
		p.skipSpace()
		if p.i >= len(p.s) {
			return p.closeAll()
		}
		switch c := p.s[p.i]; {
		case (c == '{' || c == '[') && p.m.placeholderAt(p.s, p.i) == 0:
			p.entryNode()
			p.frames = append(p.frames, &flowFrame{mapping: c == '{'})
			p.i++
		case c == '}' || c == ']':
			top := p.frames[len(p.frames)-1]
			if top.mapping != (c == '}') {
				return p.closeAll()
			}
			p.close(top)
			p.i++
			if len(p.frames) == 0 {
				return p.i
			}
		default:
			p.punctuation(c)
		}
	}
}

// punctuation reads a ',', a ':', a "? " explicit key indicator, or a scalar.
func (p *flowParser) punctuation(c byte) {
	top := p.frames[len(p.frames)-1]

	switch {
	case c == ',':
		top.key, top.keyJSON, top.value = "", false, false
		p.i++
	case c == ':':
		top.value = true
		p.i++
	case c == '?' && p.i+1 < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i+1]) >= 0:
		p.i++
	default:
		p.scalar(top)
	}
}

// entryNode records that the node at p.i is a collection: as a key it names no
// credential, and as a value it is not one this pass replaces.
func (p *flowParser) entryNode() {
	if len(p.frames) > 0 {
		top := p.frames[len(p.frames)-1]
		if !top.value {
			top.key, top.keyJSON = "", false
		}
	}
}

// scalar reads the scalar at p.i, after any anchor or tag, as the current entry's
// key or value. Under a key that is a JSON string, a JSON scalar other than a
// string is left as it is unless a tag comes before it (a tag can make 1234 a
// string).
func (p *flowParser) scalar(top *flowFrame) {
	tag := p.properties()
	if p.i >= len(p.s) || strings.IndexByte(",:[]{}", p.s[p.i]) >= 0 && p.m.placeholderAt(p.s, p.i) == 0 {
		return
	}
	start := p.i
	end, closed := p.scalarEnd(start, !top.value)
	p.i = end
	raw := p.s[start:p.i]
	text := yamlScalar(raw)
	if !top.value {
		// Two scalars with no ':' or ',' between them are not valid YAML; the
		// second never takes the place of a key that names a credential.
		if !p.m.direct.MatchString(top.key) {
			top.key, top.keyJSON = text, jsonKey(raw)
		}

		return
	}
	top.value = false
	if top.mapping && strings.EqualFold(top.key, "name") && p.m.keyEnd.MatchString(text) {
		top.named = true
	}
	sp := span{start, p.i, placeholder("credential-field")}
	if top.keyJSON && raw[0] == '"' {
		// A string under a key that is a JSON string keeps its quotes, as the JSON
		// passes keep them, so a JSON document stays valid.
		sp = span{start + 1, p.i - boolInt(closed), sp.repl}
	}
	if p.m.done(raw) || p.m.done(text) || p.m.done(p.s[sp.start:sp.end]) ||
		top.keyJSON && !tag && raw[0] != '"' && json.Valid([]byte(raw)) {
		return
	}
	if p.m.credentialKey(top.key, top.keyJSON && raw[0] == '"') {
		p.spans = append(p.spans, sp)
	} else if top.mapping && strings.EqualFold(top.key, "value") {
		top.values = append(top.values, sp)
	}
}

// properties steps past the anchor and tag properties at p.i, with any comment
// between them and before the node, and reports whether they hold a tag.
func (p *flowParser) properties() bool {
	tag := false
	for {
		pr := p.m.flowProps.FindString(p.s[p.i:])
		if pr == "" {
			return tag
		}
		tag = tag || hasTag(pr)
		p.i += len(pr)
		p.skipSpace()
	}
}

// scalarEnd returns the offset after the scalar that starts at s[start], and
// whether it is a quoted one that closes: after its closing quote, or the end of
// content when it has none, for a quoted one. A plain one, which may start with a
// placeholder, runs up to a flow indicator, a ':' before a blank or an indicator,
// or a comment, without the blanks before that; a value runs over lines, while a
// key, which YAML keeps on one line, ends at the line break.
func (p *flowParser) scalarEnd(start int, key bool) (int, bool) {
	s := p.s
	if s[start] == '"' || s[start] == '\'' {
		if q := closeQuote(s, start); q >= 0 {
			return q + 1, true
		}

		return len(s), false
	}
	end := start + max(p.m.placeholderAt(s, start), 1)
	for i := end; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(",[]{}", c) >= 0 || key && c == '\n' ||
			c == ':' && (i+1 == len(s) || strings.IndexByte(" \t\r\n,[]{}", s[i+1]) >= 0) ||
			c == '#' && strings.IndexByte(" \t\r\n", s[i-1]) >= 0 {
			break
		}
		if strings.IndexByte(" \t\r\n", c) < 0 {
			end = i + 1
		}
	}

	return end, false
}

// skipSpace steps past blanks, line breaks and comments.
func (p *flowParser) skipSpace() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case strings.IndexByte(" \t\r\n", c) >= 0:
			p.i++
		case c == '#' && strings.IndexByte(" \t\r\n", p.s[p.i-1]) >= 0:
			// YAML opens a comment only after a blank. Any other '#' starts a
			// scalar, which hides nothing after it and cannot replace a
			// credential key (see scalar).
			if nl := strings.IndexByte(p.s[p.i:], '\n'); nl >= 0 {
				p.i += nl
			} else {
				p.i = len(p.s)
			}
		default:
			return
		}
	}
}

// close ends the innermost collection.
func (p *flowParser) close(top *flowFrame) {
	if top.named {
		p.spans = append(p.spans, top.values...)
	}
	p.frames = p.frames[:len(p.frames)-1]
	if len(p.frames) > 0 {
		p.frames[len(p.frames)-1].value = false
	}
}

// closeAll ends every open collection and returns the offset reading stopped at.
func (p *flowParser) closeAll() int {
	for len(p.frames) > 0 {
		p.close(p.frames[len(p.frames)-1])
	}

	return p.i
}
