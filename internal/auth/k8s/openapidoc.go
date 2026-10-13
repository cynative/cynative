package k8s

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Pre-pass bounds. Over a cap the document is unavailable: it is never answered from a truncated set.
const (
	// MaxOperations bounds the operations in one document.
	MaxOperations = 4000
	// MaxOperationParams bounds one operation's parameters, path-level and operation-level, references counted.
	MaxOperationParams = 64
	// MaxParamRefs bounds the parameters of every operation of a document, summed.
	MaxParamRefs = 25_000
	// maxPathBytes is the longest path the path form reads.
	maxPathBytes = 2048
	// maxIDBytes is the longest operation id the lookup grammar admits.
	maxIDBytes = 200
	// maxParamNameBytes is the longest parameter name the name grammar admits.
	maxParamNameBytes = 100
	// paramRefPrefix is the only reference form a parameter may use.
	paramRefPrefix = "#/components/parameters/"
	// The parameter locations the tool renders.
	inPath   = "path"
	inQuery  = "query"
	inHeader = "header"
)

// ErrDocument marks a group-version document the pre-pass refuses. Its text is fixed host text.
var ErrDocument = errors.New("the document")

// ErrShape marks a document that does not decode into the shape the pre-pass or the core reads.
var ErrShape = fmt.Errorf("%w does not decode into the OpenAPI shape this tool reads", ErrDocument)

// Unrenderable reasons: why an operation the index lists cannot be described.
const (
	reasonPath     = "its path is outside the form this tool renders"
	reasonName     = "a parameter's name is outside the form this tool renders"
	reasonLocation = "a parameter's location is not path, query or header"
	reasonType     = "a parameter's type is not one this tool renders"
	reasonRef      = "a parameter's reference does not name a component parameter"
	reasonLabel    = "its path names a label that is not a declared path parameter"
)

//nolint:gochecknoglobals // immutable lookup table.
var paramTypes = map[string]bool{
	"string": true, "integer": true, "number": true, "boolean": true, "array": true, "object": true,
}

var (
	// idPattern is the lookup grammar for an operation id.
	idPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,199}$`)
	// paramNamePattern is the grammar for a parameter name.
	paramNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,99}$`)
)

// ValidOperationID reports an id in the lookup grammar.
func ValidOperationID(id string) bool {
	return len(id) <= maxIDBytes && idPattern.MatchString(id)
}

// Class is how the index answers a lookup of one operation id.
type Class int

// The index classes.
const (
	// ClassAdmitted is an id on exactly one operation, which the tool renders.
	ClassAdmitted Class = iota + 1
	// ClassDuplicate is an id the document lists on more than one operation.
	ClassDuplicate
	// ClassUnrenderable is an id on one operation outside the form the tool renders.
	ClassUnrenderable
)

// Route is one METHOD and path an id is listed on. PathOK is whether the path passed the path form.
type Route struct {
	Method string
	Path   string
	PathOK bool
}

// IndexEntry is one indexed operation id.
type IndexEntry struct {
	Class  Class
	Routes []Route
	// Reason is the fixed reason of an unrenderable id.
	Reason string
}

// Extras are the facts of an admitted operation the core does not keep, as the document wrote them.
type Extras struct {
	Description  string
	Kind         string
	RequestTypes []string
	ResponseRef  string
	ResponseType string
}

// Prepared is the pre-pass result: the index over every operation whose id is in the lookup grammar, the count of
// operations that cannot be looked up, and the extras of each admitted operation.
type Prepared struct {
	Index    map[string]IndexEntry
	Excluded int
	Extras   map[string]Extras
	// operations counts every operation the document lists.
	operations int
}

// Admitted reports whether the core keeps an operation: its id is admitted on exactly this METHOD and path.
func (p *Prepared) Admitted(method, path, id string) bool {
	e, ok := p.Index[id]
	return ok && e.Class == ClassAdmitted && e.Routes[0].Method == method && e.Routes[0].Path == path
}

// prepParam is a parameter as the core decodes it: $ref typed, every other field raw.
type prepParam struct {
	Ref    string          `json:"$ref"`
	Name   json.RawMessage `json:"name"`
	In     json.RawMessage `json:"in"`
	Schema json.RawMessage `json:"schema"`
}

type prepBody struct {
	Content map[string]json.RawMessage `json:"content"`
}

type prepOp struct {
	OperationID json.RawMessage            `json:"operationId"`
	Description json.RawMessage            `json:"description"`
	GVK         json.RawMessage            `json:"x-kubernetes-group-version-kind"`
	Parameters  []prepParam                `json:"parameters"`
	RequestBody *prepBody                  `json:"requestBody"`
	Responses   map[string]json.RawMessage `json:"responses"`
}

// prepPathItem has the core's method fields and JSON names, so encoding/json binds the same method keys in both.
type prepPathItem struct {
	// RawParameters stays raw until an operation of the item needs it: a path item with no operation can hold most
	// of a document's counted elements, and decoding them would cost slices nothing reads.
	RawParameters json.RawMessage `json:"parameters"`
	Parameters    []prepParam     `json:"-"`
	Get           *prepOp         `json:"get"`
	Head          *prepOp         `json:"head"`
	Post          *prepOp         `json:"post"`
	Put           *prepOp         `json:"put"`
	Patch         *prepOp         `json:"patch"`
	Delete        *prepOp         `json:"delete"`
	Options       *prepOp         `json:"options"`
}

func (it *prepPathItem) ops() map[string]*prepOp {
	return map[string]*prepOp{
		"GET": it.Get, "HEAD": it.Head, "POST": it.Post, "PUT": it.Put,
		"PATCH": it.Patch, "DELETE": it.Delete, "OPTIONS": it.Options,
	}
}

type prepDoc struct {
	Paths      map[string]prepPathItem `json:"paths"`
	Components struct {
		Parameters map[string]prepParam `json:"parameters"`
	} `json:"components"`
}

// paramFacts is a parameter's verdict: its location and name when it renders, else the reason it does not.
type paramFacts struct {
	in, name, reason string
}

// prepper is one pre-pass: the document, its key, each component parameter's verdict computed once, and the
// operations admitted so far.
type prepper struct {
	doc        *prepDoc
	key        string
	components map[string]paramFacts
	out        *Prepared
	admitted   map[string]*prepOp
}

// Prepare reads a group-version document that already passed the streaming pass: it enforces the caps, the path
// form and the parameter rules, and indexes every operation whose id is in the lookup grammar. key is the
// document key, api/<version> or apis/<group>/<version>.
func Prepare(ctx context.Context, raw []byte, key string) (*Prepared, error) {
	var doc prepDoc
	if json.Unmarshal(raw, &doc) != nil {
		return nil, ErrShape
	}
	if err := checkCaps(&doc); err != nil {
		return nil, err
	}
	p := &prepper{
		doc: &doc, key: key, components: map[string]paramFacts{}, admitted: map[string]*prepOp{},
		out: &Prepared{Index: map[string]IndexEntry{}, Extras: map[string]Extras{}},
	}
	for path, item := range doc.Paths {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("k8s: prepare: %w", err)
		}
		// The path item's parameters are checked once, when its first operation needs them, and shared by its
		// methods; a path item with no operation never has them checked.
		var shared []paramFacts
		checked := false
		for method, op := range item.ops() {
			if op == nil {
				continue
			}
			if !checked {
				shared, checked = p.factsOf(item.Parameters), true
			}
			p.add(method, path, shared, op)
		}
	}
	for id, op := range p.admitted {
		p.out.Extras[id] = extrasOf(op)
	}
	for id, e := range p.out.Index {
		slices.SortFunc(
			e.Routes,
			// Compared field by field: joining them would copy each path, however long, on every comparison.
			func(a, b Route) int {
				return cmp.Or(strings.Compare(a.Method, b.Method), strings.Compare(a.Path, b.Path))
			},
		)
		p.out.Index[id] = e
	}
	switch {
	case p.out.operations == 0:
		return nil, fmt.Errorf("%w lists no operation", ErrDocument)
	case len(p.out.Index) == 0:
		return nil, fmt.Errorf("%w lists no operation id this tool can look up", ErrDocument)
	}

	return p.out, nil
}

// checkCaps refuses a document over a cap before anything is indexed.
func checkCaps(doc *prepDoc) error {
	ops, refs := 0, 0
	for path, item := range doc.Paths {
		decoded := false
		for _, op := range item.ops() {
			if op == nil {
				continue
			}
			if !decoded {
				if len(item.RawParameters) > 0 && json.Unmarshal(item.RawParameters, &item.Parameters) != nil {
					return ErrShape
				}
				doc.Paths[path], decoded = item, true
			}
			ops++
			n := len(item.Parameters) + len(op.Parameters)
			refs += n
			if n > MaxOperationParams {
				return fmt.Errorf("%w has an operation with more than %d parameters", ErrDocument, MaxOperationParams)
			}
		}
	}
	if ops > MaxOperations {
		return fmt.Errorf("%w has more than %d operations", ErrDocument, MaxOperations)
	}
	if refs > MaxParamRefs {
		return fmt.Errorf("%w has more than %d parameter references", ErrDocument, MaxParamRefs)
	}

	return nil
}

// add indexes one operation under its id.
func (p *prepper) add(method, path string, shared []paramFacts, op *prepOp) {
	p.out.operations++
	id := text(op.OperationID)
	if !ValidOperationID(id) {
		p.out.Excluded++
		return
	}
	labels, pathOK := pathLabels(path, p.key)
	declared, reason := parameters(shared, p.factsOf(op.Parameters))
	// A route is safe to show, as an ambiguity choice among others, only when the whole path form holds: every
	// label also names a declared path parameter.
	labelsOK := pathOK && allDeclared(labels, declared)
	route := Route{Method: method, Path: path, PathOK: labelsOK}
	if e, seen := p.out.Index[id]; seen {
		delete(p.admitted, id)
		p.out.Index[id] = IndexEntry{Class: ClassDuplicate, Routes: append(e.Routes, route)}
		return
	}
	switch {
	case !pathOK:
		reason = reasonPath
	case reason == "" && !labelsOK:
		reason = reasonLabel
	}
	if reason != "" {
		p.out.Index[id] = IndexEntry{Class: ClassUnrenderable, Routes: []Route{route}, Reason: reason}
		return
	}
	p.out.Index[id] = IndexEntry{Class: ClassAdmitted, Routes: []Route{route}}
	p.admitted[id] = op
}

// factsOf checks each parameter of a list.
func (p *prepper) factsOf(list []prepParam) []paramFacts {
	out := make([]paramFacts, len(list))
	for i, raw := range list {
		out[i] = p.facts(raw)
	}

	return out
}

// parameters reads the checked parameters of one operation, the path item's then its own. It returns the names of
// its valid declared path parameters, collected from every parameter whatever its order, and the first reason a
// parameter cannot be rendered, or "".
func parameters(shared, own []paramFacts) (map[string]bool, string) {
	// An operation parameter replaces the path item's with the same name and location, as the core's merge does,
	// so a shared definition it overrides is not checked against the operation.
	overridden := map[[2]string]bool{}
	for _, f := range own {
		overridden[[2]string{f.name, f.in}] = true
	}
	declared, reason := map[string]bool{}, ""
	for i, list := range [][]paramFacts{shared, own} {
		for _, f := range list {
			if i == 0 && overridden[[2]string{f.name, f.in}] {
				continue
			}
			switch {
			case f.reason != "":
				if reason == "" {
					reason = f.reason
				}
			case f.in == inPath:
				declared[f.name] = true
			}
		}
	}

	return declared, reason
}

// allDeclared reports whether every label names a declared path parameter.
func allDeclared(labels []string, declared map[string]bool) bool {
	for _, l := range labels {
		if !declared[l] {
			return false
		}
	}

	return true
}

// facts is a parameter's verdict. A component parameter's verdict is computed once and shared by every reference.
func (p *prepper) facts(raw prepParam) paramFacts {
	if raw.Ref == "" {
		return paramVerdict(raw)
	}
	name, ok := strings.CutPrefix(raw.Ref, paramRefPrefix)
	if !ok {
		return paramFacts{reason: reasonRef}
	}
	if f, done := p.components[name]; done {
		return f
	}
	comp, found := p.doc.Components.Parameters[name]
	f := paramFacts{reason: reasonRef}
	if found && comp.Ref == "" {
		f = paramVerdict(comp)
	}
	p.components[name] = f

	return f
}

// paramVerdict checks one parameter object's name, location and schema type.
func paramVerdict(raw prepParam) paramFacts {
	f := paramFacts{in: text(raw.In), name: text(raw.Name)}
	switch {
	case len(f.name) > maxParamNameBytes || !paramNamePattern.MatchString(f.name):
		f.reason = reasonName
	case f.in != inPath && f.in != inQuery && f.in != inHeader:
		f.reason = reasonLocation
	default:
		// Only a string type can fall outside the vocabulary. Any other value is no type, and it is never decoded:
		// an object or array here can nest below the streaming pass's counted depth.
		if t := objectOf(raw.Schema)["type"]; len(t) > 0 && t[0] == '"' && !paramTypes[text(t)] {
			f.reason = reasonType
		}
	}

	return f
}

// pathLabels checks the path form on the path as written, by an index walk after the length check: /<key>,
// /<key>/, or /<key>/ followed by segments that are each a literal or a whole-segment {label}. It returns the
// labels in order.
func pathLabels(path, key string) ([]string, bool) {
	if len(path) > maxPathBytes {
		return nil, false
	}
	rest, ok := strings.CutPrefix(path, "/"+key)
	if !ok {
		return nil, false
	}
	if rest == "" || rest == "/" {
		return nil, true
	}
	if rest[0] != '/' {
		return nil, false
	}
	var labels []string
	for start := 1; start <= len(rest); {
		end := strings.IndexByte(rest[start:], '/')
		if end < 0 {
			end = len(rest) - start
		}
		seg := rest[start : start+end]
		label, isLabel := wholeLabel(seg)
		switch {
		case isLabel:
			labels = append(labels, label)
		case !literalSegment(seg):
			return nil, false
		}
		start += end + 1
	}

	return labels, true
}

// wholeLabel reports a segment that is exactly {name}, with a name in the parameter name grammar.
func wholeLabel(seg string) (string, bool) {
	if len(seg) < len("{x}") || seg[0] != '{' || seg[len(seg)-1] != '}' {
		return "", false
	}
	name := seg[1 : len(seg)-1]

	return name, len(name) <= maxParamNameBytes && paramNamePattern.MatchString(name)
}

// literalSegment reports a segment from [A-Za-z0-9._-] that starts and ends with a letter or digit, which rules out
// an empty segment, a dot segment and every escape.
func literalSegment(seg string) bool {
	if seg == "" || !alnum(seg[0]) || !alnum(seg[len(seg)-1]) {
		return false
	}
	for i := range len(seg) {
		if c := seg[i]; !alnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}

	return true
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// extrasOf reads an admitted operation's facts the core does not keep: its description, its kind, its request
// media types, and its 200 application/json schema's reference or type.
func extrasOf(op *prepOp) Extras {
	x := Extras{Description: text(op.Description), Kind: text(objectOf(op.GVK)["kind"])}
	if op.RequestBody != nil {
		for mt := range op.RequestBody.Content {
			x.RequestTypes = append(x.RequestTypes, mt)
		}
		slices.Sort(x.RequestTypes)
	}
	content := objectOf(objectOf(op.Responses["200"])["content"])
	schema := objectOf(objectOf(content["application/json"])["schema"])
	x.ResponseRef, x.ResponseType = text(schema["$ref"]), text(schema["type"])

	return x
}

// objectOf decodes a JSON object by exact key, the last of repeated keys winning, or returns nil.
func objectOf(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}

	return m
}

// text returns raw as a string when it is a JSON string and "" otherwise.
func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}

	return s
}
