package azure

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"slices"
	"strings"
)

// The bounds on $ref resolution in one lookup: distinct files loaded, the operation's own included, the length of
// one chain of refs, and maxDecodedSchema, the bytes charged for every parameter and schema object decoded and every
// name and ref target merged into a body (see merge). A successful decode is memoized once per cache, the parameter
// cache and the schema cache, so one target can decode once through each. A malformed target is not memoized: it is
// decoded, and charged, again each time something reaches it, as an inline object is. A ref target is merged at most
// once per body.
const (
	maxRefFiles      = 16
	maxRefDepth      = 8
	maxDecodedSchema = 16 << 20
	// mergedNameCost is what merging one required or property name, or one ref target's key, charges beyond its own
	// bytes: about the memory of the input and the gap the render can build from a required name, of the schema
	// stored for a property, or of a key's map entry (on a 64-bit platform an apiref.Input is 96 bytes, a
	// swaggerSchema 112 and a refKey 48).
	mergedNameCost = 256
)

// The ref tables the reader follows; responses, examples and every other pointer are not followed.
const (
	refTableParameters  = "parameters"
	refTableDefinitions = "definitions"
)

// The errors that turn a parameter or a body into a gap rather than failing the lookup.
var (
	errRefConfined = errors.New("the ref target is outside the spec trees the index admits")
	errUnindexed   = errors.New("the ref target is not in this commit's index")
	errRefLimit    = errors.New("the ref limit was reached")
	errRefKind     = errors.New("only parameters and definitions refs are followed")
	errRefMissing  = errors.New("the ref target does not exist")
	errBadParam    = errors.New("the parameter is malformed")
	errBadSchema   = errors.New("the schema is malformed")
)

// swaggerMethods are the operation keys of a Swagger 2.0 path item.
//
//nolint:gochecknoglobals // immutable lookup table.
var swaggerMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true, "options": true,
}

// swaggerDoc is the part of a Swagger 2.0 document the reader uses.
type swaggerDoc struct {
	Info        swaggerInfo                           `json:"info"`
	Paths       map[string]map[string]json.RawMessage `json:"paths"`
	XMsPaths    map[string]map[string]json.RawMessage `json:"x-ms-paths"`
	Parameters  map[string]json.RawMessage            `json:"parameters"`
	Definitions map[string]json.RawMessage            `json:"definitions"`
}

type swaggerInfo struct {
	Version string `json:"version"`
}

// swaggerOp is one operation object.
type swaggerOp struct {
	OperationID string            `json:"operationId"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	Parameters  []json.RawMessage `json:"parameters"`
	Pageable    json.RawMessage   `json:"x-ms-pageable"`
	LongRunning bool              `json:"x-ms-long-running-operation"`
}

// swaggerParam is one parameter object. Keys written beside a $ref are ignored, as JSON Reference defines.
type swaggerParam struct {
	Ref              string            `json:"$ref"`
	Name             string            `json:"name"`
	In               string            `json:"in"`
	Required         bool              `json:"required"`
	Type             string            `json:"type"`
	Description      string            `json:"description"`
	Enum             []json.RawMessage `json:"enum"`
	Schema           json.RawMessage   `json:"schema"`
	CollectionFormat string            `json:"collectionFormat"`
	SkipURLEncoding  bool              `json:"x-ms-skip-url-encoding"`
}

// swaggerSchema is the part of a schema object the body rules read.
type swaggerSchema struct {
	Ref         string                     `json:"$ref"`
	Type        string                     `json:"type"`
	Description string                     `json:"description"`
	Required    []string                   `json:"required"`
	Properties  map[string]json.RawMessage `json:"properties"`
	AllOf       []json.RawMessage          `json:"allOf"`
	ReadOnly    bool                       `json:"readOnly"`
}

// bodyShape is a body schema with its allOf parents merged one level deep: the required names as a set, the
// properties by name, and the ref targets already merged.
type bodyShape struct {
	object   bool
	required map[string]bool
	props    map[string]swaggerSchema
	merged   map[refKey]bool
}

// fileSource reads one verified spec file at a commit.
type fileSource interface {
	File(ctx context.Context, sha string, f IndexFile) ([]byte, error)
}

// refResolver follows $refs for one lookup, loading each file at most once and charging what it parses to the
// lookup's budget. It decodes each ref target at most once, and charges every object it decodes and every body
// schema part it merges against maxDecoded.
type refResolver struct {
	src        fileSource
	ix         *Index
	budget     *Budget
	docs       map[string]*swaggerDoc
	paths      map[string]string
	params     map[refKey]swaggerParam
	schemas    map[refKey]swaggerSchema
	decoded    int64
	maxDecoded int64
}

// refKey names one ref target: a file and an entry of its parameters or definitions table.
type refKey struct {
	file, table, name string
}

// newRefResolver builds the resolver for one lookup.
func newRefResolver(src fileSource, ix *Index, b *Budget) *refResolver {
	return &refResolver{
		src: src, ix: ix, budget: b, docs: map[string]*swaggerDoc{}, paths: map[string]string{},
		params: map[refKey]swaggerParam{}, schemas: map[refKey]swaggerSchema{}, maxDecoded: maxDecodedSchema,
	}
}

// decodeSwagger decodes a spec file.
func decodeSwagger(body []byte) (*swaggerDoc, error) {
	var d swaggerDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("%w: spec file: %w", ErrSpecsRejected, err)
	}

	return &d, nil
}

// Summarize lists a spec file's operations: paths first, then x-ms-paths, each sorted by path, then by method. An
// operation with no string operationId is left out.
func Summarize(body []byte) (*FileSummary, error) {
	d, err := decodeSwagger(body)
	if err != nil {
		return nil, err
	}
	ops := appendOps([]OpSummary{}, d.Paths, false)
	ops = appendOps(ops, d.XMsPaths, true)

	return &FileSummary{Version: d.Info.Version, Ops: ops}, nil
}

func appendOps(out []OpSummary, paths map[string]map[string]json.RawMessage, xms bool) []OpSummary {
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		item := paths[p]
		for _, m := range slices.Sorted(maps.Keys(item)) {
			var op struct {
				OperationID string `json:"operationId"`
			}
			if !swaggerMethods[m] || json.Unmarshal(item[m], &op) != nil || op.OperationID == "" {
				continue
			}
			out = append(out, OpSummary{ID: op.OperationID, Method: strings.ToUpper(m), Path: p, XMs: xms})
		}
	}

	return out
}

// operation returns the operation a summary names and its path item's own parameters.
func (d *swaggerDoc) operation(s OpSummary) (swaggerOp, []json.RawMessage, error) {
	if !swaggerMethods[strings.ToLower(s.Method)] || s.ID == "" {
		return swaggerOp{}, nil, fmt.Errorf("%w: summary has invalid method %q or empty id", ErrSpecsRejected, s.Method)
	}
	paths := d.Paths
	if s.XMs {
		paths = d.XMsPaths
	}
	item := paths[s.Path]
	raw, ok := item[strings.ToLower(s.Method)]
	if !ok {
		return swaggerOp{}, nil, fmt.Errorf("%w: no operation %s %s", ErrSpecsRejected, s.Method, s.Path)
	}
	var op swaggerOp
	if err := json.Unmarshal(raw, &op); err != nil {
		return swaggerOp{}, nil, fmt.Errorf("%w: operation %s %s: %w", ErrSpecsRejected, s.Method, s.Path, err)
	}
	// The summary that led here is a cache; the file is verified by its blob id, so the file decides.
	if op.OperationID != s.ID {
		return swaggerOp{}, nil, fmt.Errorf("%w: the operation at %s %s is %q, not %q", ErrSpecsRejected,
			s.Method, s.Path, op.OperationID, s.ID)
	}
	var common []json.RawMessage
	if pr, has := item[refTableParameters]; has {
		if err := json.Unmarshal(pr, &common); err != nil {
			return swaggerOp{}, nil, fmt.Errorf("%w: parameters of %s: %w", ErrSpecsRejected, s.Path, err)
		}
	}

	return op, common, nil
}

// refGap reports whether err makes an input or a body a gap. Budget, context and load errors end the lookup instead.
func refGap(err error) bool {
	for _, gap := range []error{
		errRefConfined, errUnindexed, errRefLimit, errRefKind, errRefMissing, errBadParam, errBadSchema,
	} {
		if errors.Is(err, gap) {
			return true
		}
	}

	return false
}

// add registers a document the caller already read and charged, under the same per-lookup file bound load
// applies, so the operation files a lookup renders count toward maxRefFiles like the files their refs reach.
func (r *refResolver) add(p string, d *swaggerDoc) error {
	if _, ok := r.docs[p]; ok {
		return nil
	}
	if len(r.docs) >= maxRefFiles {
		return fmt.Errorf("%w: more than %d files", errRefLimit, maxRefFiles)
	}
	r.docs[p], r.paths[p] = d, p

	return nil
}

// param resolves one parameter object, following a $ref chain of at most maxRefDepth links. It returns the
// parameter, the file it lives in and whether it came through a $ref (the shared-parameter shape).
func (r *refResolver) param(ctx context.Context, from string, raw json.RawMessage) (swaggerParam, string, bool, error) {
	var p swaggerParam
	err := r.decode(raw, &p, errBadParam)
	shared := false
	for depth := 0; ; depth++ {
		if err != nil {
			return swaggerParam{}, "", shared, err
		}
		if p.Ref == "" {
			if p.Name == "" || p.In == "" {
				return swaggerParam{}, "", shared, fmt.Errorf("%w: no name or location", errBadParam)
			}

			return p, from, shared, nil
		}
		if depth == maxRefDepth {
			return swaggerParam{}, "", shared, fmt.Errorf("%w: a chain longer than %d", errRefLimit, maxRefDepth)
		}
		var key refKey
		key, err = r.target(ctx, from, p.Ref)
		if err == nil {
			p, err = targetOf(r, r.params, key, errBadParam)
		}
		from, shared = key.file, true
	}
}

// schema decodes a schema object, following a top-level $ref chain of at most maxRefDepth links, and returns the
// schema and where it lives: the last ref target of the chain, or only the file for an inline schema. Two keys
// written beside a $ref are kept, as AutoRest keeps them: readOnly (any link marking it read-only makes the property
// read-only, so a required one is dropped from the body, never sent) and description (the outermost one wins).
func (r *refResolver) schema(ctx context.Context, from string, raw json.RawMessage) (swaggerSchema, refKey, error) {
	var s swaggerSchema
	err := r.decode(raw, &s, errBadSchema)
	readOnly, desc := false, ""
	key := refKey{file: from}
	for depth := 0; ; depth++ {
		if err != nil {
			return swaggerSchema{}, refKey{}, err
		}
		readOnly = readOnly || s.ReadOnly
		desc = cmp.Or(desc, s.Description)
		if s.Ref == "" {
			s.ReadOnly, s.Description = readOnly, desc

			return s, key, nil
		}
		if depth == maxRefDepth {
			return swaggerSchema{}, refKey{}, fmt.Errorf("%w: a chain longer than %d", errRefLimit, maxRefDepth)
		}
		key, err = r.target(ctx, key.file, s.Ref)
		if err == nil {
			s, err = targetOf(r, r.schemas, key, errBadSchema)
		}
	}
}

// body resolves a body schema and merges its allOf parents one level deep, one part at a time: the schema's own
// properties before its parents', each property resolved through its own $ref so its type and readOnly are known.
func (r *refResolver) body(ctx context.Context, from string, raw json.RawMessage) (bodyShape, error) {
	s, key, err := r.schema(ctx, from, raw)
	if err != nil {
		return bodyShape{}, err
	}
	if s.Type != "object" && (s.Type != "" || (len(s.Properties) == 0 && len(s.AllOf) == 0)) {
		return bodyShape{}, nil
	}
	shape := bodyShape{
		object: true, required: map[string]bool{}, props: map[string]swaggerSchema{}, merged: map[refKey]bool{},
	}
	if err = r.merge(ctx, &shape, s, key); err != nil {
		return bodyShape{}, err
	}
	for _, a := range s.AllOf {
		ps, pk, perr := r.schema(ctx, key.file, a)
		if perr != nil {
			return bodyShape{}, perr
		}
		if err = r.merge(ctx, &shape, ps, pk); err != nil {
			return bodyShape{}, err
		}
	}

	return shape, nil
}

// merge adds one part's required names and the properties shape does not have yet, each property resolved from the
// part's file. Its invariant:
//
//   - Deduplicated: a ref target already in shape.merged is skipped before anything is charged or stored, and a
//     required name or a property is stored once, so one body holds at most the distinct targets and names its
//     documents contain.
//   - Charged before stored: merge adds up the part's key (the lengths of its file and name, for a ref target) and
//     each of its required and property names, each plus mergedNameCost, charges the sum against maxDecoded, and
//     only then stores the key and the names. It charges each property schema as it decodes it. A memoized ref target
//     is decoded once but charged on every merge, so one lookup merges at most maxDecodedSchema / mergedNameCost
//     (65,536) ref targets and names across all its bodies and candidates.
//   - Keys hold their own strings: a stored key's file is the resolver's one copy of that path (see target), its
//     table a constant and its name a copy (see refPointer), so a key keeps no document string alive and its charge
//     covers its own bytes. Keys share the file string, so charging its length for each key overcounts it.
//
// Together these keep the merged state of one lookup within a constant factor of the bytes charged, which the decode
// bound caps, however the documents repeat or spread their parts. merge checks the context first and before each
// property, since a cached ref target costs no read that would.
func (r *refResolver) merge(ctx context.Context, shape *bodyShape, part swaggerSchema, key refKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var cost int64
	if key.name != "" {
		if shape.merged[key] {
			return nil
		}
		cost = int64(len(key.file) + len(key.name) + mergedNameCost)
	}
	for _, name := range part.Required {
		cost += int64(len(name) + mergedNameCost)
	}
	for name := range part.Properties {
		cost += int64(len(name) + mergedNameCost)
	}
	if err := r.charge(cost); err != nil {
		return err
	}
	if key.name != "" {
		shape.merged[key] = true
	}
	for _, name := range part.Required {
		shape.required[name] = true
	}
	for _, name := range slices.Sorted(maps.Keys(part.Properties)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		prop, _, err := r.schema(ctx, key.file, part.Properties[name])
		if err != nil {
			return err
		}
		if _, seen := shape.props[name]; !seen {
			shape.props[name] = prop
		}
	}

	return nil
}

// decode decodes raw into v after charging its bytes against maxDecoded; malformed wraps a decode error.
func (r *refResolver) decode(raw json.RawMessage, v any, malformed error) error {
	if err := r.charge(int64(len(raw))); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %w", malformed, err)
	}

	return nil
}

// charge counts n bytes against maxDecoded and fails once the count passes it.
func (r *refResolver) charge(n int64) error {
	r.decoded += n
	if r.decoded > r.maxDecoded {
		return fmt.Errorf("%w: more than %d bytes of parameters and schemas decoded or merged", errRefLimit,
			r.maxDecoded)
	}

	return nil
}

// targetOf returns the decoded ref target key names, decoding it on its first use in the lookup only.
func targetOf[T any](r *refResolver, cache map[refKey]T, key refKey, malformed error) (T, error) {
	if v, ok := cache[key]; ok {
		return v, nil
	}
	var v T
	if err := r.decode(r.raw(key), &v, malformed); err != nil {
		return v, err
	}
	cache[key] = v

	return v, nil
}

// raw returns the object key names in its file, which target has already loaded.
func (r *refResolver) raw(key refKey) json.RawMessage {
	d := r.docs[key.file]
	if key.table == refTableDefinitions {
		return d.Definitions[key.name]
	}

	return d.Parameters[key.name]
}

// target follows one $ref written in file from, loading the file it names, and returns the target's key once the
// target is known to exist. The key's file is the copy of the path the resolver kept when it loaded the file, not the
// one refPath built, so every key naming a file shares one string.
func (r *refResolver) target(ctx context.Context, from, ref string) (refKey, error) {
	file, pointer, found := strings.Cut(ref, "#")
	if !found {
		return refKey{}, fmt.Errorf("%w: %q has no JSON pointer", errRefKind, ref)
	}
	target, err := refPath(from, file, r.ix)
	if err != nil {
		return refKey{}, err
	}
	table, name, err := refPointer(pointer)
	if err != nil {
		return refKey{}, err
	}
	d, err := r.load(ctx, target)
	if err != nil {
		return refKey{}, err
	}
	entries := d.Parameters
	if table == refTableDefinitions {
		entries = d.Definitions
	}
	if _, ok := entries[name]; !ok {
		return refKey{}, fmt.Errorf("%w: %q", errRefMissing, ref)
	}

	return refKey{file: r.paths[target], table: table, name: name}, nil
}

// load returns the decoded file at p, reading and charging it once per lookup.
func (r *refResolver) load(ctx context.Context, p string) (*swaggerDoc, error) {
	if d, ok := r.docs[p]; ok {
		return d, nil
	}
	if len(r.docs) >= maxRefFiles {
		return nil, fmt.Errorf("%w: more than %d files", errRefLimit, maxRefFiles)
	}
	body, err := r.src.File(ctx, r.ix.SHA, IndexFile{Path: p, Blob: r.ix.Refs[p]})
	if err != nil {
		return nil, err
	}
	if chargeErr := r.budget.Charge(int64(len(body))); chargeErr != nil {
		return nil, chargeErr
	}
	d, err := decodeSwagger(body)
	if err != nil {
		return nil, err
	}
	r.docs[p], r.paths[p] = d, p

	return d, nil
}

// refPath resolves the file part of a ref against the referring file's directory. Only a relative path with no
// scheme, host, query or backslash is accepted, and the result must be a ref target of the index.
func refPath(from, file string, ix *Index) (string, error) {
	if file == "" {
		if err := indexed(ix, from, from); err != nil {
			return "", err
		}

		return from, nil
	}
	u, err := url.Parse(file)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery ||
		strings.HasPrefix(u.Path, "/") || strings.Contains(file, `\`) {
		return "", fmt.Errorf("%w: %q", errRefConfined, file)
	}
	target := path.Clean(path.Join(path.Dir(from), u.Path))
	if err = indexed(ix, target, file); err != nil {
		return "", err
	}

	return target, nil
}

// indexed reports whether p, which the ref written as ref names, is a ref target of the index: a path the trees
// admit that the index lacks is missing from this commit's index, and any other path is outside the admitted trees.
func indexed(ix *Index, p, ref string) error {
	if _, ok := ix.Refs[p]; ok {
		return nil
	}
	if refTarget(p) {
		return fmt.Errorf("%w: %q", errUnindexed, ref)
	}

	return fmt.Errorf("%w: %q", errRefConfined, ref)
}

// refPointer splits a JSON pointer of the form /parameters/<name> or /definitions/<name> and unescapes the name as
// RFC 6901 defines (~1 is '/', ~0 is '~'). It returns the table as a constant and the name as a copy, so a key built
// from them keeps none of the $ref string alive.
func refPointer(pointer string) (string, string, error) {
	parts := strings.Split(pointer, "/")
	if len(parts) != 3 || parts[0] != "" || parts[2] == "" ||
		(parts[1] != refTableParameters && parts[1] != refTableDefinitions) {
		return "", "", fmt.Errorf("%w: pointer %q", errRefKind, pointer)
	}
	table := refTableParameters
	if parts[1] == refTableDefinitions {
		table = refTableDefinitions
	}

	return table, strings.NewReplacer("~1", "/", "~0", "~").Replace(strings.Clone(parts[2])), nil
}
