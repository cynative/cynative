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

// The bounds on $ref resolution in one lookup: distinct files loaded, the operation's own included, and the length
// of one chain of refs.
const (
	maxRefFiles = 16
	maxRefDepth = 8
)

// The ref tables the reader follows; responses, examples and every other pointer are not followed.
const (
	refTableParameters  = "parameters"
	refTableDefinitions = "definitions"
)

// The errors that turn a parameter or a body into a gap rather than failing the lookup.
var (
	errRefConfined = errors.New("the ref target is not a spec file of this commit")
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

// bodyShape is a body schema with its allOf parents merged one level deep.
type bodyShape struct {
	object   bool
	required []string
	props    map[string]swaggerSchema
}

// fileSource reads one verified spec file at a commit.
type fileSource interface {
	File(ctx context.Context, sha string, f IndexFile) ([]byte, error)
}

// refResolver follows $refs for one lookup, loading each file at most once and charging what it parses to the
// lookup's budget.
type refResolver struct {
	src    fileSource
	ix     *Index
	budget *Budget
	docs   map[string]*swaggerDoc
}

// newRefResolver builds the resolver for one lookup.
func newRefResolver(src fileSource, ix *Index, b *Budget) *refResolver {
	return &refResolver{src: src, ix: ix, budget: b, docs: map[string]*swaggerDoc{}}
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
	for _, gap := range []error{errRefConfined, errRefLimit, errRefKind, errRefMissing, errBadParam, errBadSchema} {
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
	r.docs[p] = d

	return nil
}

// param resolves one parameter object, following a $ref chain of at most maxRefDepth links. It returns the
// parameter, the file it lives in and whether it came through a $ref (the shared-parameter shape).
func (r *refResolver) param(ctx context.Context, from string, raw json.RawMessage) (swaggerParam, string, bool, error) {
	shared := false
	for depth := 0; ; depth++ {
		var p swaggerParam
		if err := json.Unmarshal(raw, &p); err != nil {
			return swaggerParam{}, "", shared, fmt.Errorf("%w: %w", errBadParam, err)
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
		next, file, err := r.resolve(ctx, from, p.Ref)
		if err != nil {
			return swaggerParam{}, "", shared, err
		}
		raw, from, shared = next, file, true
	}
}

// schema decodes a schema object, following a top-level $ref chain of at most maxRefDepth links, and returns the
// schema and the file it lives in. Two keys written beside a $ref are kept, as AutoRest keeps them: readOnly (any
// link marking it read-only makes the property read-only, so a required one is dropped from the body, never sent)
// and description (the outermost one wins).
func (r *refResolver) schema(ctx context.Context, from string, raw json.RawMessage) (swaggerSchema, string, error) {
	readOnly, desc := false, ""
	for depth := 0; ; depth++ {
		var s swaggerSchema
		if err := json.Unmarshal(raw, &s); err != nil {
			return swaggerSchema{}, "", fmt.Errorf("%w: %w", errBadSchema, err)
		}
		readOnly = readOnly || s.ReadOnly
		desc = cmp.Or(desc, s.Description)
		if s.Ref == "" {
			s.ReadOnly, s.Description = readOnly, desc

			return s, from, nil
		}
		if depth == maxRefDepth {
			return swaggerSchema{}, "", fmt.Errorf("%w: a chain longer than %d", errRefLimit, maxRefDepth)
		}
		next, file, err := r.resolve(ctx, from, s.Ref)
		if err != nil {
			return swaggerSchema{}, "", err
		}
		raw, from = next, file
	}
}

// body resolves a body schema and merges its allOf parents one level deep: required names in order, the schema's own
// properties before its parents', each property resolved through its own $ref so its type and readOnly are known.
//
//nolint:unparam // from varies in production (Tasks 7-8); tests use one file for simplicity.
func (r *refResolver) body(ctx context.Context, from string, raw json.RawMessage) (bodyShape, error) {
	s, file, err := r.schema(ctx, from, raw)
	if err != nil {
		return bodyShape{}, err
	}
	if s.Type != "object" && (s.Type != "" || (len(s.Properties) == 0 && len(s.AllOf) == 0)) {
		return bodyShape{}, nil
	}
	parts, files := []swaggerSchema{s}, []string{file}
	for _, a := range s.AllOf {
		ps, pf, perr := r.schema(ctx, file, a)
		if perr != nil {
			return bodyShape{}, perr
		}
		parts, files = append(parts, ps), append(files, pf)
	}
	shape := bodyShape{object: true, props: map[string]swaggerSchema{}}
	for i, part := range parts {
		shape.required = append(shape.required, part.Required...)
		for _, name := range slices.Sorted(maps.Keys(part.Properties)) {
			prop, _, perr := r.schema(ctx, files[i], part.Properties[name])
			if perr != nil {
				return bodyShape{}, perr
			}
			if _, seen := shape.props[name]; !seen {
				shape.props[name] = prop
			}
		}
	}

	return shape, nil
}

// resolve follows one $ref written in file from and returns the target object and the file it lives in.
func (r *refResolver) resolve(ctx context.Context, from, ref string) (json.RawMessage, string, error) {
	file, pointer, found := strings.Cut(ref, "#")
	if !found {
		return nil, "", fmt.Errorf("%w: %q has no JSON pointer", errRefKind, ref)
	}
	target, err := refPath(from, file, r.ix)
	if err != nil {
		return nil, "", err
	}
	table, name, err := refPointer(pointer)
	if err != nil {
		return nil, "", err
	}
	d, err := r.load(ctx, target)
	if err != nil {
		return nil, "", err
	}
	entries := d.Parameters
	if table == refTableDefinitions {
		entries = d.Definitions
	}
	raw, ok := entries[name]
	if !ok {
		return nil, "", fmt.Errorf("%w: %q", errRefMissing, ref)
	}

	return raw, target, nil
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
	r.docs[p] = d

	return d, nil
}

// refPath resolves the file part of a ref against the referring file's directory. Only a relative path with no
// scheme, host, query or backslash is accepted, and the result must be a ref target of the index.
func refPath(from, file string, ix *Index) (string, error) {
	if file == "" {
		return from, nil
	}
	u, err := url.Parse(file)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery ||
		strings.HasPrefix(u.Path, "/") || strings.Contains(file, `\`) {
		return "", fmt.Errorf("%w: %q", errRefConfined, file)
	}
	target := path.Clean(path.Join(path.Dir(from), u.Path))
	if _, ok := ix.Refs[target]; !ok {
		return "", fmt.Errorf("%w: %q", errRefConfined, file)
	}

	return target, nil
}

// refPointer splits a JSON pointer of the form /parameters/<name> or /definitions/<name> and unescapes the name as
// RFC 6901 defines (~1 is '/', ~0 is '~').
func refPointer(pointer string) (string, string, error) {
	parts := strings.Split(pointer, "/")
	if len(parts) != 3 || parts[0] != "" || parts[2] == "" ||
		(parts[1] != refTableParameters && parts[1] != refTableDefinitions) {
		return "", "", fmt.Errorf("%w: pointer %q", errRefKind, pointer)
	}

	return parts[1], strings.NewReplacer("~1", "/", "~0", "~").Replace(parts[2]), nil
}
