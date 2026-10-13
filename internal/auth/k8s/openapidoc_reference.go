package k8s

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

const (
	// MaxTextBytes is where a cluster description is cut before its markup is stripped.
	MaxTextBytes = 8 << 10
	// maxRequestTypes bounds the request media types a reference lists.
	maxRequestTypes = 6
	// maxMediaPart bounds the type and the subtype of a media type.
	maxMediaPart = 64
	// minChoicePrefix is the shortest case-folded prefix a not_found choice must share with the requested id.
	minChoicePrefix = 4
	// maxKindBytes bounds a kind or a response schema name.
	maxKindBytes = 63
	// protocol is the reference's protocol and connector name.
	protocol = "kubernetes"
	// jsonMedia is the media type the API server's JSON serializer reads and writes.
	jsonMedia = "application/json"
	// anyMedia is the media type a built-in operation declares for its body or a connect operation for its
	// response.
	anyMedia = "*/*"
	// schemaRefPrefix introduces a component schema reference.
	schemaRefPrefix = "#/components/schemas/"
)

// Reference text. Every string here is fixed host text; the only variable parts are validated cluster values.
const (
	limitServedNow = "read from this cluster's /openapi/v3 document as served now; an aggregated API server can " +
		"claim a group-version another server also serves"
	limitPermission = "a description, not a permission: the gate allows only what the configured ClusterRole %q " +
		"permits"
	limitPaging = "pass limit; while metadata.continue in the response is non-empty, repeat the request with " +
		"continue set to it and the other parameters unchanged; an expired token answers 410 Gone and the list " +
		"restarts"
	limitWatch = "with watch=true the response is a stream of watch events, one JSON object per line (leave " +
		"pretty unset), which the server ends after timeoutSeconds; keep timeoutSeconds below http_request's " +
		"timeout_seconds, and add fieldSelector=metadata.name=<name> to watch one object"
	limitDeprecatedWatch = "deprecated path; use the list operation with watch=true"
	limitProxy           = "the response is whatever the proxied pod, service or node returns"
	limitLog             = "leave follow unset and use tailLines or limitBytes; a followed log ends only when the " +
		"container stops or the request times out"
	limitContentType = "send Content-Type as one of: "
	gapConnect       = "%s needs a WebSocket or SPDY upgrade, which http_request does not perform"
	gapWholeBody     = "request body is a whole %s object, which the template does not render"
	gapPatchBody     = "request body is a patch of %s, which the template does not render"
	defaultKind      = "Kubernetes object"
	podLogPath       = "/api/v1/namespaces/{namespace}/pods/{name}/log"
)

var (
	// kindPattern is the grammar for a kind or a response schema name.
	kindPattern = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	// mediaPartPattern is the grammar for a media type's type or subtype.
	mediaPartPattern = regexp.MustCompile(`^[A-Za-z0-9!#$&^_.+-]+$`)
)

// opRules are the per-operation rules a reference gets on top of what the core builds.
type opRules struct {
	Limitations []string
	Response    *apiref.Response
}

// Document is a distilled group-version document: the pre-pass index and the admitted operations after
// distillation and post-processing. It is what the cache stores, and it is never changed after it is built.
type Document struct {
	APIVersion APIVersion
	Index      map[string]IndexEntry
	Excluded   int
	Docs       *openapidoc.OperationDocs
	Rules      map[string]opRules
}

// ParseDocument runs the streaming pass, the pre-pass and the core over a group-version document read from the
// cluster, then applies the Kubernetes rules to each admitted operation. Every error is fixed host text: the
// decoder's message never leaves this function.
func ParseDocument(ctx context.Context, body []byte, v APIVersion) (*Document, error) {
	if _, err := Scan(ctx, body, MaxDocumentElements); err != nil {
		return nil, err
	}
	prep, err := Prepare(ctx, body, v.Key)
	if err != nil {
		return nil, err
	}
	if len(prep.Extras) == 0 {
		// Every indexed id is duplicate or unrenderable: those answer ambiguous or unsupported from the index, and
		// the core, which rejects an empty result, is not run.
		return &Document{
			APIVersion: v, Index: prep.Index, Excluded: prep.Excluded,
			Docs: &openapidoc.OperationDocs{Ops: map[string]openapidoc.OperationDoc{}}, Rules: map[string]opRules{},
		}, nil
	}
	docs, err := openapidoc.DistillContext(ctx, body, distillProfile(prep))
	if err != nil {
		// A done context also ends the core early; the caller's own context check reports that case.
		return nil, ErrShape
	}
	d := &Document{APIVersion: v, Index: prep.Index, Excluded: prep.Excluded, Docs: docs, Rules: map[string]opRules{}}
	for id, op := range docs.Ops {
		d.Rules[id] = postProcess(v, &op, prep.Extras[id])
		docs.Ops[id] = op
	}

	return d, nil
}

// distillProfile is the core profile for a cluster document: only the operations the pre-pass admitted, no body
// schema decoded, descriptions cut before their markup is stripped, and the document's servers ignored.
func distillProfile(prep *Prepared) openapidoc.Profile {
	return openapidoc.Profile{
		Connector:    protocol,
		Protocol:     protocol,
		Paged:        continuePaged,
		Keep:         prep.Admitted,
		SkipBodies:   true,
		MaxTextBytes: MaxTextBytes,
	}
}

// continuePaged reports an operation that takes both the limit and the continue query parameters.
func continuePaged(params []openapidoc.DocParam, _ []string) bool {
	return hasQuery(params, "limit") && hasQuery(params, "continue")
}

func hasQuery(params []openapidoc.DocParam, name string) bool {
	return slices.ContainsFunc(params, func(p openapidoc.DocParam) bool { return p.In == inQuery && p.Name == name })
}

// postProcess applies the Kubernetes rules to one distilled operation and returns the rules its reference gets.
func postProcess(v APIVersion, op *openapidoc.OperationDoc, x Extras) opRules {
	var r opRules
	op.Summary = apiref.StripMarkupCut(x.Description, MaxTextBytes, apiref.MaxSummary)
	for i := range op.Params {
		if op.Params[i].In == inPath {
			op.Params[i].Required, op.Params[i].Type = true, "string"
		}
	}
	kind := defaultKind
	if validKind(x.Kind) {
		kind = x.Kind
	}
	if op.BodySkipped &&
		(op.Method == http.MethodPost || op.Method == http.MethodPut || op.Method == http.MethodPatch) {
		// Not every cluster marks a create, replace or patch body required (the v1.23 document marks none), but the
		// API server rejects the call without one. Any other method's optional body stays optional.
		op.BodySkipped, op.BodyGap = false, gapWholeBody
	}
	if op.BodyGap != "" {
		op.BodyGap = fmt.Sprintf(gapWholeBody, kind)
		if op.Method == http.MethodPatch {
			op.BodyGap = fmt.Sprintf(gapPatchBody, kind)
		}
	}
	if types := requestTypes(x.RequestTypes); len(types) > 0 {
		r.Limitations = append(r.Limitations, limitContentType+strings.Join(types, ", "))
	}
	segs := strings.Split(strings.TrimPrefix(op.Path, "/"+v.Key), "/")
	r.Response = responseRule(op, x)
	switch {
	case v.Key == "api/v1" && op.Method == http.MethodGet && op.Path == podLogPath:
		r.Response = &apiref.Response{Encoding: "text/plain", Parse: "the body is the log text, not JSON"}
		r.Limitations = append(r.Limitations, limitLog)
	case len(segs) > 1 && segs[1] == "watch":
		r.Response = &apiref.Response{
			Encoding: "json-stream", Parse: "split response.body on newlines and JSON.parse each non-empty line",
		}
		op.Paged = false
		r.Limitations = append(r.Limitations, limitDeprecatedWatch)
	case hasQuery(op.Params, "watch"):
		r.Limitations = append(r.Limitations, limitWatch)
	}
	if sub := segs[len(segs)-1]; sub == "exec" || sub == "attach" || sub == "portforward" {
		op.Gaps = append(op.Gaps, fmt.Sprintf(gapConnect, sub))
	}
	if i := slices.Index(segs, "proxy"); i >= 0 {
		r.Limitations = append(r.Limitations, limitProxy)
		if i+1 < len(segs) && segs[i+1] == "{path}" {
			op.Path = strings.Replace(op.Path, "/proxy/{path}", "/proxy/{path+}", 1)
		}
	}

	return r
}

// responseRule names the object a JSON response holds, and reads a */* response as raw. Nil keeps the core's.
func responseRule(op *openapidoc.OperationDoc, x Extras) *apiref.Response {
	switch op.ResponseType {
	case anyMedia:
		return &apiref.Response{Encoding: "raw", Parse: "read Content-Type before parsing response.body"}
	case jsonMedia:
		name, ok := strings.CutPrefix(x.ResponseRef, schemaRefPrefix)
		if name = name[strings.LastIndexByte(name, '.')+1:]; ok && validKind(name) {
			return &apiref.Response{Encoding: "json", Parse: "JSON.parse(response.body) is a " + name}
		}
	}

	return nil
}

func validKind(s string) bool {
	return len(s) <= maxKindBytes && kindPattern.MatchString(s)
}

// requestTypes validates the request media types, shows */* as application/json, and keeps the six that sort first,
// sorted and without repeats. The list never holds more than seven, so a document listing many thousands of types
// costs one binary search each.
func requestTypes(types []string) []string {
	var out []string
	for _, mt := range types {
		if mt == anyMedia {
			mt = jsonMedia
		} else if !validMedia(mt) {
			continue
		}
		i, seen := slices.BinarySearch(out, mt)
		if seen || i == maxRequestTypes {
			continue
		}
		if out == nil {
			out = make([]string, 0, maxRequestTypes+1)
		}
		out = slices.Insert(out, i, mt)[:min(len(out)+1, maxRequestTypes)]
	}

	return out
}

func validMedia(mt string) bool {
	typ, sub, ok := strings.Cut(mt, "/")

	return ok && validMediaPart(typ) && validMediaPart(sub)
}

func validMediaPart(s string) bool {
	return len(s) <= maxMediaPart && mediaPartPattern.MatchString(s)
}

// Lookup is one lookup in a distilled document: the requested id and what the reference names.
type Lookup struct {
	Operation   string
	Endpoint    string
	ClusterRole string
	Source      apiref.Source
}

// Lookup answers a lookup by operation id over the whole index, so an id the tool cannot describe neither
// vanishes nor loses an ambiguity to an admitted id that differs only by case.
func (d *Document) Lookup(q Lookup) apiref.Result {
	id := q.Operation
	if _, ok := d.Index[id]; !ok {
		var folded []string
		for other := range d.Index {
			if strings.EqualFold(other, id) {
				folded = append(folded, other)
			}
		}
		slices.Sort(folded)
		switch len(folded) {
		case 0:
			return d.notFound(id)
		case 1:
			id = folded[0]
		default:
			return apiref.Result{
				Outcome: apiref.OutcomeAmbiguous, Reason: "several operations differ only by case", Choices: folded,
			}
		}
	}
	e := d.Index[id]
	switch e.Class {
	case ClassAdmitted:
	case ClassDuplicate:
		// The routes are sorted, so the first valid ones are the choices; later ones are never built.
		var choices []string
		for _, r := range e.Routes {
			if len(choices) == apiref.MaxChoices {
				break
			}
			if r.PathOK {
				choices = append(choices, r.Method+" "+r.Path)
			}
		}
		return apiref.Result{
			Outcome: apiref.OutcomeAmbiguous,
			Reason: fmt.Sprintf("the cluster's document lists operation %q more than once; this tool does not "+
				"pick one", id),
			Choices: choices,
		}
	case ClassUnrenderable:
		return apiref.Result{
			Outcome: apiref.OutcomeUnsupported,
			Reason:  fmt.Sprintf("operation %q cannot be described: %s", id, e.Reason),
		}
	}

	return d.reference(id, q)
}

// notFound answers an id no indexed id matches, with up to five admitted ids sharing its longest case-folded prefix.
func (d *Document) notFound(id string) apiref.Result {
	guidance := "; operation ids look like listAppsV1NamespacedDeployment"
	if d.Excluded > 0 {
		guidance += fmt.Sprintf("; the document also lists %d operations this tool cannot look up", d.Excluded)
	}
	reason := apiref.Bounded(fmt.Sprintf("no operation %q in %s as this cluster serves it", id, d.APIVersion.Model()),
		guidance)
	best, choices := minChoicePrefix, []string(nil)
	for other, e := range d.Index {
		if e.Class != ClassAdmitted {
			continue
		}
		switch n := foldedPrefix(other, id); {
		case n > best:
			best, choices = n, []string{other}
		case n == best:
			choices = append(choices, other)
		}
	}
	slices.Sort(choices)

	return apiref.Result{
		Outcome: apiref.OutcomeNotFound, Reason: reason, Choices: choices[:min(len(choices), apiref.MaxChoices)],
	}
}

// foldedPrefix is the length of the longest common prefix of a and b under ASCII case folding.
func foldedPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && strings.EqualFold(a[n:n+1], b[n:n+1]) {
		n++
	}

	return n
}

// reference builds an admitted operation's reference through the core, by its exact id, then applies its rules.
func (d *Document) reference(id string, q Lookup) apiref.Result {
	prof := openapidoc.Profile{
		Connector: protocol,
		Protocol:  protocol,
		Endpoint:  q.Endpoint,
		//nolint:gosec // G101 reads the token fields as credentials; they name pagination members.
		Paging: apiref.Pagination{
			Style: "continue-token", InputToken: "continue", OutputToken: "metadata.continue", Items: "items",
			PageSize: "limit",
		},
		PagingLimit: limitPaging,
		Limitations: []string{limitServedNow, fmt.Sprintf(limitPermission, q.ClusterRole)},
	}
	res := d.Docs.Reference(apiref.Query{Operation: id}, prof)
	ref := res.Reference
	ref.Model, ref.APIVersion, ref.Source = d.APIVersion.Model(), d.APIVersion.Model(), q.Source
	rules := d.Rules[id]
	ref.Limitations = append(ref.Limitations, rules.Limitations...)
	if rules.Response != nil {
		ref.Response = *rules.Response
	}

	return res
}

// sizeOverhead is what a cache entry's size counts for each operation, parameter, index entry and rule set, on
// top of the byte length of its strings.
const sizeOverhead = 96

// Size is the byte length of every string the document holds, counted at each occurrence, plus sizeOverhead for
// each operation, parameter, index entry and rule set. The walk stops once it passes limit, so measuring an entry
// costs no allocation and no serialization.
func (d *Document) Size(limit int) int {
	n := len(d.APIVersion.Group) + len(d.APIVersion.Version) + len(d.APIVersion.Key) + len(d.Docs.Version) +
		len(d.Docs.SHA256)
	for id, e := range d.Index {
		n += len(id) + len(e.Reason) + sizeOverhead
		for _, r := range e.Routes {
			n += len(r.Method) + len(r.Path)
		}
		if n > limit {
			return n
		}
	}
	for id, op := range d.Docs.Ops {
		n += len(id) + opSize(&op) + sizeOverhead
		if n > limit {
			return n
		}
	}
	for id, r := range d.Rules {
		n += len(id) + sizeOverhead
		for _, l := range r.Limitations {
			n += len(l)
		}
		if r.Response != nil {
			n += len(r.Response.Encoding) + len(r.Response.Parse)
		}
	}

	return n
}

func opSize(op *openapidoc.OperationDoc) int {
	n := len(op.Method) + len(op.Path) + len(op.Summary) + len(op.BodyGap) + len(op.ResponseType)
	for _, p := range op.Params {
		n += len(p.Name) + len(p.In) + len(p.Type) + len(p.Description) + sizeOverhead
	}
	for _, g := range op.Gaps {
		n += len(g)
	}

	return n
}
