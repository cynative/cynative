package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// ModelSource is the archive surface documentation reads.
type ModelSource interface {
	Resolve(ctx context.Context, prefix string) ([]*ServiceModel, error)
	RawModel(ctx context.Context, dir string) ([]byte, string, error)
}

// docEntry is a parsed documentation model and the digest of the bytes it came from.
type docEntry struct {
	model *DocModel
	sha   string
}

// docHit is one operation a query matched.
type docHit struct {
	dir   string
	name  string
	entry *docEntry
}

// Documenter answers api_reference lookups from the Smithy model archive.
type Documenter struct {
	src  ModelSource
	memo sync.Map // dir -> *docEntry.
}

// NewDocumenter returns a Documenter reading models from src.
func NewDocumenter(src ModelSource) *Documenter { return &Documenter{src: src} }

// Reference looks up the operation q names.
func (d *Documenter) Reference(ctx context.Context, q apiref.Query) apiref.Result {
	models, res, ok := d.resolveModels(ctx, q)
	if !ok {
		return res
	}
	entries := make([]*docEntry, len(models))
	for i, sm := range models {
		e, err := d.docModel(ctx, sm.Dir)
		if err != nil {
			return unavailable(err)
		}
		entries[i] = e
	}
	hit, res, ok := findOperation(q, models, entries)
	if !ok {
		return res
	}
	m := hit.entry.model
	if !DocSupported(m.Protocol()) {
		return apiref.Result{
			Outcome: apiref.OutcomeUnsupported,
			Reason: apiref.Truncate(
				"protocol "+ProtocolName(m.Protocol())+" is not supported by api_reference", apiref.MaxReason),
		}
	}
	ref := m.Reference(q.Service, hit.dir, hit.name)
	ref.Source.SHA256 = hit.entry.sha
	ref.Source.Document = "models/" + hit.dir + "/service/" + ref.APIVersion
	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

func unavailable(err error) apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: apiref.Truncate(err.Error(), apiref.MaxReason)}
}

// resolveModels returns the models serving q.Service, narrowed by q.Model. ok is false when res already answers.
func (d *Documenter) resolveModels(ctx context.Context, q apiref.Query) ([]*ServiceModel, apiref.Result, bool) {
	models, err := d.src.Resolve(ctx, q.Service)
	if err != nil {
		if errors.Is(err, ErrUnsupportedService) {
			return nil, apiref.Result{
				Outcome: apiref.OutcomeNotFound,
				Reason: apiref.Truncate(
					fmt.Sprintf("no AWS model answers on endpoint prefix %q", q.Service), apiref.MaxReason),
			}, false
		}
		return nil, unavailable(err), false
	}
	if q.Model == "" {
		return models, apiref.Result{}, true
	}
	var kept []*ServiceModel
	for _, sm := range models {
		if sm.Dir == q.Model {
			kept = append(kept, sm)
		}
	}
	if len(kept) == 0 {
		dirs := make([]string, len(models))
		for i, sm := range models {
			dirs[i] = sm.Dir
		}
		return nil, apiref.Result{
			Outcome: apiref.OutcomeNotFound,
			Reason: apiref.Truncate(
				fmt.Sprintf("model %q does not serve %q", q.Model, q.Service), apiref.MaxReason),
			Choices: apiref.Choices(dirs),
		}, false
	}
	return kept, apiref.Result{}, true
}

// docModel loads and memoizes the documentation model of dir. Failures are not memoized.
func (d *Documenter) docModel(ctx context.Context, dir string) (*docEntry, error) {
	if v, ok := d.memo.Load(dir); ok {
		entry, _ := v.(*docEntry) // only *docEntry values are stored.
		return entry, nil
	}
	raw, sha, err := d.src.RawModel(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("model %s: %w", dir, err)
	}
	m, err := ParseDocModel(raw)
	if err != nil {
		return nil, fmt.Errorf("model %s: %w", dir, err)
	}
	v, _ := d.memo.LoadOrStore(dir, &docEntry{model: m, sha: sha})
	entry, _ := v.(*docEntry) // only *docEntry values are stored.
	return entry, nil
}

// findOperation picks the one operation q names: an exact name first, otherwise a case-insensitive match.
func findOperation(q apiref.Query, models []*ServiceModel, entries []*docEntry) (docHit, apiref.Result, bool) {
	var exact, folded []docHit
	for i, e := range entries {
		dir := models[i].Dir
		if e.model.HasOperation(q.Operation) {
			exact = append(exact, docHit{dir, q.Operation, e})
		}
		for _, n := range e.model.OperationNames() {
			if n != q.Operation && strings.EqualFold(n, q.Operation) {
				folded = append(folded, docHit{dir, n, e})
			}
		}
	}
	hits := exact
	if len(hits) == 0 {
		hits = folded
	}
	switch len(hits) {
	case 0:
		dirs := make([]string, len(models))
		for i, sm := range models {
			dirs[i] = sm.Dir
		}
		return docHit{}, apiref.Result{
			Outcome: apiref.OutcomeNotFound,
			Reason: apiref.Truncate(
				fmt.Sprintf("no operation %q in %s", q.Operation, strings.Join(dirs, ", ")), apiref.MaxReason),
		}, false
	case 1:
		return hits[0], apiref.Result{}, true
	}
	return docHit{}, ambiguous(hits), false
}

func ambiguous(hits []docHit) apiref.Result {
	dirs := make([]string, 0, len(hits))
	names := make([]string, 0, len(hits))
	for _, h := range hits {
		if !slices.Contains(dirs, h.dir) {
			dirs = append(dirs, h.dir)
		}
		names = append(names, h.name)
	}
	if len(dirs) > 1 {
		return apiref.Result{
			Outcome: apiref.OutcomeAmbiguous,
			Reason:  apiref.Truncate(`pass "model" to choose`, apiref.MaxReason),
			Choices: apiref.Choices(dirs),
		}
	}
	return apiref.Result{
		Outcome: apiref.OutcomeAmbiguous,
		Reason:  apiref.Truncate("several operations differ only by case", apiref.MaxReason),
		Choices: apiref.Choices(names),
	}
}

// Hint suggests a fix for a request the gate matched to no operation of service. It reads only the
// models the gate just resolved.
func (d *Documenter) Hint(ctx context.Context, v authreq.View, service string) apiref.Hint {
	models, err := d.src.Resolve(ctx, service)
	if err != nil {
		return apiref.Hint{}
	}
	if name, viaTarget := requestedName(v); name != "" {
		lines := d.protocolCandidates(ctx, models, service, name, viaTarget)
		if lines = apiref.Bound(lines); lines != nil {
			h := apiref.Hint{Candidates: lines}
			if len(lines) == 1 {
				h.Operation = name
			}
			return h
		}
	}
	var routes []apiref.Route
	for _, sm := range models {
		if sm.Protocol != ProtocolRestXML && sm.Protocol != ProtocolRestJSON1 {
			continue
		}
		for name, op := range sm.Operations {
			routes = append(routes, apiref.Route{Operation: name, Method: op.HTTPMethod, Template: op.URITemplate})
		}
	}
	h := apiref.Hint{Candidates: apiref.Candidates(routes, v.Method, v.EscapedPath)}
	if ops := apiref.CandidateOperations(routes, v.Method, v.EscapedPath); len(ops) == 1 {
		h.Operation = ops[0]
	}
	return h
}

// requestedName returns the operation name a request carries: the X-Amz-Target suffix, else the Action
// parameter of the query or form body.
func requestedName(v authreq.View) (string, bool) {
	if target := v.Header.Get("X-Amz-Target"); target != "" {
		return target[strings.LastIndex(target, ".")+1:], true
	}
	if q, err := url.ParseQuery(v.RawQuery); err == nil && q.Get("Action") != "" {
		return q.Get("Action"), false
	}
	if f, err := url.ParseQuery(v.Body); err == nil {
		return f.Get("Action"), false
	}
	return "", false
}

// protocolCandidates lists, for each model that defines name under a protocol the request did not speak, how
// the operation is actually called.
func (d *Documenter) protocolCandidates(
	ctx context.Context, models []*ServiceModel, service, name string, viaTarget bool,
) []string {
	var lines []string
	for _, sm := range models {
		if _, ok := sm.Operations[name]; !ok || !DocSupported(sm.Protocol) {
			continue
		}
		spoke := sm.Protocol == ProtocolAWSQuery
		if viaTarget {
			spoke = sm.Protocol == ProtocolAWSJSON10 || sm.Protocol == ProtocolAWSJSON11
		}
		if spoke {
			continue
		}
		e, err := d.docModel(ctx, sm.Dir)
		if err != nil {
			continue
		}
		lines = append(lines, service+" uses "+e.model.Reference(service, sm.Dir, name).Shape())
	}
	return lines
}
