package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/cynative/cynative/internal/apiref"
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
			Reason:  "protocol " + ProtocolName(m.Protocol()) + " is not supported by api_reference",
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
				Reason:  fmt.Sprintf("no AWS model answers on endpoint prefix %q", q.Service),
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
			Reason:  fmt.Sprintf("model %q does not serve %q", q.Model, q.Service),
			Choices: choices(dirs),
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
			Reason:  fmt.Sprintf("no operation %q in %s", q.Operation, strings.Join(dirs, ", ")),
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
			Reason:  `pass "model" to choose`,
			Choices: choices(dirs),
		}
	}
	return apiref.Result{
		Outcome: apiref.OutcomeAmbiguous,
		Reason:  "several operations differ only by case",
		Choices: choices(names),
	}
}

// choices sorts, truncates and bounds a choice list.
func choices(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	if len(out) > apiref.MaxChoices {
		out = out[:apiref.MaxChoices]
	}
	for i, c := range out {
		out[i] = apiref.Truncate(c, apiref.MaxChoice)
	}
	return out
}
