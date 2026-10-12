package azure

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cynative/cynative/internal/apiref"
)

// The lookup's bounds.
const (
	lookupDeadline     = 120 * time.Second
	lookupBudget       = 160 << 20
	maxLookupDownloads = 8
	// maxNearestEcho bounds each nearest operation id a reason lists, quoted. A longer id is left out before any
	// scoring, never cut, since a cut id is not an operation the caller can retry with.
	maxNearestEcho = 100
	// maxNearest bounds how many nearest operation ids a reason lists.
	maxNearest = 5
	// maxGroupEcho bounds how many searched group ids a not_found reason names before "and N more".
	maxGroupEcho = 5
	// selectorMinParts and selectorMaxParts bound "<kind>/<dir>" and "<kind>/<dir>/<file>" after the '@'.
	selectorMinParts = 2
	selectorMaxParts = 3
)

// matchMode is how a search compares operation ids: exactly, then, only when nothing anywhere matched exactly,
// case-insensitively.
type matchMode int

const (
	matchExact matchMode = iota
	matchFolded
)

// The lookup's reasons and guidance.
const (
	namespaceFormat  = "a namespace looks like Microsoft.Compute"
	modelGuidance    = "; pass an api-version dir name such as 2024-07-01, or a choice from an ambiguous result"
	operationFormat  = "; names are Swagger operationIds such as VirtualMachines_List"
	operationGrammar = "; an operationId is letters, digits, '_', '.' and '-', at most 200, such as " +
		"VirtualMachines_List"
	olderGuidance = "; model can name an api-version dir outside the default search"
	// gateNotLoaded says the lookup could not compare the template with the gate's catalog.
	gateNotLoaded = "gate recognition not checked: the azure gate's catalog is not loaded yet"
)

// specSource is the store a lookup reads.
type specSource interface {
	Index(ctx context.Context) (*Index, error)
	File(ctx context.Context, sha string, f IndexFile) ([]byte, error)
	Summary(ctx context.Context, sha string, f IndexFile, b *Budget) (*FileSummary, error)
}

// Docs answers api_reference lookups for azure from the specs store. It never sends a credential and never loads the
// gate's catalog: gate returns only a snapshot the gate already loaded.
type Docs struct {
	store    specSource
	endpoint string
	gate     func() Catalog
	budget   int64
}

// NewDocs builds the lookup. endpoint is the session cloud's ARM endpoint; gate returns the gate's loaded catalog
// snapshot, or nil.
func NewDocs(store specSource, endpoint string, gate func() Catalog) *Docs {
	return &Docs{store: store, endpoint: endpoint, gate: gate, budget: lookupBudget}
}

// Reference answers one lookup.
func (d *Docs) Reference(ctx context.Context, q apiref.Query) apiref.Result {
	m, res := parseQuery(q)
	if res != nil {
		return *res
	}
	ctx, cancel := context.WithTimeout(ctx, lookupDeadline)
	defer cancel()
	ix, err := d.store.Index(ctx)
	if err != nil {
		// The store's error can carry another caller's cause, so only this lookup's own context says it stopped.
		if ctx.Err() != nil {
			return unavailable(ContextReason(ctx))
		}

		return unavailable("the Azure REST API specs index could not be loaded: " + err.Error())
	}
	ns, ok := ix.Namespaces[strings.ToLower(q.Service)]
	if !ok {
		return notFound(apiref.Bounded("the Azure REST API specs list no namespace "+echo(q.Service),
			"; "+namespaceFormat))
	}

	s := newSearch(d, ix, ns, q)
	out := s.run(ctx, m)
	// Every outcome passes here. A context that ends during the last read or the render meets no later check, so a
	// lookup that ended answers as stopped, whatever the search had reached.
	if ctx.Err() != nil {
		return s.failure(ctx, ctx.Err())
	}

	return out
}

// ContextReason is the unavailable reason for a lookup whose context is done. Its text is auth.ContextReason's,
// which this package cannot import; a test in internal/auth pins the two equal.
func ContextReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "the lookup timed out after 120s"
	}

	return "the lookup was interrupted"
}

// finish is the one exit of every rendered reference: it runs the gate check and answers it. OutcomeOf runs after
// the check, so a gate gap makes the result incomplete.
func (d *Docs) finish(ctx context.Context, ref *apiref.Reference) apiref.Result {
	applyGateCheck(ctx, d.gate, ref)

	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

// lookupModel is what model names: nothing, a bare version dir name, or a selector.
type lookupModel struct {
	version string
	sel     *selector
}

// selector names a version dir of a group, and optionally one file in it.
type selector struct {
	group, kind, dir, file string
}

func (s selector) String() string {
	out := s.group + "@" + s.kind + "/" + s.dir
	if s.file != "" {
		out += "/" + s.file
	}

	return out
}

// parseQuery checks service, operation and model against their grammars before any I/O.
func parseQuery(q apiref.Query) (lookupModel, *apiref.Result) {
	switch {
	case q.Service == "":
		res := notFound("service is required for an azure lookup: the resource-provider namespace azure_auth.service " +
			"takes; " + namespaceFormat)

		return lookupModel{}, &res
	case !validNamespace(q.Service):
		res := notFound(apiref.Bounded("service "+echo(q.Service)+" is not a resource-provider namespace",
			"; "+namespaceFormat))

		return lookupModel{}, &res
	case !validOperation(q.Operation):
		res := notFound(apiref.Bounded("operation "+echo(q.Operation)+" is not a Swagger operationId",
			operationGrammar))

		return lookupModel{}, &res
	case q.Model == "":
		return lookupModel{}, nil
	case validVersion(q.Model):
		return lookupModel{version: q.Model}, nil
	}
	if sel, ok := parseSelector(q.Model); ok {
		return lookupModel{sel: &sel}, nil
	}
	res := notFound(apiref.Bounded("model "+echo(q.Model)+" is not an api-version dir name or a selector",
		modelGuidance))

	return lookupModel{}, &res
}

// parseSelector reads <group>@<kind>/<dir>[/<file>].
func parseSelector(s string) (selector, bool) {
	group, rest, ok := strings.Cut(s, "@")
	parts := strings.Split(rest, "/")
	if !ok || !validGroupID(group) || len(parts) < selectorMinParts || len(parts) > selectorMaxParts ||
		(parts[0] != kindStable && parts[0] != kindPreview) || !validVersion(parts[1]) {
		return selector{}, false
	}
	sel := selector{group: group, kind: parts[0], dir: parts[1]}
	if len(parts) == selectorMaxParts {
		if !validFileName(parts[2]) {
			return selector{}, false
		}
		sel.file = parts[2]
	}

	return sel, true
}

// echo quotes model text, then bounds it, so guidance appended after it survives.
func echo(s string) string { return apiref.Truncate(strconv.Quote(s), apiref.MaxChoice) }

func notFound(reason string) apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeNotFound, Reason: reason}
}

func unavailable(reason string) apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: apiref.Truncate(reason, apiref.MaxReason)}
}

// match is one operation a search found. pinned says model named its file, so its selector keeps the file.
type match struct {
	group  string
	dir    IndexDir
	file   IndexFile
	op     OpSummary
	pinned bool
}

// rendered is a match with its reference.
type rendered struct {
	m   match
	ref *apiref.Reference
}

// groupDir is one dir a search reads, restricted to one file when file is set.
type groupDir struct {
	group string
	dir   IndexDir
	file  string
}

// search is one lookup's walk over a namespace.
type search struct {
	d        *Docs
	ix       *Index
	ns       *IndexNamespace
	q        apiref.Query
	budget   *Budget
	groups   []string
	mode     matchMode
	found    []match
	searched []string
	ids      map[string]bool
	scanned  map[string]bool
}

func newSearch(d *Docs, ix *Index, ns *IndexNamespace, q apiref.Query) *search {
	return &search{
		d: d, ix: ix, ns: ns, q: q, budget: NewBudget(d.budget),
		groups: slices.Sorted(maps.Keys(ns.Groups)), ids: map[string]bool{}, scanned: map[string]bool{},
	}
}

func (s *search) run(ctx context.Context, m lookupModel) apiref.Result {
	if m.sel == nil && m.version == "" {
		return s.passes(ctx)
	}
	dirs := s.modelDirs(m)
	if len(dirs) == 0 {
		return s.noSuchModel(m)
	}
	for _, mode := range []matchMode{matchExact, matchFolded} {
		s.mode = mode
		for _, gd := range dirs {
			if _, err := s.scanDir(ctx, gd); err != nil {
				return s.failure(ctx, err)
			}
		}
		if len(s.found) > 0 {
			break
		}
	}

	return s.conclude(ctx, false, false)
}

// passes runs the three passes of a lookup without model: each group's newest stable dir; then each group's older
// stable dirs, stopping a group at its first dir that defines the operation; then the preview dirs the same way.
// The whole search runs matching ids exactly first, and only when it finds nothing runs again case-insensitively,
// so a case variant in a newer dir never hides the exact id in an older one.
func (s *search) passes(ctx context.Context) apiref.Result {
	steps := []struct {
		kind        string
		first, last int
	}{{kindStable, 0, 0}, {kindStable, 1, math.MaxInt}, {kindPreview, 0, math.MaxInt}}
	for _, mode := range []matchMode{matchExact, matchFolded} {
		s.mode = mode
		for i, st := range steps {
			if err := s.walk(ctx, st.kind, st.first, st.last); err != nil {
				return s.failure(ctx, err)
			}
			if len(s.found) > 0 {
				return s.conclude(ctx, i == len(steps)-1, true)
			}
		}
	}

	return s.notFound(true)
}

// walk reads, in each group, the dirs of kind whose position among that kind is between first and last, newest
// first, and stops the group at the first dir with a match.
func (s *search) walk(ctx context.Context, kind string, first, last int) error {
	for _, g := range s.groups {
		at := -1
		for _, dir := range s.ns.Groups[g].Dirs {
			if dir.Kind != kind {
				continue
			}
			at++
			if at < first || at > last {
				continue
			}
			hit, err := s.scanDir(ctx, groupDir{group: g, dir: dir})
			if err != nil {
				return err
			}
			if hit {
				break
			}
		}
	}

	return nil
}

// modelDirs lists the dirs a model names, groups in order, stable before preview within a group.
func (s *search) modelDirs(m lookupModel) []groupDir {
	var out []groupDir
	for _, g := range s.groups {
		for _, dir := range s.ns.Groups[g].Dirs {
			switch {
			case m.sel != nil && g == m.sel.group && dir.Kind == m.sel.kind && dir.Name == m.sel.dir &&
				(m.sel.file == "" || slices.ContainsFunc(dir.Files, func(f IndexFile) bool {
					return path.Base(f.Path) == m.sel.file
				})):
				out = append(out, groupDir{group: g, dir: dir, file: m.sel.file})
			case m.sel == nil && dir.Name == m.version:
				out = append(out, groupDir{group: g, dir: dir})
			}
		}
	}

	return out
}

// scanDir reads the summaries of one dir, at most maxLookupDownloads at a time, and records the matches under the
// search's mode. It reports whether the dir defined the operation. It checks the context first, since a warm store
// answers from disk without looking at it.
func (s *search) scanDir(ctx context.Context, gd groupDir) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	files := gd.dir.Files
	if gd.file != "" {
		files = slices.DeleteFunc(slices.Clone(files), func(f IndexFile) bool { return path.Base(f.Path) != gd.file })
	}
	sums, err := s.summaries(ctx, files)
	if err != nil {
		return false, err
	}
	if s.mode == matchExact {
		s.searched = append(s.searched, selector{group: gd.group, kind: gd.dir.Kind, dir: gd.dir.Name}.String())
		s.scanned[gd.group] = true
	}
	hit := false
	for i, sum := range sums {
		for _, op := range sum.Ops {
			s.ids[op.ID] = true
			if s.matches(op.ID) {
				m := match{group: gd.group, dir: gd.dir, file: files[i], op: op, pinned: gd.file != ""}
				s.found, hit = append(s.found, m), true
			}
		}
	}

	return hit, nil
}

// matches compares an id with the lookup's operation under the search's mode.
func (s *search) matches(id string) bool {
	if s.mode == matchExact {
		return id == s.q.Operation
	}

	return strings.EqualFold(id, s.q.Operation)
}

// summaries reads the files' summaries concurrently and reports the first error by file position, so the answer
// does not depend on which download finished first.
func (s *search) summaries(ctx context.Context, files []IndexFile) ([]*FileSummary, error) {
	out := make([]*FileSummary, len(files))
	errs := make([]error, len(files))
	var g errgroup.Group
	g.SetLimit(maxLookupDownloads)
	for i, f := range files {
		g.Go(func() error {
			out[i], errs[i] = s.d.store.Summary(ctx, s.ix.SHA, f, s.budget)

			return nil
		})
	}
	_ = g.Wait() // Every function returns nil: errors are kept per file and reported in file order below.
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// conclude turns the matches into an answer. previewOnly says no stable dir defined the operation; fromPasses says
// the lookup had no model.
func (s *search) conclude(ctx context.Context, previewOnly, fromPasses bool) apiref.Result {
	cands := s.found
	if len(cands) == 0 {
		return s.notFound(fromPasses)
	}
	// Only a case-insensitive search can find several distinct ids.
	if ids := distinctIDs(cands); len(ids) > 1 {
		return apiref.Result{
			Outcome: apiref.OutcomeAmbiguous,
			Reason:  apiref.Bounded("several operation ids differ only by case from "+echo(s.q.Operation), ""),
			Choices: apiref.Choices(ids),
		}
	}
	if previewOnly {
		return s.choose(cands, apiref.Bounded("no stable version in the specs defines "+echo(s.q.Operation),
			"; pass model with a preview choice to read it"))
	}
	rs, err := s.renderAll(ctx, cands)
	if err != nil {
		return s.failure(ctx, err)
	}
	rs = merge(rs)
	if len(rs) > 1 {
		return s.ambiguous(rs)
	}
	return s.d.finish(ctx, rs[0].ref)
}

// renderAll renders every candidate, reading and charging each file once.
func (s *search) renderAll(ctx context.Context, cands []match) ([]rendered, error) {
	res := newRefResolver(s.d.store, s.ix, s.budget)
	docs := map[string]*swaggerDoc{}
	sums := map[string]string{}
	out := make([]rendered, 0, len(cands))
	for _, m := range cands {
		// The files may come from a warm cache that never looks at the context.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		doc, ok := docs[m.file.Path]
		if !ok {
			body, err := s.d.store.File(ctx, s.ix.SHA, m.file)
			if err != nil {
				return nil, err
			}
			if err = s.budget.Charge(int64(len(body))); err != nil {
				return nil, err
			}
			if doc, err = decodeSwagger(body); err != nil {
				return nil, err
			}
			sum := sha256.Sum256(body)
			docs[m.file.Path], sums[m.file.Path] = doc, hex.EncodeToString(sum[:])
		}
		ref, err := renderOperation(ctx, renderInput{
			Doc: doc, File: m.file, Dir: m.dir, Group: m.group, Op: m.op, Commit: s.ix.SHA,
			Endpoint: s.d.endpoint, Service: s.q.Service, SHA256: sums[m.file.Path],
			Selector: shortestSelector(m, cands), Resolver: res,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, rendered{m: m, ref: ref})
	}

	return out, nil
}

// merge keeps one reference per request (see requestKey). The newest dir wins, then stable before preview, then
// group id, then file, then path.
func merge(rs []rendered) []rendered {
	slices.SortStableFunc(rs, func(a, b rendered) int {
		return cmp.Or(
			strings.Compare(b.m.dir.Name, a.m.dir.Name),
			kindRank(a.m.dir.Kind)-kindRank(b.m.dir.Kind),
			strings.Compare(a.m.group, b.m.group),
			strings.Compare(a.m.file.Path, b.m.file.Path),
			strings.Compare(a.m.op.Path, b.m.op.Path),
		)
	})
	seen := map[string]bool{}
	out := rs[:0]
	for _, r := range rs {
		if k := requestKey(r.ref); !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}

	return out
}

// requestKey is what makes two matches the same request: the method, the path, the body encoding, every fixed query
// value but the api-version, every fixed header value, and each required input with its location, wire name and
// type. The api-version is left out on purpose: it is what differs between version dirs, and between otherwise
// identical requests the newest dir wins. Every value is quoted on its own, so no value can mimic a separator.
func requestKey(ref *apiref.Reference) string {
	parts := []string{"m:" + ref.Method, "p:" + ref.PathTemplate, "b:" + string(ref.BodyEncoding)}
	for _, p := range ref.FixedQuery {
		if p.Key != apiVersionParam {
			parts = append(parts, "q:"+strconv.Quote(p.Key)+"="+strconv.Quote(p.Value))
		}
	}
	for _, h := range ref.FixedHeaders {
		parts = append(parts, "h:"+strconv.Quote(h.Key)+"="+strconv.Quote(h.Value))
	}
	for _, in := range ref.Inputs {
		if in.Required {
			parts = append(parts, "i:"+string(in.Location)+":"+strconv.Quote(in.WireName)+":"+strconv.Quote(in.Type))
		}
	}
	slices.Sort(parts[3:])

	return strings.Join(parts, " ")
}

// ambiguous answers several distinct requests with their shortest selectors.
func (s *search) ambiguous(rs []rendered) apiref.Result {
	ms := make([]match, 0, len(rs))
	for _, r := range rs {
		ms = append(ms, r.m)
	}

	return s.choose(ms, apiref.Bounded("several operations named "+echo(s.q.Operation)+" differ in their request",
		"; pass model with one of the choices"))
}

// choose answers ambiguous with the matches' shortest selectors: ordered by group id, then dir name descending, the
// first apiref.MaxChoices kept. A selector two matches share names one file, which a selector cannot split.
func (s *search) choose(ms []match, reason string) apiref.Result {
	slices.SortStableFunc(ms, func(a, b match) int {
		return cmp.Or(strings.Compare(a.group, b.group), strings.Compare(b.dir.Name, a.dir.Name),
			kindRank(a.dir.Kind)-kindRank(b.dir.Kind), strings.Compare(a.file.Path, b.file.Path))
	})
	var choices []string
	shared := false
	for _, m := range ms {
		c := shortestSelector(m, ms)
		if slices.Contains(choices, c) {
			shared = true

			continue
		}
		choices = append(choices, c)
	}
	if shared {
		reason = apiref.Bounded(reason, "; two of them are in one file, which a selector cannot tell apart")
	}

	return apiref.Result{
		Outcome: apiref.OutcomeAmbiguous, Reason: reason,
		Choices: apiref.Choices(choices[:min(len(choices), apiref.MaxChoices)]),
	}
}

// shortestSelector names m's dir, and its file too when model named the file or another candidate shares the dir.
func shortestSelector(m match, all []match) string {
	sel := selector{group: m.group, kind: m.dir.Kind, dir: m.dir.Name}
	if m.pinned {
		sel.file = path.Base(m.file.Path)

		return sel.String()
	}
	for _, o := range all {
		if o.group == m.group && o.dir.Kind == m.dir.Kind && o.dir.Name == m.dir.Name && o.file.Path != m.file.Path {
			sel.file = path.Base(m.file.Path)

			break
		}
	}

	return sel.String()
}

func distinctIDs(ms []match) []string {
	var ids []string
	for _, m := range ms {
		if !slices.Contains(ids, m.op.ID) {
			ids = append(ids, m.op.ID)
		}
	}

	return ids
}

// notFound answers a search that found nothing, naming what it read and the nearest ids.
func (s *search) notFound(fromPasses bool) apiref.Result {
	head := fmt.Sprintf("no operation %s in %s (%d version dirs searched in groups %s)", echo(s.q.Operation),
		s.ns.Name, len(s.searched), s.scannedGroups())
	suffix := s.nearest() + operationFormat
	if fromPasses {
		suffix += olderGuidance
	}

	return notFound(apiref.Bounded(head, suffix))
}

// scannedGroups names the groups the search read, up to maxGroupEcho in sorted order, then how many more.
func (s *search) scannedGroups() string {
	names := slices.Sorted(maps.Keys(s.scanned))
	if len(names) <= maxGroupEcho {
		return strings.Join(names, ", ")
	}

	return strings.Join(names[:maxGroupEcho], ", ") + fmt.Sprintf(" and %d more", len(names)-maxGroupEcho)
}

// noSuchModel answers a model that names no dir of the namespace.
func (s *search) noSuchModel(m lookupModel) apiref.Result {
	if m.sel != nil {
		return notFound(apiref.Bounded("no "+echo(m.sel.String())+" in "+s.ns.Name, modelGuidance))
	}
	var names []string
	for _, g := range s.groups {
		for _, dir := range s.ns.Groups[g].Dirs {
			if !slices.Contains(names, dir.Name) {
				names = append(names, dir.Name)
			}
		}
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(b, a) })

	return notFound(apiref.Bounded(s.ns.Name+" has no api-version dir "+echo(m.version),
		"; its newest dirs are "+strings.Join(names[:min(len(names), apiref.MaxChoices)], ", ")))
}

// failure answers a search a bound, the context or a load error stopped, naming the bound, the dirs read so far,
// the nearest ids seen while the context is live, and that model can name one version.
func (s *search) failure(ctx context.Context, err error) apiref.Result {
	var head string
	switch {
	case ctx.Err() != nil:
		head = ContextReason(ctx)
	case errors.Is(err, ErrBudgetExceeded):
		head = "the search stopped at the per-lookup budget of 160 MiB of spec files"
	default:
		head = "a spec file could not be loaded: " + err.Error()
	}
	suffix := fmt.Sprintf("; %d version dirs searched", len(s.searched))
	if n := len(s.searched); n > 0 {
		suffix += ", the last " + s.searched[n-1]
	}
	// A done lookup does no more work, scoring included.
	if ctx.Err() == nil {
		suffix += s.nearest()
	}
	suffix += "; pass model with an api-version dir name to search one version"

	return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: apiref.Bounded(head, suffix)}
}

// nearest lists up to maxNearest operation ids seen in the search, nearest first. Only ids in the operation grammar
// whose quoted form fits maxNearestEcho are scored, so the edit distances cost at most 200 by 100 bytes each.
func (s *search) nearest() string {
	var ids []string
	for id := range s.ids {
		if validOperation(id) && len(strconv.Quote(id)) <= maxNearestEcho {
			ids = append(ids, id)
		}
	}
	near := apiref.Nearest(ids, s.q.Operation, maxNearest)
	if len(near) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(near))
	for _, id := range near {
		quoted = append(quoted, strconv.Quote(id))
	}

	return "; nearest operation ids: " + strings.Join(quoted, ", ")
}
