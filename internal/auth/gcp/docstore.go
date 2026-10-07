package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/cache"
)

// docNameFormat tells a model what a GCP operation name looks like, after a lookup found none.
const docNameFormat = "GCP operation names are Discovery method ids: the API name, then the resources and the " +
	"method, for example compute.instances.list"

// docSafePart is what a directory name or version must look like before it names a cache file.
var docSafePart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// defaultVersion is a version label a lookup without model searches.
var defaultVersion = regexp.MustCompile(`^v[0-9]+$`)

// Docs serves api_reference from the Discovery directory and the documents a lookup needs, each in its own TTL
// cache under one directory. It never reads the gate's catalog and never sends a credential.
type Docs struct {
	cfg   cache.Config
	fetch func(ctx context.Context, url string) ([]byte, error)
	dir   *cache.TTLCache[directoryResponse]

	mu   sync.Mutex
	docs map[string]*cache.TTLCache[APIDoc]
}

// NewDocs builds the store. cfg.Dir is the docs cache directory (<cache>/gcp/docs); fetch downloads one URL.
func NewDocs(cfg cache.Config, directoryURL string, fetch func(ctx context.Context, url string) ([]byte, error)) *Docs {
	return &Docs{
		cfg:   cfg,
		fetch: fetch,
		dir: cache.NewNamedCache(cfg, "directory",
			func(ctx context.Context) ([]byte, error) { return fetch(ctx, directoryURL) },
			distillDirectory, serializeDirectory, distillDirectory, admitDirectory),
		docs: map[string]*cache.TTLCache[APIDoc]{},
	}
}

// distillDirectory keeps each directory item's name, version and document URL.
func distillDirectory(raw []byte) (*directoryResponse, error) {
	var d directoryResponse
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%w: directory: %w", ErrDocsRejected, err)
	}
	return &d, nil
}

func serializeDirectory(d *directoryResponse) []byte {
	// A directoryResponse is plain strings in a slice, so json.Marshal cannot fail.
	b, _ := json.Marshal(d)
	return b
}

func admitDirectory(d *directoryResponse) error {
	if len(d.Items) == 0 {
		return fmt.Errorf("%w: directory lists no APIs", ErrDocsRejected)
	}
	return nil
}

// Reference answers an api_reference lookup for a Discovery method id.
func (d *Docs) Reference(ctx context.Context, q apiref.Query) apiref.Result {
	dir := d.dir.Get(ctx)
	if dir == nil {
		return apiref.Result{
			Outcome: apiref.OutcomeUnavailable,
			Reason:  "the Google API Discovery directory could not be loaded",
		}
	}
	res := d.lookup(ctx, dir, q)
	if res.Outcome != apiref.OutcomeNotFound {
		return res
	}
	// Models copy the "repos/get" naming of other connectors and prefix a correct id. Name the method the part
	// after the last slash resolves to, without answering for it.
	if i := strings.LastIndex(q.Operation, "/"); i >= 0 {
		sub := q
		sub.Operation = q.Operation[i+1:]
		if r := d.lookup(ctx, dir, sub); r.Reference != nil {
			res.Reason = apiref.Truncate(fmt.Sprintf("%s; GCP operation names carry no prefix: did you mean %q?",
				res.Reason, r.Reference.Operation), apiref.MaxReason)
			return res
		}
	}
	res.Reason = apiref.Truncate(res.Reason+"; "+docNameFormat, apiref.MaxReason)
	return res
}

// lookup resolves the API name, selects the versions to search and finds the method in them.
func (d *Docs) lookup(ctx context.Context, dir *directoryResponse, q apiref.Query) apiref.Result {
	echo := apiref.Truncate(strconv.Quote(q.Operation), apiref.MaxChoice)
	prefix, _, _ := strings.Cut(q.Operation, ".")
	api, res := resolveAPI(dir, prefix)
	if res != nil {
		return *res
	}
	items := itemsOf(dir, api)
	search, res := selectVersions(items, api, q.Model, echo)
	if res != nil {
		return *res
	}
	docs := make([]*APIDoc, 0, len(search))
	for _, it := range search {
		doc := d.load(ctx, it)
		if doc == nil {
			return apiref.Result{
				Outcome: apiref.OutcomeUnavailable,
				Reason: apiref.Truncate(
					"the Discovery document "+it.Name+" "+it.Version+" could not be loaded",
					apiref.MaxReason,
				),
			}
		}
		docs = append(docs, doc)
	}
	doc, id, res := pickMethod(docs, q.Operation)
	if res != nil {
		return *res
	}
	if doc == nil {
		var labels []string
		for _, it := range search {
			labels = append(labels, it.Version)
		}
		reason := fmt.Sprintf("no operation %s in %s %s", echo, api, strings.Join(labels, ", "))
		if q.Model == "" {
			reason = fmt.Sprintf("no operation %s in the default-eligible versions searched (%s)", echo,
				strings.Join(labels, ", ")) + otherVersions(items, search)
		}
		return apiref.Result{Outcome: apiref.OutcomeNotFound, Reason: reason}
	}
	ref := buildReference(doc, id)
	return apiref.Result{Outcome: apiref.OutcomeOf(ref), Reference: ref}
}

// resolveAPI matches a directory name exactly, then case-insensitively when exactly one name folds to it.
func resolveAPI(dir *directoryResponse, name string) (string, *apiref.Result) {
	var folded []string
	for _, it := range dir.Items {
		if it.Name == name {
			return name, nil
		}
		if strings.EqualFold(it.Name, name) && !slices.Contains(folded, it.Name) {
			folded = append(folded, it.Name)
		}
	}
	switch len(folded) {
	case 1:
		return folded[0], nil
	case 0:
		return "", &apiref.Result{
			Outcome: apiref.OutcomeNotFound,
			Reason: fmt.Sprintf("API %s is not in the Google API Discovery directory",
				apiref.Truncate(strconv.Quote(name), apiref.MaxChoice)),
		}
	}
	return "", &apiref.Result{
		Outcome: apiref.OutcomeAmbiguous,
		Reason:  "several Discovery API names differ only by case",
		Choices: apiref.Choices(folded),
	}
}

func itemsOf(dir *directoryResponse, api string) []directoryItem {
	var out []directoryItem
	for _, it := range dir.Items {
		if it.Name == api {
			out = append(out, it)
		}
	}
	return out
}

// selectVersions returns the directory items a lookup searches: exactly the model when one is given, else every
// default-eligible version in ascending numeric order.
func selectVersions(items []directoryItem, api, model, echo string) ([]directoryItem, *apiref.Result) {
	if model != "" {
		if i := slices.IndexFunc(items, func(it directoryItem) bool { return it.Version == model }); i >= 0 {
			return items[i : i+1], nil
		}
		return nil, &apiref.Result{
			Outcome: apiref.OutcomeNotFound,
			Reason: fmt.Sprintf("API %s has no version %s; its versions are %s", api,
				apiref.Truncate(strconv.Quote(model), apiref.MaxChoice), strings.Join(versionLabels(items), ", ")),
		}
	}
	var search []directoryItem
	for _, it := range items {
		if defaultVersion.MatchString(it.Version) {
			search = append(search, it)
		}
	}
	if len(search) == 0 {
		return nil, &apiref.Result{
			Outcome: apiref.OutcomeNotFound,
			Reason: fmt.Sprintf("no operation %s in the default-eligible versions searched (none)", echo) +
				otherVersions(items, nil),
		}
	}
	slices.SortFunc(search, func(a, b directoryItem) int { return compareVersions(a.Version, b.Version) })
	return search, nil
}

// compareVersions orders vN labels by number: a shorter number is smaller, and equal lengths compare as text.
func compareVersions(a, b string) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

// versionLabels lists the items' versions, sorted, at most apiref.MaxChoices.
func versionLabels(items []directoryItem) []string {
	labels := make([]string, 0, len(items))
	for _, it := range items {
		labels = append(labels, it.Version)
	}
	return apiref.Choices(labels)
}

// otherVersions names the versions a lookup without model did not search, as lookups to try with model.
func otherVersions(items, searched []directoryItem) string {
	var rest []directoryItem
	for _, it := range items {
		if !slices.Contains(searched, it) {
			rest = append(rest, it)
		}
	}
	if len(rest) == 0 {
		return ""
	}
	return "; other versions to try with model: " + strings.Join(versionLabels(rest), ", ")
}

// pickMethod finds the method id in the loaded documents: an exact match in any document outranks a
// case-insensitive one. It returns a nil document and result when no document defines it.
func pickMethod(docs []*APIDoc, op string) (*APIDoc, string, *apiref.Result) {
	var exact []*APIDoc
	for _, doc := range docs {
		if _, ok := doc.Methods[op]; ok {
			exact = append(exact, doc)
		}
	}
	if len(exact) == 1 {
		return exact[0], op, nil
	}
	if len(exact) > 1 {
		return nil, "", ambiguousVersions(exact, op)
	}
	var hits []*APIDoc
	var ids []string
	for _, doc := range docs {
		for _, id := range slices.Sorted(maps.Keys(doc.Methods)) {
			if strings.EqualFold(id, op) {
				hits = append(hits, doc)
				ids = append(ids, id)
			}
		}
	}
	switch {
	case len(hits) == 1:
		return hits[0], ids[0], nil
	case len(hits) == 0:
		return nil, "", nil
	case slices.ContainsFunc(hits, func(h *APIDoc) bool { return h.Version != hits[0].Version }):
		return nil, "", ambiguousVersions(hits, op)
	}
	return nil, "", &apiref.Result{
		Outcome: apiref.OutcomeAmbiguous,
		Reason:  "several operations differ only by case",
		Choices: apiref.Choices(ids),
	}
}

func ambiguousVersions(docs []*APIDoc, op string) *apiref.Result {
	var labels []string
	for _, doc := range docs {
		if !slices.Contains(labels, doc.Version) {
			labels = append(labels, doc.Version)
		}
	}
	return &apiref.Result{
		Outcome: apiref.OutcomeAmbiguous,
		Reason: fmt.Sprintf("several versions define %s; pass model with one of the choices",
			apiref.Truncate(strconv.Quote(op), apiref.MaxChoice)),
		Choices: apiref.Choices(labels),
	}
}

// load returns the distilled document of a directory item, or nil when it cannot be named safely as a cache file
// or cannot be loaded.
func (d *Docs) load(ctx context.Context, it directoryItem) *APIDoc {
	tc := d.docCache(it)
	if tc == nil {
		return nil
	}
	return tc.Get(ctx)
}

// docCache returns the cache for one document, creating it on first use. A name or version that is not a safe
// file name part gets none.
func (d *Docs) docCache(it directoryItem) *cache.TTLCache[APIDoc] {
	if !safePart(it.Name) || !safePart(it.Version) {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// The map key keeps the parts apart: the file stem joins them with a dot, so two entries can share a file, and
	// each cache admits only its own document from it.
	key := it.Name + "\x00" + it.Version
	if tc, ok := d.docs[key]; ok {
		return tc
	}
	url := it.DiscoveryRestURL
	tc := cache.NewNamedCache(d.cfg, it.Name+"."+it.Version,
		func(ctx context.Context) ([]byte, error) { return d.fetch(ctx, url) },
		DistillDoc, (*APIDoc).Serialize, UnmarshalDoc, admitDoc(it.Name, it.Version))
	d.docs[key] = tc
	return tc
}

func safePart(s string) bool {
	return docSafePart.MatchString(s) && s != "." && s != ".."
}
