package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// Read bounds of the Kubernetes lookup recipe. The caps count decompressed bytes.
const (
	kubeRootMaxBytes    = 2 << 20
	kubeDocMaxBytes     = 10 << 20
	kubeVersionMaxBytes = 64 << 10
	kubeRootTimeout     = 20 * time.Second
	kubeDocTimeout      = 60 * time.Second
	kubeVersionTimeout  = 10 * time.Second
	// maxGitVersion bounds the gitVersion a reference shows, in bytes.
	maxGitVersion = 64
	// maxReadError bounds the transport error text an unavailable reason carries, in runes.
	maxReadError = 500
)

// Cache bounds: entries and bytes for the whole cache, and the largest entry it stores.
const (
	kubeCacheEntries  = 16
	kubeCacheBytes    = 16 << 20
	kubeCacheMaxEntry = 8 << 20
)

const (
	kubeRootPath    = "/openapi/v3"
	kubeVersionPath = "/version"
	kubeSourceName  = "cluster /openapi/v3"
	limitNoHash     = "the cluster published no usable hash for this document, so it was read fresh and not cached"
	limitChanged    = "the document changed while it was read, so it was read without a hash and not cached"
	limitNoVersion  = "the cluster version could not be read"
	reasonNoV3      = "this cluster does not serve /openapi/v3"
	reasonLeftOut   = "an aggregated API whose server is not answering is left out of that list"
	reasonCoreGroup = `the core group's apiVersion is "v1"`
)

// errKubeService rejects a service, which a kubernetes lookup does not take.
var errKubeService = errors.New(`service must be empty for kubernetes: the group goes in model, as in "apps/v1"`)

// errKubeOperation rejects an operation outside the lookup grammar.
var errKubeOperation = errors.New("operation must be an OpenAPI operationId: a letter, then letters, digits or " +
	"underscores, at most 200 characters, such as listAppsV1NamespacedDeployment")

// errKubeBlock rejects a kubernetes_auth block that does not decode.
var errKubeBlock = errors.New("kubernetes_auth must be a JSON object; pass {} as in http_request")

// gitVersionPattern is the form of a usable /version gitVersion.
var gitVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+_-]*$`)

var (
	_ TargetDocumenter = (*kubernetesProvider)(nil)
	_ TargetLookup     = (*kubeLookup)(nil)
)

// PrepareLookup validates a kubernetes lookup with no I/O: the block decodes into KubernetesAuthArgs, whose
// canonical form is always {}; service is empty; model is an apiVersion and operation an operationId, both used
// exactly as sent.
func (p *kubernetesProvider) PrepareLookup(q apiref.Query, raw json.RawMessage) (TargetLookup, error) {
	var args KubernetesAuthArgs
	if json.Unmarshal(raw, &args) != nil {
		return nil, errKubeBlock
	}
	// KubernetesAuthArgs has no fields, so json.Marshal cannot fail on it.
	block, _ := json.Marshal(args)
	if q.Service != "" {
		return nil, errKubeService
	}
	v, err := k8sauthz.ParseAPIVersion(q.Model)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}
	if !k8sauthz.ValidOperationID(q.Operation) {
		return nil, errKubeOperation
	}

	return &kubeLookup{p: p, version: v, operation: q.Operation, block: block}, nil
}

// kubeLookup is one validated kubernetes lookup. Nothing in it changes after PrepareLookup returns it.
type kubeLookup struct {
	p         *kubernetesProvider
	version   k8sauthz.APIVersion
	operation string
	block     json.RawMessage
}

// Block returns a copy of the canonical block, {}.
func (l *kubeLookup) Block() json.RawMessage { return slices.Clone(l.block) }

// Resolve makes no I/O: the target is the authority the kubeconfig names, which the host and port gates pin.
func (l *kubeLookup) Resolve(context.Context) (Target, error) {
	a := l.p.cluster.authority

	return Target{Endpoint: "https://" + a, Identity: "kubernetes/" + a}, nil
}

// Admit admits exactly /version, /openapi/v3 and this lookup's own document, the last with an optional valid
// hash, each with no block of its own.
func (l *kubeLookup) Admit(_ Target, r MetadataRead) bool {
	if r.Block != nil {
		return false
	}
	doc := l.docPath()
	if r.Path == kubeVersionPath || r.Path == kubeRootPath || r.Path == doc {
		return true
	}
	hash, ok := strings.CutPrefix(r.Path, doc+"?hash=")

	return ok && k8sauthz.ValidHash(hash)
}

func (l *kubeLookup) docPath() string { return kubeRootPath + "/" + l.version.Key }

// Answer runs the recipe: the root, then this lookup's document by the hash the root published, then /version.
func (l *kubeLookup) Answer(ctx context.Context, t Target, rd MetadataReader) apiref.Result {
	r := &kubeRecipe{l: l, t: t, rd: rd}

	return r.run(ctx)
}

// kubeRecipe is one run of the recipe and what it learned on the way.
type kubeRecipe struct {
	l           *kubeLookup
	t           Target
	rd          MetadataReader
	canonical   bool
	limitations []string
}

// kubeDoc is one document read that answered 200: the distilled document and the body's facts.
type kubeDoc struct {
	doc        *k8sauthz.Document
	sha, hash  string
	observedAt string
}

func (r *kubeRecipe) run(ctx context.Context) apiref.Result {
	hash, res, ok := r.root(ctx)
	if !ok {
		return res
	}
	if hash == "" {
		r.limitations = append(r.limitations, limitNoHash)
		return r.fetch(ctx)
	}
	if e, hit := r.l.p.refs.get(r.t.Endpoint, r.l.version.Key, hash); hit {
		return r.answer(e)
	}
	got, res, ok := r.document(ctx, hash)
	switch {
	case !ok:
		return res
	case got != nil:
		return r.finish(ctx, got)
	}
	// The hash was stale: re-read the root once.
	h2, res, ok := r.root(ctx)
	switch {
	case !ok:
		return res
	case h2 == "" || h2 == hash:
		return r.unhashed(ctx)
	}
	if e, hit := r.l.p.refs.get(r.t.Endpoint, r.l.version.Key, h2); hit {
		return r.answer(e)
	}
	if got, res, ok = r.document(ctx, h2); !ok {
		return res
	}
	if got != nil {
		return r.finish(ctx, got)
	}

	return r.unhashed(ctx)
}

// unhashed reads the document once without a hash, which the server cannot redirect, and caches nothing.
func (r *kubeRecipe) unhashed(ctx context.Context) apiref.Result {
	r.limitations = append(r.limitations, limitChanged)

	return r.fetch(ctx)
}

// fetch reads the document without a hash and answers from it. A 301 to that read is unavailable.
func (r *kubeRecipe) fetch(ctx context.Context) apiref.Result {
	got, res, ok := r.document(ctx, "")
	if !ok {
		return res
	}

	return r.finish(ctx, got)
}

// read makes one read and checks the context after it. ok is false when res is the answer.
func (r *kubeRecipe) read(ctx context.Context, mr MetadataRead) (MetadataResponse, apiref.Result, bool) {
	resp, err := r.rd.Read(ctx, mr)
	if res, done := checkContext(ctx); done {
		return resp, res, false
	}
	if err != nil {
		return resp, unavailable("GET " + mr.Path + " failed: " + apiref.Truncate(err.Error(), maxReadError)), false
	}
	if resp.Truncated {
		return resp, unavailable(fmt.Sprintf("GET %s exceeded %d bytes", mr.Path, mr.MaxBytes)), false
	}

	return resp, apiref.Result{}, true
}

// root reads and parses the root and finds this lookup's key in it. ok is false when res is the answer.
func (r *kubeRecipe) root(ctx context.Context) (string, apiref.Result, bool) {
	resp, res, ok := r.read(ctx, MetadataRead{Path: kubeRootPath, MaxBytes: kubeRootMaxBytes, Timeout: kubeRootTimeout})
	switch {
	case !ok:
		return "", res, false
	case resp.Status == http.StatusNotFound:
		return "", unavailable(reasonNoV3), false
	case resp.Status != http.StatusOK:
		return "", unavailable(statusReason(kubeRootPath, resp.Status)), false
	}
	root, err := k8sauthz.ParseRoot(ctx, []byte(resp.Body))
	if late, done := checkContext(ctx); done {
		return "", late, false
	}
	if err != nil {
		return "", unavailable(parseReason("the /openapi/v3 root", err)), false
	}
	hash, listed := root.Lookup(r.l.version.Key)
	if !listed {
		return "", r.notListed(root), false
	}
	r.canonical = root.Canonical(r.l.version.Key)

	return hash, apiref.Result{}, true
}

// notListed answers a key the root does not list, with the listed versions of the same group as choices.
func (r *kubeRecipe) notListed(root k8sauthz.Root) apiref.Result {
	v := r.l.version
	choices := root.Versions(v)
	choices = choices[:min(len(choices), apiref.MaxChoices)]
	head := v.Model() + " is not listed in this cluster's /openapi/v3"
	if len(choices) > 0 {
		head += "; it lists " + strings.Join(choices, ", ")
	}
	guidance := "; " + reasonLeftOut
	if v.Group == "core" || v.Group == "api" {
		guidance += "; " + reasonCoreGroup
	}

	return apiref.Result{Outcome: apiref.OutcomeNotFound, Reason: apiref.Bounded(head, guidance), Choices: choices}
}

// document reads this lookup's document, with ?hash= when hash is set. On a 200 it returns the distilled
// document; on a 301 to a hashed read it returns nil with ok set, so the caller applies the stale-hash rule.
func (r *kubeRecipe) document(ctx context.Context, hash string) (*kubeDoc, apiref.Result, bool) {
	path := r.l.docPath()
	if hash != "" {
		path += "?hash=" + hash
	}
	resp, res, ok := r.read(ctx, MetadataRead{Path: path, MaxBytes: kubeDocMaxBytes, Timeout: kubeDocTimeout})
	switch {
	case !ok:
		return nil, res, false
	case resp.Status == http.StatusMovedPermanently && hash != "":
		return nil, apiref.Result{}, true
	case resp.Status == http.StatusNotFound || (resp.Status == http.StatusOK && resp.Body == ""):
		return nil, unavailable(r.missingReason(resp.Status)), false
	case resp.Status != http.StatusOK:
		return nil, unavailable(statusReason(path, resp.Status)), false
	}
	v := r.l.version
	doc, err := k8sauthz.ParseDocument(ctx, []byte(resp.Body), v)
	if late, done := checkContext(ctx); done {
		return nil, late, false
	}
	if err != nil {
		return nil, unavailable(parseReason("the "+v.Model()+" document", err)), false
	}
	sum := sha256.Sum256([]byte(resp.Body))

	return &kubeDoc{
		doc: doc, sha: hex.EncodeToString(sum[:]), hash: hash,
		observedAt: r.l.p.now().UTC().Format(time.RFC3339),
	}, apiref.Result{}, true
}

// missingReason explains a listed document whose read answered 404 or an empty body.
func (r *kubeRecipe) missingReason(status int) string {
	what := "an empty body"
	if status == http.StatusNotFound {
		what = "404"
	}
	where := "; the cluster published that document's URL in the canonical form"
	if !r.canonical {
		where = "; the cluster published that document's URL outside the canonical path, which this tool does not follow"
	}

	return apiref.Bounded(fmt.Sprintf("the root lists %s but GET %s answered %s", r.l.version.Model(), r.l.docPath(),
		what), where)
}

// finish reads /version, stores the entry when the 200 answered a hashed read, and answers.
func (r *kubeRecipe) finish(ctx context.Context, got *kubeDoc) apiref.Result {
	version := r.version(ctx)
	if res, done := checkContext(ctx); done {
		return res
	}
	e := kubeRefEntry{doc: got.doc, version: version, observedAt: got.observedAt, sha: got.sha, hash: got.hash}
	if got.hash != "" {
		r.l.p.refs.put(r.t.Endpoint, r.l.version.Key, e)
	}

	return r.answer(e)
}

// version reads the cluster's gitVersion. Any ordinary failure leaves it empty; the reference then says so.
func (r *kubeRecipe) version(ctx context.Context) string {
	resp, err := r.rd.Read(ctx, MetadataRead{
		Path: kubeVersionPath, MaxBytes: kubeVersionMaxBytes, Timeout: kubeVersionTimeout,
	})
	if err != nil || resp.Status != http.StatusOK || resp.Truncated {
		return ""
	}
	var info map[string]json.RawMessage
	_ = json.Unmarshal([]byte(resp.Body), &info) // a body that is not an object has no version.
	var v string
	_ = json.Unmarshal(info["gitVersion"], &v) // a non-string gitVersion is no version.
	if len(v) > maxGitVersion || !gitVersionPattern.MatchString(v) {
		return ""
	}

	return v
}

// answer looks the operation up in a distilled document and adds what this run learned.
func (r *kubeRecipe) answer(e kubeRefEntry) apiref.Result {
	res := e.doc.Lookup(k8sauthz.Lookup{
		Operation:   r.l.operation,
		Endpoint:    r.t.Endpoint,
		ClusterRole: r.l.p.clusterRole,
		Source: apiref.Source{
			Name: kubeSourceName, Document: r.l.docPath(), Version: e.version, SHA256: e.sha,
			Target: r.t.Identity, ServerHash: e.hash, ObservedAt: e.observedAt,
		},
	})
	if res.Reference == nil {
		return res
	}
	res.Reference.Limitations = append(res.Reference.Limitations, r.limitations...)
	if e.version == "" {
		res.Reference.Limitations = append(res.Reference.Limitations, limitNoVersion)
	}

	return res
}

func unavailable(reason string) apiref.Result {
	return apiref.Result{Outcome: apiref.OutcomeUnavailable, Reason: reason}
}

func statusReason(path string, status int) string {
	return fmt.Sprintf("GET %s answered %d", path, status)
}

// parseReason names what was refused and why, in fixed host text only.
func parseReason(subject string, err error) string {
	if errors.Is(err, k8sauthz.ErrScanRefused) {
		return subject + " was " + err.Error()
	}
	if rest, ok := strings.CutPrefix(err.Error(), "the document "); ok {
		return subject + " " + rest
	}

	return err.Error()
}

// checkContext answers unavailable when ctx is done.
func checkContext(ctx context.Context) (apiref.Result, bool) {
	if ctx.Err() == nil {
		return apiref.Result{}, false
	}

	return unavailable(ContextReason(ctx)), true
}

// kubeRefEntry is one cached distilled document and the facts of the read that produced it.
type kubeRefEntry struct {
	doc        *k8sauthz.Document
	version    string
	observedAt string
	sha        string
	hash       string
	key        string
	size       int
}

// kubeRefCache holds distilled documents for one provider, so for one session: at most kubeCacheEntries entries
// and kubeCacheBytes bytes, the oldest evicted first. It is keyed by endpoint, document key and the hash the
// server confirmed, so a changed document misses.
type kubeRefCache struct {
	mu      sync.Mutex
	entries []kubeRefEntry
	bytes   int
}

func kubeCacheKey(endpoint, key, hash string) string { return endpoint + "\x00" + key + "\x00" + hash }

func (c *kubeRefCache) get(endpoint, key, hash string) (kubeRefEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := kubeCacheKey(endpoint, key, hash)
	for _, e := range c.entries {
		if e.key == k {
			return e, true
		}
	}

	return kubeRefEntry{}, false
}

// put stores e unless it is over kubeCacheMaxEntry, then evicts the oldest entries until both bounds hold. The
// size is a walk that stops once it passes the entry limit, so nothing is serialized to measure it.
func (c *kubeRefCache) put(endpoint, key string, e kubeRefEntry) {
	e.key = kubeCacheKey(endpoint, key, e.hash)
	e.size = len(e.key) + len(e.version) + len(e.observedAt) + len(e.sha) + e.doc.Size(kubeCacheMaxEntry)
	if e.size > kubeCacheMaxEntry {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = slices.DeleteFunc(c.entries, func(old kubeRefEntry) bool { return old.key == e.key })
	c.entries = append(c.entries, e)
	c.bytes = 0
	for _, old := range c.entries {
		c.bytes += old.size
	}
	for len(c.entries) > kubeCacheEntries || c.bytes > kubeCacheBytes {
		c.bytes -= c.entries[0].size
		// Clear the slot first: the backing array outlives the reslice and would keep the document reachable.
		c.entries[0] = kubeRefEntry{}
		c.entries = c.entries[1:]
	}
}
