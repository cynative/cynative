package aws

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// vhostBucketPlaceholder is the synthetic {Bucket} path segment prepended for
// virtual-hosted S3 requests so the path-style URI templates line up. It must be
// a single, non-empty, dot/slash-free segment that does not collide with any
// literal first path segment in the S3 model. Almost every S3 path-style template
// begins with the {Bucket} placeholder (which matches any non-empty segment); the
// lone exception is WriteGetObjectResponse (POST /WriteGetObjectResponse), so a
// placeholder equal to that literal would let a virtual-hosted "POST /" spuriously
// match it. The leading/trailing-underscore form below is not a valid AWS
// operation path literal, so it cannot collide; an invariant test pins this.
const vhostBucketPlaceholder = "_cynative_vhost_bucket_"

// classificationPath returns the path classifyREST should match. For
// virtual-hosted S3 requests (parsed.BucketInHost) it prepends the synthetic
// {Bucket} segment the host carries but the path omits; otherwise it returns the
// path unchanged (path-style and every non-S3 request are untouched).
func classificationPath(parsed ParsedHost, rawPath string) string {
	if !parsed.BucketInHost {
		return rawPath
	}
	if rawPath == "" || rawPath == "/" {
		return "/" + vhostBucketPlaceholder
	}
	return "/" + vhostBucketPlaceholder + rawPath
}

// classifyREST identifies which operations in model match v. Matching uses
// (method, URI template); among multiple matches the most specific template
// ranks highest, by the Smithy specificity of its path first and by how many
// of the request's discriminators it requires second (see compareCandidates),
// and every operation at that top rank is returned in name order. More than
// one name is a tie: nothing in the request or the model says which of them
// AWS runs, so the caller must authorize all of them. path is the effective
// classification path (already normalized by classificationPath).
func classifyREST(model *ServiceModel, v authreq.View, path string) ([]string, error) {
	method := strings.ToUpper(v.Method)
	// Lenient parse, matching what [net/url.URL.Query] did here before the view.
	reqQuery, _ := url.ParseQuery(v.RawQuery)

	var hits []candidate

	// Iterate operations in deterministic (lexicographic) order so the
	// tie-break logic below is reproducible regardless of map iteration order.
	names := make([]string, 0, len(model.Operations))
	for name := range model.Operations {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		op := model.Operations[name]
		if op.HTTPMethod == "" || !strings.EqualFold(op.HTTPMethod, method) {
			continue
		}
		tplPath, tplQuery := splitTemplateQuery(op.URITemplate)
		if !matchURITemplate(tplPath, path) {
			continue
		}
		score, ok := scoreDiscriminators(op, tplQuery, reqQuery, v.Header)
		if !ok {
			continue
		}
		hits = append(hits, candidate{name: name, shape: templateShape(tplPath), score: score})
	}

	if len(hits) == 0 {
		return nil, fmt.Errorf("%w: no match for %s %s", ErrClassifierUnknownOp, method, path)
	}
	return topCandidates(hits), nil
}

// candidate is an operation whose template fully matches the request: its
// name, the shape of its template path and its discriminator count.
type candidate struct {
	name  string
	shape []segmentKind
	score int
}

// segmentKind classifies a URI template path segment for specificity routing.
// The declaration order is the specificity order: a literal segment is more
// specific than a label, and a label more specific than a greedy label.
type segmentKind int

const (
	greedyLabel segmentKind = iota
	singleLabel
	literalSegment
)

// templateShape maps a template path to the kinds of its segments.
func templateShape(tplPath string) []segmentKind {
	segs := splitSegments(tplPath)
	shape := make([]segmentKind, len(segs))
	for i, seg := range segs {
		switch {
		case isGreedyPlaceholder(seg):
			shape[i] = greedyLabel
		case isSinglePlaceholder(seg):
			shape[i] = singleLabel
		default:
			shape[i] = literalSegment
		}
	}
	return shape
}

// compareCandidates orders two full matches by path first, then by
// discriminator count. The path order is the Smithy 2.0 http-bindings
// "Specificity Routing" comparison: shapes are compared segment by segment, at
// the first index whose kinds differ the more specific kind wins, and a
// template that runs out of segments loses to the longer one. Literal values
// take no part, as the specification continues past a pair of literals.
//
// The count that breaks a remaining tie is cynative's own, not the
// specification's: the specification counts URI query literals alone, while
// this count adds the required member-bound @httpQuery and @httpHeader
// discriminators S3 routes on (see scoreDiscriminators). A request carrying
// one operation's query literal and another's required member therefore still
// ties, and the caller authorizes both.
func compareCandidates(a, b candidate) int {
	if c := slices.Compare(a.shape, b.shape); c != 0 {
		return c
	}
	return cmp.Compare(a.score, b.score)
}

// topCandidates returns the names of every candidate at the top rank. hits
// come in name order, so the result is in name order too.
func topCandidates(hits []candidate) []string {
	best := hits[0]
	ops := []string{best.name}
	for _, h := range hits[1:] {
		switch c := compareCandidates(h, best); {
		case c > 0:
			best, ops = h, []string{h.name}
		case c == 0:
			ops = append(ops, h.name)
		}
	}
	return ops
}

// scoreDiscriminators returns how many of an operation's required
// discriminators are present in the request and whether ALL of them are. The
// discriminators are the @http URI-literal query flags plus the required
// member-bound @httpQuery params and @httpHeader names (e.g. uploadId,
// x-amz-copy-source) — the parameters S3 itself uses to route operations that
// share a (method, URI). Among templates of the same path shape a higher count
// ⇒ a more specific operation, which outranks its catch-all sibling in
// classifyREST so the action check authorizes the right IAM action; operations
// at the same count are returned together.
func scoreDiscriminators(
	op Operation,
	tplQuery []string,
	reqQuery map[string][]string,
	reqHeader http.Header,
) (int, bool) {
	score := 0
	for _, flag := range tplQuery {
		if _, ok := reqQuery[flag]; !ok {
			return 0, false
		}
		score++
	}
	for _, q := range op.RequiredQuery {
		if _, ok := reqQuery[q]; !ok {
			return 0, false
		}
		score++
	}
	for _, h := range op.RequiredHeader {
		if reqHeader.Get(h) == "" {
			return 0, false
		}
		score++
	}
	return score, true
}

// splitTemplateQuery splits "/{Bucket}?policy&versionId" into ("/{Bucket}",
// []string{"policy", "versionId"}). Only the presence of a flag matters, not
// its value, so "?list-type=2" yields the flag "list-type". The SDK-injected
// x-id tag is dropped (see the loop) so it is never a required discriminator.
func splitTemplateQuery(uri string) (string, []string) {
	path, query, hasQuery := strings.Cut(uri, "?")
	if !hasQuery || query == "" {
		return path, nil
	}
	var flags []string
	for kv := range strings.SplitSeq(query, "&") {
		name, _, _ := strings.Cut(kv, "=")
		// x-id is an AWS SDK-injected operation tag (e.g. "/?x-id=ListBuckets"),
		// not a semantic discriminator; non-SDK requests omit it, so it must not
		// be treated as a required query flag or the canonical request fails to
		// match and is denied closed.
		if name == "" || strings.EqualFold(name, "x-id") {
			continue
		}
		flags = append(flags, name)
	}
	return path, flags
}

// matchURITemplate reports whether path conforms to the Smithy URI template.
// path carries no query: the view keeps it in RawQuery, so a "?" here is a
// decoded %3F and belongs to the segment it sits in. Treating it as a
// separator would let /automationrulesv2/list%3Fx forge a match against the
// literal /automationrulesv2/list, while AWS reads the identifier "list?x".
// Supports:
//   - literal segments: must match exactly
//   - {Var}: matches a single non-empty path segment
//   - {Var+}: matches one or more non-empty segments; the template segments
//     after it must match the tail of the path, so a literal suffix such as
//     /{Name+}/policy never matches a path that does not end in it.
func matchURITemplate(template, path string) bool {
	tSegs := splitSegments(template)
	pSegs := splitSegments(path)

	for i, t := range tSegs {
		if isGreedyPlaceholder(t) {
			return matchGreedy(tSegs[i+1:], pSegs, i)
		}
		if !matchSegment(t, i, pSegs) {
			return false
		}
	}

	// No greedy placeholder consumed; path must have exactly the same length.
	return len(pSegs) == len(tSegs)
}

// matchGreedy matches a greedy label starting at path index i, followed by the
// template segments in suffix. The label takes every segment the suffix leaves,
// which must be at least one and all non-empty; the suffix then has to match
// the remaining tail segment by segment.
func matchGreedy(suffix, pSegs []string, i int) bool {
	end := len(pSegs) - len(suffix)
	if end <= i || slices.Contains(pSegs[i:end], "") {
		return false
	}
	for j, t := range suffix {
		if !matchSegment(t, end+j, pSegs) {
			return false
		}
	}
	return true
}

// matchSegment reports whether the non-greedy template segment t matches the
// i-th path segment: a placeholder needs a non-empty segment, a literal an
// exact one.
func matchSegment(t string, i int, pSegs []string) bool {
	if isSinglePlaceholder(t) {
		return i < len(pSegs) && pSegs[i] != ""
	}
	return i < len(pSegs) && pSegs[i] == t
}

// splitSegments splits a URI path on "/", dropping the leading empty segment.
// "/" → []string{""}, "/foo" → []string{"foo"}, etc.
func splitSegments(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return []string{""}
	}
	return strings.Split(p, "/")
}

func isSinglePlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && !strings.HasSuffix(seg, "+}")
}

func isGreedyPlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "+}")
}

// ErrClassifierUnknownOp indicates the request did not match any operation
// in the supplied ServiceModel.
var ErrClassifierUnknownOp = errors.New("aws_hardening: cannot identify operation from request")
