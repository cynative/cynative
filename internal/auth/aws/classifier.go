package aws

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
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

// classifyREST identifies which operation in model matches req. Matching uses
// (method, URI template); among multiple matches, the one whose query-flag
// set is the longest subset of req's query parameters wins. path is the
// effective classification path (already normalized by classificationPath).
func classifyREST(model *ServiceModel, req *http.Request, path string) (string, error) {
	method := strings.ToUpper(req.Method)
	reqQuery := req.URL.Query()

	type candidate struct {
		name  string
		score int
	}
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
		score, ok := scoreDiscriminators(op, tplQuery, reqQuery, req.Header)
		if !ok {
			continue
		}
		hits = append(hits, candidate{name: name, score: score})
	}

	if len(hits) == 0 {
		return "", fmt.Errorf("%w: no match for %s %s", ErrClassifierUnknownOp, method, path)
	}
	best := hits[0]
	for _, h := range hits[1:] {
		if h.score > best.score {
			best = h
		}
	}
	return best.name, nil
}

// scoreDiscriminators returns how many of an operation's required
// discriminators are present in the request and whether ALL of them are. The
// discriminators are the @http URI-literal query flags plus the required
// member-bound @httpQuery params and @httpHeader names (e.g. uploadId,
// x-amz-copy-source) — the parameters S3 itself uses to route operations that
// share a (method, URI). A higher count ⇒ a more specific operation, which
// breaks ties in classifyREST so the precise op (not the alphabetically-first)
// wins and the action check authorizes the right IAM action.
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
// Supports:
//   - literal segments: must match exactly
//   - {Var}: matches a single non-empty path segment
//   - {Var+}: matches one or more remaining segments (greedy), each non-empty.
func matchURITemplate(template, path string) bool {
	// Strip query string from path (URITemplate doesn't include query).
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	tSegs := splitSegments(template)
	pSegs := splitSegments(path)

	for i, t := range tSegs {
		if !matchSegment(t, i, pSegs) {
			return false
		}
		if isGreedyPlaceholder(t) {
			return true
		}
	}

	// No greedy placeholder consumed; path must have exactly the same length.
	return len(pSegs) == len(tSegs)
}

// matchSegment reports whether the i-th template segment t matches against pSegs.
// Greedy placeholders consume all remaining segments (caller stops iterating).
func matchSegment(t string, i int, pSegs []string) bool {
	switch {
	case isGreedyPlaceholder(t):
		return i < len(pSegs) && !slices.Contains(pSegs[i:], "")
	case isSinglePlaceholder(t):
		return i < len(pSegs) && pSegs[i] != ""
	default:
		return i < len(pSegs) && pSegs[i] == t
	}
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
