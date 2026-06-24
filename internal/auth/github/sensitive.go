package github

import (
	"fmt"
	"slices"
	"strings"
)

// sensitivePattern is the admission anchor for a sensitive route family: every
// table template whose path contains Segment (as a whole path segment) must
// classify to Route.Category. AdmitTable enforces this at table load time,
// so a tampered or misdescribed OpenAPI spec cannot downgrade the family.
type sensitivePattern struct {
	segment string // a whole path segment that marks the sensitive family.
	route   Route
}

// sensitivePatterns is the integrity anchor. It is scoped to secret-scanning:
// the one unambiguous category whose READ endpoints leak secret material. (*/secrets
// is intentionally excluded — it spans several categories so a blanket override
// would mis-attribute, and secret values are write-only so its reads are
// metadata-only and its writes are blocked by the read default.)
//
// Note: there is intentionally no request-time SensitiveOverride. Matching on
// user-controlled path segments (e.g. a branch named "secret-scanning") would
// cause false-positive denials. Instead, protection comes from three layers:
// AdmitTable (rejects any table that maps a secret-scanning template to another
// category), the secret-scanning:none baseline in the default Exposure, and
// fail-closed-on-unknown (ErrUnclassifiable for routes not in the table).
var sensitivePatterns = []sensitivePattern{ //nolint:gochecknoglobals // immutable security constant.
	{segment: "secret-scanning", route: Route{Category: "secret-scanning", Subcategory: "secret-scanning"}},
}

// hasSegment reports whether any path segment equals seg (so "secret-scanning"
// matches ".../secret-scanning/alerts" but not ".../contents/secret-scanning.txt").
func hasSegment(path, seg string) bool {
	return slices.Contains(splitPath(path), seg)
}

// AdmitTable rejects a candidate table that would downgrade a sensitive route:
// every template whose path contains a sensitive segment must classify into the
// pattern's restrictive category. A mismatch fails closed (ErrTableRejected).
func AdmitTable(t *Table) error {
	for _, tm := range t.Routes() {
		path := "/" + strings.Join(tm.Segments, "/")
		for _, p := range sensitivePatterns {
			if hasSegment(path, p.segment) && tm.Route.Category != p.route.Category {
				return fmt.Errorf("%w: %q maps to category %q, want %q (sensitive-path downgrade)",
					ErrTableRejected, path, tm.Route.Category, p.route.Category)
			}
		}
	}
	return nil
}
