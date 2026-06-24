package gitlab

import (
	"fmt"
	"slices"
	"strings"
)

// sensitiveSegment is the whole path segment that marks the secret-leaking
// variable family. CI/CD variable GETs return the plaintext `value` field, so
// DistillOpenAPI forces the ci-variables category for any template carrying a
// literal `variables` segment regardless of the operation's tag (the tag
// scatters across CI variables / Pipelines / Pipeline schedules).
const sensitiveSegment = "variables"

// AdmitTable rejects a candidate (fetched or cached) table that maps a
// variables-segment template to any category other than ci-variables — a
// cache-poisoning defense. DistillOpenAPI forces ci-variables for these
// templates, so a fresh table always passes; a tampered cached blob does not.
func AdmitTable(t *Table) error {
	for _, tm := range t.Routes() {
		if hasVariablesSegment(tm.Segments) && tm.Route.Category != ciVariablesKey {
			return fmt.Errorf("%w: %q maps to %q, want %q (ci-variables downgrade)",
				ErrTableRejected, "/"+strings.Join(tm.Segments, "/"), tm.Route.Category, ciVariablesKey)
		}
	}
	return nil
}

// hasVariablesSegment reports whether segs contains the sensitive "variables"
// segment that marks a CI/CD-variable endpoint.
func hasVariablesSegment(segs []string) bool {
	return slices.Contains(segs, sensitiveSegment)
}
