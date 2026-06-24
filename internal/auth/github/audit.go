package github

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// levelReadValue is the canonical permission value string for read access.
const levelReadValue = "read"

// DriftWarning compares our access-level classification against GitHub's
// authoritative X-Accepted-GitHub-Permissions response header. It returns a
// warning (and true) only when we classified the request as read and allowed it
// but GitHub considers read insufficient — a possible under-classification. It
// never blocks (the response already returned); it is advisory defense-in-depth.
func DriftWarning(accessLevel exposure.Level, acceptedPermissionsHeader string) (string, bool) {
	header := strings.TrimSpace(acceptedPermissionsHeader)
	if accessLevel != exposure.LevelRead || header == "" {
		return "", false
	}
	if headerReadSatisfiable(header) {
		return "", false
	}
	return fmt.Sprintf(
		"github_hardening: ⚠️  classified read but GitHub requires write/admin "+
			"(X-Accepted-GitHub-Permissions: %s) — possible classifier/table under-classification",
		header,
	), true
}

// headerReadSatisfiable reports whether at least one ";"-separated alternative
// permission set is satisfiable entirely by read-level permissions.
func headerReadSatisfiable(header string) bool {
	return slices.ContainsFunc(strings.Split(header, ";"), altAllRead)
}

// altAllRead reports whether every comma-separated permission in a single
// alternative set is at read level. An empty set is not read-satisfiable.
func altAllRead(alt string) bool {
	found := false
	for perm := range strings.SplitSeq(alt, ",") {
		perm = strings.TrimSpace(perm)
		if perm == "" {
			continue
		}
		found = true
		_, val, ok := strings.Cut(perm, "=")
		if !ok || strings.TrimSpace(val) != levelReadValue {
			return false
		}
	}
	return found
}
