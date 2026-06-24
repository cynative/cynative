// Package exposure holds the provider-agnostic exposure-ceiling currency shared
// by the github and gitlab auth subpackages: the access Level lattice and the
// Exposure map plus its merge/build helpers. It is a stdlib-only leaf and imports
// nothing from internal/auth, so both subpackages (which the parent internal/auth
// imports) can depend on it without an import cycle.
package exposure

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
)

// ErrInvalidLevel indicates a permission value that is not none|read|write.
var ErrInvalidLevel = errors.New("invalid exposure level")

// Level is the access ceiling for a category: none < read < write. write implies
// read; none denies even reads.
type Level int

const (
	// LevelNone denies every request for the category, including reads.
	LevelNone Level = iota
	// LevelRead allows reads and denies writes.
	LevelRead
	// LevelWrite allows reads and writes.
	LevelWrite
)

// DefaultKey is the always-present fallback key in an Exposure map.
const DefaultKey = "default"

// LevelName returns the canonical string name for a Level: "none", "read", or
// "write". It is the inverse of ParseLevel and is used for posture rendering.
func LevelName(l Level) string {
	switch l { //nolint:exhaustive // LevelNone is the safe default; default branch covers it.
	case LevelWrite:
		return "write"
	case LevelRead:
		return "read"
	default:
		return "none"
	}
}

// ParseLevel parses a config level value. It is case-sensitive and rejects the
// unexpected (fail closed), mirroring the classifier's exact-match posture.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "none":
		return LevelNone, nil
	case "read":
		return LevelRead, nil
	case "write":
		return LevelWrite, nil
	default:
		return LevelNone, fmt.Errorf("%w: %q (want none|read|write)", ErrInvalidLevel, s)
	}
}

// Allows reports whether a configured ceiling permits a request requiring level
// required (ceiling >= required), so write implies read and none denies all.
func Allows(ceiling, required Level) bool {
	return ceiling >= required
}

// Exposure is the resolved per-area ceiling. Keys are "default", a category, or a
// "category/subcategory" (github only; gitlab has no subcategory layer).
type Exposure map[string]Level

// MergeExposure overlays operator keys onto the secure baseline. An operator key
// overrides the baseline only for that exact key, so default:write does not relax
// a baseline-denied category unless the operator sets that category explicitly.
func MergeExposure(baseline, operator Exposure) Exposure {
	merged := make(Exposure, len(baseline)+len(operator))
	maps.Copy(merged, baseline)
	maps.Copy(merged, operator)
	return merged
}

// CompactCeiling renders an Exposure as the compact scalar the permissions
// config/env accepts (e.g. "default=read,issues=write,secret-scanning=none"): the
// default level first, then every other non-sensitive key sorted, then the
// sensitiveKey LAST so the security-relevant sensitive category is always the
// trailing, always-shown token. sensitiveKey is rendered even at its baseline none
// level (so the default-deny is always visible). It reuses LevelName, so a missing
// key prints "none".
func CompactCeiling(e Exposure, sensitiveKey string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s=%s", DefaultKey, LevelName(e[DefaultKey]))

	overrides := make([]string, 0, len(e))
	for k, v := range e {
		if k == DefaultKey || k == sensitiveKey {
			continue
		}
		overrides = append(overrides, k+"="+LevelName(v))
	}
	sort.Strings(overrides)
	for _, o := range overrides {
		b.WriteString(",")
		b.WriteString(o)
	}

	fmt.Fprintf(&b, ",%s=%s", sensitiveKey, LevelName(e[sensitiveKey]))

	return b.String()
}

// BuildExposure parses operator permission values and overlays them on the given
// baseline. Invalid values are skipped — config validation (config.Load) is the
// real gate, and a skipped key falls back to baseline/default, never over-granting.
func BuildExposure(baseline Exposure, operator map[string]string) Exposure {
	parsed := make(Exposure, len(operator))
	for k, v := range operator {
		if lvl, err := ParseLevel(v); err == nil {
			parsed[k] = lvl
		}
	}
	return MergeExposure(baseline, parsed)
}
