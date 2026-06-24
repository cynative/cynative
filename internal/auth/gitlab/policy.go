package gitlab

import (
	"fmt"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// ciVariablesKey is the category whose reads return plaintext CI/CD variable
// values; the secure baseline denies it (the GitLab analogue to GitHub's
// secret-scanning).
const ciVariablesKey = "ci-variables"

// BaselineExposure is the secure default: read everything except ci-variables
// (whose reads return plaintext secret values).
func BaselineExposure() exposure.Exposure {
	return exposure.Exposure{exposure.DefaultKey: exposure.LevelRead, ciVariablesKey: exposure.LevelNone}
}

// BuildExposure overlays operator permission values onto the gitlab secure baseline.
func BuildExposure(operator map[string]string) exposure.Exposure {
	return exposure.BuildExposure(BaselineExposure(), operator)
}

// Resolve returns the effective ceiling for a category: "category" → "default".
// default is always present after MergeExposure, so the lookup terminates.
func Resolve(e exposure.Exposure, category string) exposure.Level {
	if lvl, ok := e[category]; ok {
		return lvl
	}
	return e[exposure.DefaultKey]
}

// ValidateExposureKeys fails closed when an operator-configured key matches no
// real category in the active table. The baseline-managed keys are always valid:
// "default" (the fallback) and "ci-variables" (the baseline deny — exempt so a
// table that happens to lack a ci-variables route does not reject the secure
// baseline). An unknown remaining key is almost always a typo, and under
// default:write a typo'd narrowing override would silently over-grant — so fatal.
func ValidateExposureKeys(e exposure.Exposure, t *Table) error {
	for key := range e {
		if key == exposure.DefaultKey || key == ciVariablesKey {
			continue
		}
		if !t.Knows(key) {
			return fmt.Errorf("%w: connectors.gitlab.permissions key %q matches no GitLab category", ErrUnknownKey, key)
		}
	}
	return nil
}
