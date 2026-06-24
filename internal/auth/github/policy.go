package github

import (
	"fmt"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// secretScanningKey is the category whose read endpoints can leak secret
// material; the secure baseline denies it.
const secretScanningKey = "secret-scanning"

// BaselineExposure is the secure default: read everything except secret-scanning.
func BaselineExposure() exposure.Exposure {
	return exposure.Exposure{exposure.DefaultKey: exposure.LevelRead, secretScanningKey: exposure.LevelNone}
}

// BuildExposure overlays operator permission values onto the github secure baseline.
func BuildExposure(operator map[string]string) exposure.Exposure {
	return exposure.BuildExposure(BaselineExposure(), operator)
}

// Resolve returns the effective ceiling for (category, subcategory) using
// most-specific precedence: "category/subcategory" → "category" → "default".
// default is always present after MergeExposure, so the lookup terminates.
func Resolve(e exposure.Exposure, category, subcategory string) exposure.Level {
	if subcategory != "" {
		if lvl, ok := e[category+"/"+subcategory]; ok {
			return lvl
		}
	}
	if lvl, ok := e[category]; ok {
		return lvl
	}
	return e[exposure.DefaultKey]
}

// ValidateExposureKeys fails closed when an operator-configured key matches no
// real category in the active table. The baseline-managed keys are always valid:
// "default" (the fallback) and "secret-scanning" (the baseline deny — exempt so a
// table that happens to lack it does not reject the secure baseline). An unknown
// remaining key is almost always a typo, and under default:write a typo'd narrowing
// override would silently over-grant — so it is fatal.
func ValidateExposureKeys(e exposure.Exposure, t *Table) error {
	for key := range e {
		if key == exposure.DefaultKey || key == secretScanningKey {
			continue
		}
		if !t.Knows(key) {
			return fmt.Errorf("%w: connectors.github.permissions key %q matches no GitHub category", ErrUnknownKey, key)
		}
	}
	return nil
}
