package github

import (
	"strings"

	"github.com/cynative/cynative/internal/auth/exposure"
)

// secretScanningOpened reports whether any key equal to "secret-scanning" or
// with the prefix "secret-scanning/" has a level other than LevelNone. An
// operator who sets a subcategory key (e.g. "secret-scanning/secret-scanning")
// opens secret-scanning reads via Resolve's most-specific match, so the posture
// must treat the whole family as opened.
func secretScanningOpened(e exposure.Exposure) bool {
	for k, v := range e {
		if (k == secretScanningKey || strings.HasPrefix(k, secretScanningKey+"/")) && v != exposure.LevelNone {
			return true
		}
	}
	return false
}

// PostureLoud reports whether an Exposure ceiling broadens access enough to
// warrant a loud (⚠️) posture: the default level is write, secret-scanning has
// been opened at all (including via a subcategory key), or any other category
// override broadens exposure to write.
func PostureLoud(e exposure.Exposure) bool {
	if e[exposure.DefaultKey] == exposure.LevelWrite || secretScanningOpened(e) {
		return true
	}
	for k, v := range e {
		if k == exposure.DefaultKey || k == secretScanningKey || strings.HasPrefix(k, secretScanningKey+"/") {
			continue
		}
		if v == exposure.LevelWrite {
			return true
		}
	}
	return false
}

// InventoryPosture renders the effective ceiling as the compact scalar the
// permissions config/env accepts (e.g. "default=read,secret-scanning=none"), for
// the startup connector inventory. secret-scanning is always shown so the secure
// default-deny is visible.
func InventoryPosture(e exposure.Exposure) string {
	return exposure.CompactCeiling(e, secretScanningKey)
}
