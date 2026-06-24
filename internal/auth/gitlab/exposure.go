package gitlab

import (
	"github.com/cynative/cynative/internal/auth/exposure"
)

// PostureLoud reports whether an Exposure ceiling broadens access enough to
// warrant a loud (⚠️) posture: default is write, ci-variables has been opened, or
// any other category override broadens exposure to write.
func PostureLoud(e exposure.Exposure) bool {
	if e[exposure.DefaultKey] == exposure.LevelWrite {
		return true
	}
	if lvl, ok := e[ciVariablesKey]; ok && lvl != exposure.LevelNone {
		return true
	}
	for k, v := range e {
		if k == exposure.DefaultKey || k == ciVariablesKey {
			continue
		}
		if v == exposure.LevelWrite {
			return true
		}
	}
	return false
}

// InventoryPosture renders the effective ceiling as the compact scalar the
// permissions config/env accepts (e.g. "default=read,ci-variables=none"), for the
// startup connector inventory. ci-variables is always shown so the secure
// default-deny is visible.
func InventoryPosture(e exposure.Exposure) string {
	return exposure.CompactCeiling(e, ciVariablesKey)
}
