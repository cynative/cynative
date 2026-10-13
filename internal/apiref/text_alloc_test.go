package apiref_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

// cutTextBudget is the allocation budget of one StripMarkupCut call at an 8 KiB cut: the cut of "x " repeated
// splits into 4,096 fields, 64 KiB of []string.
const cutTextBudget = 256 << 10

//nolint:paralleltest // reads process-wide runtime.MemStats, so it cannot share the process with parallel tests.
func TestStripMarkupCut_AllocatesForTheCutOnly(t *testing.T) {
	s := strings.Repeat("x ", 5<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := apiref.StripMarkupCut(s, 8<<10, apiref.MaxSummary)
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > cutTextBudget {
		t.Errorf("StripMarkupCut on %d bytes allocated %d bytes, budget %d", len(s), alloc, cutTextBudget)
	} else {
		t.Logf("StripMarkupCut on %d bytes allocated %d bytes", len(s), alloc)
	}
	if !strings.HasSuffix(got, "...") || len([]rune(got)) != apiref.MaxSummary {
		t.Errorf("result %q is not a %d-rune cut ending in the ellipsis", got, apiref.MaxSummary)
	}
}
