package gitlab

import (
	"strings"
	"testing"
)

func TestPostureLoud(t *testing.T) {
	t.Parallel()
	if PostureLoud(BaselineExposure()) {
		t.Error("baseline should be quiet")
	}
	if !PostureLoud(BuildExposure(map[string]string{"default": "write"})) {
		t.Error("default=write should be loud")
	}
	if !PostureLoud(BuildExposure(map[string]string{"ci-variables": "read"})) {
		t.Error("opening ci-variables should be loud")
	}
	if !PostureLoud(BuildExposure(map[string]string{"issues": "write"})) {
		t.Error("a write override should be loud")
	}
}

func TestPostureLoud_ReadOverrideQuiet(t *testing.T) {
	t.Parallel()
	if PostureLoud(BuildExposure(map[string]string{"issues": "read"})) {
		t.Error("a read override should be quiet")
	}
}

func TestInventoryPosture(t *testing.T) {
	t.Parallel()
	got := InventoryPosture(BaselineExposure())
	for _, marker := range []string{"default=read", "ci-variables=none"} {
		if !strings.Contains(got, marker) {
			t.Errorf("baseline inventory posture missing %q: %q", marker, got)
		}
	}
	if strings.Contains(got, "gitlab_hardening:") || strings.Contains(got, "⚠️") {
		t.Errorf("inventory posture must be the bare scalar: %q", got)
	}
}
