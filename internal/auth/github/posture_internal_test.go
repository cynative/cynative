package github

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

func TestLevelName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		level exposure.Level
		want  string
	}{
		{exposure.LevelNone, "none"},
		{exposure.LevelRead, "read"},
		{exposure.LevelWrite, "write"},
	}
	for _, c := range cases {
		if got := exposure.LevelName(c.level); got != c.want {
			t.Errorf("LevelName(%v) = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestPostureLoud(t *testing.T) {
	t.Parallel()

	merge := func(e exposure.Exposure) exposure.Exposure { return exposure.MergeExposure(BaselineExposure(), e) }

	cases := []struct {
		name string
		e    exposure.Exposure
		want bool
	}{
		{"baseline read-only", BaselineExposure(), false},
		{"default write", merge(exposure.Exposure{"default": exposure.LevelWrite}), true},
		{"secret-scanning opened read", merge(exposure.Exposure{"secret-scanning": exposure.LevelRead}), true},
		{"category write override", merge(exposure.Exposure{"issues": exposure.LevelWrite}), true},
		{"narrowing override only", merge(exposure.Exposure{"actions/secrets": exposure.LevelNone}), false},
		{"category read override only", merge(exposure.Exposure{"issues": exposure.LevelRead}), false},
	}
	for _, c := range cases {
		if got := PostureLoud(c.e); got != c.want {
			t.Errorf("PostureLoud(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSecretScanningOpened covers the secretScanningOpened helper directly.
func TestSecretScanningOpened(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		e    exposure.Exposure
		want bool
	}{
		{"baseline (secret-scanning:none)", BaselineExposure(), false},
		{
			"top-level read",
			exposure.MergeExposure(BaselineExposure(), exposure.Exposure{"secret-scanning": exposure.LevelRead}),
			true,
		},
		{
			"top-level write",
			exposure.MergeExposure(BaselineExposure(), exposure.Exposure{"secret-scanning": exposure.LevelWrite}),
			true,
		},
		{
			"subcategory read",
			exposure.MergeExposure(
				BaselineExposure(),
				exposure.Exposure{"secret-scanning/secret-scanning": exposure.LevelRead},
			),
			true,
		},
		{
			"subcategory none stays closed",
			exposure.MergeExposure(BaselineExposure(), exposure.Exposure{"secret-scanning/alerts": exposure.LevelNone}),
			false,
		},
		{
			"unrelated key only",
			exposure.MergeExposure(BaselineExposure(), exposure.Exposure{"issues": exposure.LevelRead}),
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := secretScanningOpened(c.e); got != c.want {
				t.Errorf("secretScanningOpened(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestPostureLoud_subcategorySecretScanning verifies that PostureLoud is true
// when a secret-scanning subcategory key opens access.
func TestPostureLoud_subcategorySecretScanning(t *testing.T) {
	t.Parallel()

	e := exposure.MergeExposure(
		BaselineExposure(),
		exposure.Exposure{"secret-scanning/secret-scanning": exposure.LevelRead},
	)
	if !PostureLoud(e) {
		t.Errorf("PostureLoud must be true when secret-scanning subcategory is opened")
	}
}

func TestInventoryPosture(t *testing.T) {
	t.Parallel()
	got := InventoryPosture(BaselineExposure())
	for _, marker := range []string{"default=read", "secret-scanning=none"} {
		if !strings.Contains(got, marker) {
			t.Errorf("baseline inventory posture missing %q: %q", marker, got)
		}
	}
	if strings.Contains(got, "github_hardening:") || strings.Contains(got, "⚠️") {
		t.Errorf("inventory posture must be the bare scalar: %q", got)
	}
	open := InventoryPosture(
		exposure.MergeExposure(BaselineExposure(), exposure.Exposure{"issues": exposure.LevelWrite}),
	)
	if !strings.Contains(open, "issues=write") {
		t.Errorf("override must appear: %q", open)
	}
}
