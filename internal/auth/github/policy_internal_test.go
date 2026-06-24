package github

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

func TestExposureResolve_mostSpecific(t *testing.T) {
	t.Parallel()

	e := exposure.Exposure{
		"default":         exposure.LevelRead,
		"actions":         exposure.LevelWrite,
		"actions/secrets": exposure.LevelNone,
	}
	cases := []struct {
		cat, sub string
		want     exposure.Level
	}{
		{"actions", "secrets", exposure.LevelNone},    // C/S wins.
		{"actions", "workflows", exposure.LevelWrite}, // C wins (no C/S).
		{"issues", "labels", exposure.LevelRead},      // default wins (no C, no C/S).
	}
	for _, c := range cases {
		if got := Resolve(e, c.cat, c.sub); got != c.want {
			t.Errorf("Resolve(%q,%q) = %v, want %v", c.cat, c.sub, got, c.want)
		}
	}
}

func TestBuildExposure_overlaysGithubBaseline(t *testing.T) {
	t.Parallel()

	// The thin wrapper overlays the operator map onto the github secure baseline:
	// an explicit override wins, an invalid value is skipped, and the baseline
	// secret-scanning:none deny survives.
	e := BuildExposure(map[string]string{"issues": "write", "bogus": "nope"})
	if e["issues"] != exposure.LevelWrite {
		t.Errorf("issues = %v, want write", e["issues"])
	}
	if _, ok := e["bogus"]; ok {
		t.Errorf("invalid value should be skipped, got %v", e["bogus"])
	}
	if e["default"] != exposure.LevelRead {
		t.Errorf("default = %v, want read (baseline)", e["default"])
	}
	if e["secret-scanning"] != exposure.LevelNone {
		t.Errorf("secret-scanning = %v, want none (baseline deny)", e["secret-scanning"])
	}
}

func TestBaselineExposure_isSecureDefault(t *testing.T) {
	t.Parallel()

	e := BaselineExposure()
	if e["default"] != exposure.LevelRead {
		t.Errorf("baseline default = %v, want read", e["default"])
	}
	if e["secret-scanning"] != exposure.LevelNone {
		t.Errorf("baseline secret-scanning = %v, want none", e["secret-scanning"])
	}
}

func TestValidateExposureKeys(t *testing.T) {
	t.Parallel()

	tbl, err := DistillOpenAPI([]byte(`{"paths":{
		"/repos/{owner}/{repo}/actions/secrets": {"get": {"x-github": {"category":"actions","subcategory":"secrets"}}}
	}}`))
	if err != nil {
		t.Fatalf("distill: %v", err)
	}
	// Valid: default, secret-scanning (baseline-exempt even though tbl lacks it),
	// a real category, a real category/subcategory.
	ok := exposure.Exposure{
		"default": exposure.LevelRead, "secret-scanning": exposure.LevelNone,
		"actions": exposure.LevelWrite, "actions/secrets": exposure.LevelNone,
	}
	if okErr := ValidateExposureKeys(ok, tbl); okErr != nil {
		t.Fatalf("ValidateExposureKeys(ok) = %v, want nil", okErr)
	}
	// Typo'd narrowing key under default:write must be fatal.
	bad := exposure.Exposure{"default": exposure.LevelWrite, "actions/secret": exposure.LevelNone}
	if badErr := ValidateExposureKeys(bad, tbl); !errors.Is(badErr, ErrUnknownKey) {
		t.Fatalf("ValidateExposureKeys(bad) = %v, want ErrUnknownKey", badErr)
	}
	// Stale graphql pseudo-key is now rejected (no longer baseline-exempt).
	graphqlKey := exposure.Exposure{exposure.DefaultKey: exposure.LevelRead, "graphql": exposure.LevelRead}
	if gqlErr := ValidateExposureKeys(graphqlKey, tbl); !errors.Is(gqlErr, ErrUnknownKey) {
		t.Fatalf("ValidateExposureKeys(graphql) = %v, want ErrUnknownKey", gqlErr)
	}
}
