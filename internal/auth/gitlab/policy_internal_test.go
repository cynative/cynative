package gitlab

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/auth/exposure"
)

func TestExposure_Resolve_BaselineAndOverride(t *testing.T) {
	t.Parallel()
	e := BuildExposure(map[string]string{"issues": "write"})
	if got := Resolve(e, "issues"); got != exposure.LevelWrite {
		t.Errorf("issues ceiling = %v, want write", got)
	}
	if got := Resolve(e, "merge-requests"); got != exposure.LevelRead {
		t.Errorf("unlisted category = %v, want read (default)", got)
	}
	if got := Resolve(e, "ci-variables"); got != exposure.LevelNone {
		t.Errorf("ci-variables = %v, want none (baseline deny)", got)
	}
}

func TestValidateExposureKeys_Valid(t *testing.T) {
	t.Parallel()
	// Build a small table from YAML.
	yamlData := `
paths:
  /api/v4/projects:
    get:
      tags:
        - Projects
  /api/v4/projects/{id}/issues:
    get:
      tags:
        - Issues
  /api/v4/projects/{id}/variables:
    get:
      tags:
        - CI variables
`
	tbl, err := DistillOpenAPI([]byte(yamlData))
	if err != nil {
		t.Fatalf("DistillOpenAPI failed: %v", err)
	}

	// Valid override key ("issues" exists in the table).
	e := exposure.Exposure{"issues": exposure.LevelWrite, "default": exposure.LevelRead}
	if validateErr := ValidateExposureKeys(e, tbl); validateErr != nil {
		t.Errorf("ValidateExposureKeys with valid key failed: %v", validateErr)
	}
}

func TestValidateExposureKeys_UnknownKey(t *testing.T) {
	t.Parallel()
	// Build a small table from YAML.
	yamlData := `
paths:
  /api/v4/projects:
    get:
      tags:
        - Projects
`
	tbl, err := DistillOpenAPI([]byte(yamlData))
	if err != nil {
		t.Fatalf("DistillOpenAPI failed: %v", err)
	}

	// Unknown key ("bogus" does not exist in the table).
	e := exposure.Exposure{"bogus": exposure.LevelWrite, "default": exposure.LevelRead}
	err = ValidateExposureKeys(e, tbl)
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("ValidateExposureKeys with unknown key should return ErrUnknownKey, got %v", err)
	}
}

func TestValidateExposureKeys_BaselineKeysSkipped(t *testing.T) {
	t.Parallel()
	// Build a table that has NO ci-variables routes (to test the exemption).
	yamlData := `
paths:
  /api/v4/projects:
    get:
      tags:
        - Projects
`
	tbl, err := DistillOpenAPI([]byte(yamlData))
	if err != nil {
		t.Fatalf("DistillOpenAPI failed: %v", err)
	}

	// Even though "ci-variables" is not in the table, it should be valid because
	// it is a baseline-managed key.
	e := exposure.Exposure{"default": exposure.LevelRead, "ci-variables": exposure.LevelNone}
	if validateErr := ValidateExposureKeys(e, tbl); validateErr != nil {
		t.Errorf("ValidateExposureKeys should skip baseline key 'ci-variables' even if not in table: %v", validateErr)
	}
}

func TestResolve_PresentAndAbsent(t *testing.T) {
	t.Parallel()
	e := exposure.Exposure{
		"default":      exposure.LevelRead,
		"issues":       exposure.LevelWrite,
		"ci-variables": exposure.LevelNone,
	}

	// Present key.
	t.Run("Present", func(t *testing.T) {
		t.Parallel()
		if got := Resolve(e, "issues"); got != exposure.LevelWrite {
			t.Errorf("Resolve(\"issues\") = %v, want LevelWrite", got)
		}
	})

	// Absent key (falls back to default).
	t.Run("Absent", func(t *testing.T) {
		t.Parallel()
		if got := Resolve(e, "merge-requests"); got != exposure.LevelRead {
			t.Errorf("Resolve(\"merge-requests\") = %v, want LevelRead (default)", got)
		}
	})
}
