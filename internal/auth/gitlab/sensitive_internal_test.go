package gitlab

import (
	"errors"
	"testing"
)

// TestAdmitTable_RejectsPoisonedVariablesDowngrade asserts the strict admission
// form rejects a (cache-poisoned) table that maps a variables-segment template to
// a non-ci-variables category. The poisoned table is built via UnmarshalTable of a
// hand-crafted blob (DistillOpenAPI itself would force ci-variables, so the only
// way to reach a downgrade is a tampered cached blob).
func TestAdmitTable_RejectsPoisonedVariablesDowngrade(t *testing.T) {
	t.Parallel()
	poisoned := []byte(`{"m":{"GET":[{"p":["api","v4","projects","{id}","variables"],"r":{"c":"projects"}}]}}`)
	tbl, err := UnmarshalTable(poisoned)
	if err != nil {
		t.Fatalf("UnmarshalTable(poisoned) = %v, want nil", err)
	}
	if admitErr := AdmitTable(tbl); !errors.Is(admitErr, ErrTableRejected) {
		t.Errorf("AdmitTable(poisoned) = %v, want ErrTableRejected", admitErr)
	}
}

// TestAdmitTable_AllowsCleanVariablesTable asserts a clean table — a
// variables-segment template that maps to ci-variables (as DistillOpenAPI forces)
// — passes admission.
func TestAdmitTable_AllowsCleanVariablesTable(t *testing.T) {
	t.Parallel()
	good := []byte(
		"openapi: \"3.0.0\"\npaths:\n  /api/v4/projects/{id}/variables:\n    get:\n      tags: [\"CI variables\"]\n",
	)
	tbl, _ := DistillOpenAPI(good)
	if err := AdmitTable(tbl); err != nil {
		t.Errorf("AdmitTable(clean variables) = %v, want nil", err)
	}
}

// TestAdmitTable_AllowsScatterForcedToCIVariables asserts a variables template
// that GitLab tags as a scatter category (Pipelines) still passes admission,
// because DistillOpenAPI forces it to ci-variables.
func TestAdmitTable_AllowsScatterForcedToCIVariables(t *testing.T) {
	t.Parallel()
	raw := []byte(
		"openapi: \"3.0.0\"\npaths:\n  /api/v4/projects/{id}/pipelines/{pid}/variables:\n    get:\n" +
			"      tags: [\"Pipelines\"]\n",
	)
	tbl, _ := DistillOpenAPI(raw)
	if err := AdmitTable(tbl); err != nil {
		t.Errorf("AdmitTable(scatter forced to ci-variables) = %v, want nil", err)
	}
}

func TestAdmitTable_AllowsCleanTableWithoutVariables(t *testing.T) {
	t.Parallel()
	raw := []byte("openapi: \"3.0.0\"\npaths:\n  /api/v4/projects/{id}/issues:\n    get:\n      tags: [\"Issues\"]\n")
	tbl, _ := DistillOpenAPI(raw)
	if err := AdmitTable(tbl); err != nil {
		t.Errorf("AdmitTable(clean) = %v, want nil", err)
	}
}

func TestHasVariablesSegment(t *testing.T) {
	t.Parallel()
	if !hasVariablesSegment([]string{"projects", "1", "variables"}) {
		t.Errorf("hasVariablesSegment(has variables) = false, want true")
	}
	if hasVariablesSegment([]string{"projects", "1", "issues"}) {
		t.Errorf("hasVariablesSegment(no variables) = true, want false")
	}
}
