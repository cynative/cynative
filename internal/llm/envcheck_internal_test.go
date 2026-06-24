package llm

import (
	"errors"
	"reflect"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// structWithUnexported has an unexported field to exercise the !f.CanInterface() branch.
type structWithUnexported struct {
	unexported string
}

func TestWalkEnvVars_SkipsUnexportedFields(t *testing.T) {
	t.Parallel()

	v := reflect.ValueOf(structWithUnexported{unexported: "hidden"})
	if err := walkEnvVars(v); err != nil {
		t.Errorf("expected nil for struct with only unexported fields, got: %v", err)
	}
}

// TestWalkMap_PopulatedMap exercises the iter.Next() true branch of walkMap.
// The map values are plain strings, so checkEnvVar is never reached, but the
// loop body runs at least once.
func TestWalkMap_PopulatedMap(t *testing.T) {
	t.Parallel()

	m := map[string]string{"k": "v"}
	if err := walkEnvVars(reflect.ValueOf(m)); err != nil {
		t.Errorf("expected nil for map[string]string, got: %v", err)
	}
}

// TestWalkMap_PropagatesError exercises the error-return branch of walkMap by
// constructing a map whose value is a schemas.EnvVar with FromEnv=true and an
// empty Val — walkMap should surface ErrEnvVarUnset.
func TestWalkMap_PropagatesError(t *testing.T) {
	t.Parallel()

	m := map[string]schemas.EnvVar{
		"k": {Val: "", FromEnv: true, EnvVar: "env.UNSET_MAP_VAL"},
	}
	err := walkEnvVars(reflect.ValueOf(m))
	if !errors.Is(err, ErrEnvVarUnset) {
		t.Errorf("got %v, want ErrEnvVarUnset", err)
	}
}
