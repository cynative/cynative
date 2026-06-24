package llm

import (
	"reflect"
	"slices"
	"testing"
)

// hasUnexported exercises the field.PkgPath != "" skip branch.
type hasUnexported struct {
	Exported   string `json:"exported"`
	unexported string //nolint:unused // present only to exercise the unexported-field skip
}

func TestCollectEnvKeys_SkipsUnexported(t *testing.T) {
	t.Parallel()

	var keys []string
	collectEnvKeys(reflect.TypeFor[hasUnexported](), "x", &keys)

	if !slices.Contains(keys, "x.exported") {
		t.Errorf("expected x.exported, got %v", keys)
	}
	if slices.Contains(keys, "x.unexported") {
		t.Errorf("unexported field should be skipped, got %v", keys)
	}
}

// noJSONTag exercises the empty-name fallback to the Go field name.
type noJSONTag struct {
	Plain string
}

func TestJSONFieldName_FallsBackToGoName(t *testing.T) {
	t.Parallel()

	field := reflect.TypeFor[noJSONTag]().Field(0)
	name, squash, skip := jsonFieldName(field)
	if name != "Plain" || squash || skip {
		t.Errorf("got (%q, %v, %v), want (Plain, false, false)", name, squash, skip)
	}
}
