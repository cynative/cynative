package llm

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// ValidateEnvVars walks the given ProviderEntry and returns ErrEnvVarUnset
// for any schemas.EnvVar (or *schemas.EnvVar) whose FromEnv is true but
// whose Val is empty — meaning the referenced env var was unset (or set to
// the empty string) at startup. Discovery is purely type-based, so new
// Bifrost fields that carry env-var references are validated without
// per-field updates.
func ValidateEnvVars(entry *ProviderEntry) error {
	return walkEnvVars(reflect.ValueOf(entry))
}

func walkEnvVars(
	v reflect.Value,
) error { //nolint:exhaustive // reflect.Kind has many scalar values; default covers all non-container kinds
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return walkEnvVars(v.Elem())
	case reflect.Struct:
		return walkStruct(v)
	case reflect.Slice, reflect.Array:
		return walkSequence(v)
	case reflect.Map:
		return walkMap(v)
	default:
		return nil
	}
}

// walkStruct walks a struct value: if it is a schemas.EnvVar it validates it
// directly; otherwise it recurses into each exported field.
func walkStruct(v reflect.Value) error {
	if v.Type() == envVarType {
		return checkEnvVar(v)
	}
	for _, f := range v.Fields() {
		if !f.CanInterface() {
			continue
		}
		if err := walkEnvVars(f); err != nil {
			return err
		}
	}
	return nil
}

// checkEnvVar validates a single schemas.EnvVar value.
func checkEnvVar(v reflect.Value) error {
	ev := v.Interface().(schemas.EnvVar) //nolint:forcetypeassert,errcheck // envVarType equality above guarantees this assertion succeeds.
	if ev.FromEnv && ev.Val == "" {
		name := strings.TrimPrefix(ev.EnvVar, "env.")
		return fmt.Errorf("%w: %s", ErrEnvVarUnset, name)
	}
	return nil
}

// walkSequence recurses into each element of a slice or array.
func walkSequence(v reflect.Value) error {
	for i := range v.Len() {
		if err := walkEnvVars(v.Index(i)); err != nil {
			return err
		}
	}
	return nil
}

// walkMap recurses into each value of a map.
func walkMap(v reflect.Value) error {
	iter := v.MapRange()
	for iter.Next() {
		if err := walkEnvVars(iter.Value()); err != nil {
			return err
		}
	}
	return nil
}
