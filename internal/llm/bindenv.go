package llm

import (
	"reflect"
	"slices"
	"strings"
)

// ProviderEnvKeys returns the dotted Viper key path for every bindable leaf of
// ProviderEntry, prefixed with "llm". config.Load enumerates these keys to map
// each CYNATIVE_LLM_* environment variable onto its config field. Discovery is
// purely type-based (it mirrors ValidateEnvVars's walker), so new Bifrost fields
// are exposed without per-field updates — including rarely-used internal knobs
// (proxy and custom-provider fields) that are harmless to expose. Slices and
// maps have no discrete-env form and are skipped here.
func ProviderEnvKeys() []string {
	var keys []string
	collectEnvKeys(reflect.TypeFor[ProviderEntry](), "llm", &keys)

	return keys
}

// collectEnvKeys appends the key path of each bindable leaf reachable from t.
func collectEnvKeys(t reflect.Type, prefix string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t == envVarType {
		*out = append(*out, prefix)

		return
	}

	switch t.Kind() { //nolint:exhaustive // only Struct is recursed; containers skip; default binds scalars
	case reflect.Struct:
		collectStructEnvKeys(t, prefix, out)
	case reflect.Slice, reflect.Array, reflect.Map, reflect.Interface, reflect.Chan, reflect.Func:
		// Not representable as discrete env vars; skip.
	default:
		*out = append(*out, prefix)
	}
}

// collectStructEnvKeys recurses into each exported field of a struct, building
// dotted json-tag paths and flattening squash-embedded structs.
func collectStructEnvKeys(t reflect.Type, prefix string, out *[]string) {
	for field := range t.Fields() {
		if field.PkgPath != "" { // unexported.
			continue
		}
		name, squash, skip := jsonFieldName(field)
		if skip {
			continue
		}
		child := prefix
		if !squash {
			child = prefix + "." + name
		}
		collectEnvKeys(field.Type, child, out)
	}
}

// jsonFieldName extracts the path segment from a field's json tag, returning
// (name, squash, skip): skip=true for `json:"-"`; squash=true for a `,squash`
// embed (flattened with no segment); otherwise the tag name (falling back to
// the Go field name when the tag has no name).
func jsonFieldName(field reflect.StructField) (string, bool, bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	if slices.Contains(parts[1:], "squash") {
		return "", true, false
	}
	name := parts[0]
	if name == "" {
		name = field.Name
	}

	return name, false, false
}
