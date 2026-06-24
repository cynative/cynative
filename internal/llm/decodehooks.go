package llm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/maximhq/bifrost/core/schemas"
)

// envVarType is the [reflect.Type] of schemas.EnvVar, cached at package init.
var envVarType = reflect.TypeFor[schemas.EnvVar]() //nolint:gochecknoglobals // cached reflect.Type

// envVarPtrType is the [reflect.Type] of *schemas.EnvVar, cached at package init.
var envVarPtrType = reflect.TypeFor[*schemas.EnvVar]() //nolint:gochecknoglobals // cached reflect.Type

// durationType is the [reflect.Type] of [time.Duration], cached at package init.
var durationType = reflect.TypeFor[time.Duration]() //nolint:gochecknoglobals // cached reflect.Type

// stringMapType is the [reflect.Type] of map[string]string, cached at package init.
var stringMapType = reflect.TypeFor[map[string]string]() //nolint:gochecknoglobals // cached reflect.Type

// StringToEnvVarHookFunc returns a mapstructure decode hook that turns a YAML
// string into a schemas.EnvVar via ResolveEnvVar. An "env.X" prefix is resolved
// through env (not the process environment): the resolved value goes in Val with
// FromEnv=true; if the variable is unset, Val is empty and ValidateEnvVars
// surfaces the error at startup.
func StringToEnvVarHookFunc(env LookupEnv) mapstructure.DecodeHookFunc {
	return func(from, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		if to != envVarType {
			return data, nil
		}
		s, ok := data.(string)
		if !ok {
			return data, nil
		}
		return ResolveEnvVar(s, env), nil
	}
}

// StringToEnvVarPtrHookFunc is the *schemas.EnvVar variant of
// StringToEnvVarHookFunc, used for pointer fields (client_id, session_token,
// CACertPEM, etc.).
func StringToEnvVarPtrHookFunc(env LookupEnv) mapstructure.DecodeHookFunc {
	return func(from, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		if to != envVarPtrType {
			return data, nil
		}
		s, ok := data.(string)
		if !ok {
			return data, nil
		}
		ev := ResolveEnvVar(s, env)

		return &ev, nil
	}
}

// RejectNonStringDurationHookFunc returns a mapstructure decode hook that
// errors when a non-string source is decoded into a [time.Duration] target.
// Without this hook, mapstructure's WeaklyTypedInput would silently coerce a
// YAML int into a Duration of nanoseconds (e.g. retry_backoff_initial: 500
// becomes 500ns instead of 500ms). With this hook in place, callers get a
// clear "use a duration string" error.
//
// Compose this hook BEFORE mapstructure.StringToTimeDurationHookFunc so the
// rejection fires on the original int source rather than on a post-conversion
// Duration value.
func RejectNonStringDurationHookFunc() mapstructure.DecodeHookFunc {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != durationType {
			return data, nil
		}
		if from.Kind() == reflect.String {
			return data, nil
		}
		return nil, fmt.Errorf(
			"expected a duration string like \"500ms\" for time.Duration field, got %s",
			from.Kind(),
		)
	}
}

// ErrInvalidStringMap is returned when a compact string-map env value (e.g.
// CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS) is not
// in the documented comma-separated "key=value" form.
var ErrInvalidStringMap = errors.New(`invalid map value: expected comma-separated "key=value" pairs`)

// StringToStringMapHookFunc returns a mapstructure decode hook that parses the
// documented "k=v,k2=v2" form into a map[string]string. It fires only for a
// string source decoded into a map[string]string target, so YAML maps (a map
// source) pass through untouched. This is what makes the compact CYNATIVE_*
// form of every map[string]string field work (e.g.
// CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS): the env value arrives as a single
// string and is split here.
func StringToStringMapHookFunc() mapstructure.DecodeHookFunc {
	return func(from, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		if to != stringMapType {
			return data, nil
		}
		s, ok := data.(string)
		if !ok {
			return data, nil
		}

		return parseStringMap(s)
	}
}

// parseStringMap splits "k=v,k2=v2" into a map, trimming spaces around each key
// and value. An empty (or whitespace-only) string yields an empty map; an item
// without "=" returns ErrInvalidStringMap. A duplicate key also returns
// ErrInvalidStringMap rather than silently last-wins, so an accidental dup (which
// for the github permissions ceiling could silently widen access) fails closed.
func parseStringMap(s string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for pair := range strings.SplitSeq(s, ",") {
		k, v, found := strings.Cut(pair, "=")
		if !found {
			return nil, fmt.Errorf("%w: %q is not a key=value pair", ErrInvalidStringMap, pair)
		}
		key := strings.TrimSpace(k)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrInvalidStringMap, key)
		}
		out[key] = strings.TrimSpace(v)
	}

	return out, nil
}
