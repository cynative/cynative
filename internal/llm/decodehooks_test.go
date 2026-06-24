package llm_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// mapEnv returns a llm.LookupEnv backed by m, so tests resolve "env.X"
// references hermetically without touching the process environment.
func mapEnv(m map[string]string) llm.LookupEnv {
	return func(k string) (string, bool) {
		v, ok := m[k]

		return v, ok
	}
}

func TestStringToEnvVarHookFunc_LiteralString(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(nil))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, "literal-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev, ok := got.(schemas.EnvVar)
	if !ok {
		t.Fatalf("expected schemas.EnvVar, got %T", got)
	}
	if ev.Val != "literal-key" {
		t.Errorf("Val: got %q, want literal-key", ev.Val)
	}
	if ev.FromEnv {
		t.Errorf("FromEnv: got true, want false for literal")
	}
}

func TestStringToEnvVarHookFunc_EnvReferenceSet(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(map[string]string{"HOOK_TEST_SET": "resolved"}))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, "env.HOOK_TEST_SET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev, ok := got.(schemas.EnvVar)
	if !ok {
		t.Fatalf("expected schemas.EnvVar, got %T", got)
	}
	if ev.Val != "resolved" {
		t.Errorf("Val: got %q, want resolved", ev.Val)
	}
	if !ev.FromEnv {
		t.Errorf("FromEnv: got false, want true")
	}
	if ev.EnvVar != "env.HOOK_TEST_SET" {
		t.Errorf("EnvVar: got %q, want env.HOOK_TEST_SET", ev.EnvVar)
	}
}

func TestStringToEnvVarHookFunc_EnvReferenceUnset(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(nil))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, "env.HOOK_TEST_UNSET_X")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev, ok := got.(schemas.EnvVar)
	if !ok {
		t.Fatalf("expected schemas.EnvVar, got %T", got)
	}
	if ev.Val != "" {
		t.Errorf("Val: got %q, want empty", ev.Val)
	}
	if !ev.FromEnv {
		t.Errorf("FromEnv: got false, want true (caller validates emptiness later)")
	}
}

func TestStringToEnvVarHookFunc_NonStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(nil))
	from := reflect.TypeFor[int]()
	to := reflect.TypeFor[schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("non-string source: expected passthrough, got %v", got)
	}
}

func TestStringToEnvVarHookFunc_NonEnvVarTarget_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(nil))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[string]()

	got, err := callTypeHook(hook, from, to, "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Errorf("non-EnvVar target: expected passthrough, got %v", got)
	}
}

// namedString is a named string type whose Kind() is [reflect.String] but whose
// concrete type is not string, so data.(string) returns ok=false. This
// exercises the defensive !ok guard in StringToEnvVarHookFunc and
// StringToEnvVarPtrHookFunc.
type namedString string

func TestStringToEnvVarHookFunc_NamedStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarHookFunc(mapEnv(nil))
	val := namedString("x")
	from := reflect.TypeFor[namedString]() // Kind() == reflect.String, but type is namedString
	to := reflect.TypeFor[schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, val)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != val {
		t.Errorf("named-string source: expected passthrough, got %v", got)
	}
}

func TestStringToEnvVarPtrHookFunc_Literal(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarPtrHookFunc(mapEnv(nil))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[*schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, "literal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev, ok := got.(*schemas.EnvVar)
	if !ok {
		t.Fatalf("expected *schemas.EnvVar, got %T", got)
	}
	if ev == nil || ev.Val != "literal" {
		t.Errorf("Val: got %v, want literal", ev)
	}
}

func TestStringToEnvVarPtrHookFunc_EnvReference(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarPtrHookFunc(mapEnv(map[string]string{"HOOK_PTR_TEST_SET": "ptr-resolved"}))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[*schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, "env.HOOK_PTR_TEST_SET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev, ok := got.(*schemas.EnvVar)
	if !ok {
		t.Fatalf("expected *schemas.EnvVar, got %T", got)
	}
	if ev.Val != "ptr-resolved" {
		t.Errorf("Val: got %q, want ptr-resolved", ev.Val)
	}
	if !ev.FromEnv {
		t.Errorf("FromEnv: got false, want true")
	}
}

func TestStringToEnvVarPtrHookFunc_NonStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarPtrHookFunc(mapEnv(nil))
	from := reflect.TypeFor[int]()
	to := reflect.TypeFor[*schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 7 {
		t.Errorf("non-string source: expected passthrough, got %v", got)
	}
}

func TestStringToEnvVarPtrHookFunc_NonEnvVarTarget_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarPtrHookFunc(mapEnv(nil))
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[*string]()

	got, err := callTypeHook(hook, from, to, "hi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi" {
		t.Errorf("non-EnvVar target: expected passthrough, got %v", got)
	}
}

func TestStringToEnvVarPtrHookFunc_NamedStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToEnvVarPtrHookFunc(mapEnv(nil))
	val := namedString("y")
	from := reflect.TypeFor[namedString]() // Kind() == reflect.String, but type is namedString
	to := reflect.TypeFor[*schemas.EnvVar]()

	got, err := callTypeHook(hook, from, to, val)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != val {
		t.Errorf("named-string source: expected passthrough, got %v", got)
	}
}

func TestRejectNonStringDurationHookFunc_StringPassthrough(t *testing.T) {
	t.Parallel()

	hook := llm.RejectNonStringDurationHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[time.Duration]()

	got, err := callTypeHook(hook, from, to, "500ms")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "500ms" {
		t.Errorf("expected passthrough of string source, got %v", got)
	}
}

func TestRejectNonStringDurationHookFunc_IntRejected(t *testing.T) {
	t.Parallel()

	hook := llm.RejectNonStringDurationHookFunc()
	from := reflect.TypeFor[int]()
	to := reflect.TypeFor[time.Duration]()

	_, err := callTypeHook(hook, from, to, 500)
	if err == nil {
		t.Fatal("expected error for int source to time.Duration")
	}
	if !strings.Contains(err.Error(), "duration string") {
		t.Errorf("error should mention 'duration string', got: %v", err)
	}
}

func TestRejectNonStringDurationHookFunc_NonDurationTarget_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.RejectNonStringDurationHookFunc()
	from := reflect.TypeFor[int]()
	to := reflect.TypeFor[int64]()

	got, err := callTypeHook(hook, from, to, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("non-Duration target: expected passthrough, got %v", got)
	}
}

// callTypeHook reflectively invokes a mapstructure DecodeHookFuncType.
// Hooks declared as mapstructure.DecodeHookFunc carry the underlying
// function value, so a type assertion is enough to call them.
func callTypeHook(
	hook any,
	from, to reflect.Type,
	data any,
) (any, error) {
	if fn, ok := hook.(func(reflect.Type, reflect.Type, any) (any, error)); ok {
		return fn(from, to, data)
	}
	panic("decode hook is not a recognised DecodeHookFuncType")
}

func TestStringToStringMapHookFunc_ParsesPairs(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[map[string]string]()

	got, err := callTypeHook(hook, from, to, "x-a=1, x-b = 2 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := got.(map[string]string)
	if !ok {
		t.Fatalf("expected map[string]string, got %T", got)
	}
	if m["x-a"] != "1" || m["x-b"] != "2" {
		t.Errorf("got %v, want {x-a:1, x-b:2}", m)
	}
}

func TestStringToStringMapHookFunc_EmptyString(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[map[string]string]()

	got, err := callTypeHook(hook, from, to, "  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := got.(map[string]string)
	if !ok || len(m) != 0 {
		t.Errorf("empty string should yield empty map, got %#v", got)
	}
}

func TestStringToStringMapHookFunc_Malformed(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[map[string]string]()

	_, err := callTypeHook(hook, from, to, "x-a=1,nopair")
	if !errors.Is(err, llm.ErrInvalidStringMap) {
		t.Errorf("got %v, want ErrInvalidStringMap", err)
	}
}

func TestStringToStringMapHookFunc_DuplicateKey(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[map[string]string]()

	// A duplicate key fails closed rather than silently last-wins.
	_, err := callTypeHook(hook, from, to, "x-a=1, x-a = 2")
	if !errors.Is(err, llm.ErrInvalidStringMap) {
		t.Errorf("got %v, want ErrInvalidStringMap", err)
	}
}

func TestStringToStringMapHookFunc_NonStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[map[string]string]()
	to := reflect.TypeFor[map[string]string]()

	in := map[string]string{"yaml": "map"}
	got, err := callTypeHook(hook, from, to, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := got.(map[string]string)
	if !ok || m["yaml"] != "map" {
		t.Errorf("non-string source should pass through unchanged, got %#v", got)
	}
}

func TestStringToStringMapHookFunc_NonMapTarget_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	from := reflect.TypeFor[string]()
	to := reflect.TypeFor[string]()

	got, err := callTypeHook(hook, from, to, "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Errorf("non-map target should pass through, got %v", got)
	}
}

func TestStringToStringMapHookFunc_NamedStringSource_Passthrough(t *testing.T) {
	t.Parallel()

	hook := llm.StringToStringMapHookFunc()
	val := namedString("x-a=1")
	from := reflect.TypeFor[namedString]() // Kind() == reflect.String, but type is namedString
	to := reflect.TypeFor[map[string]string]()

	got, err := callTypeHook(hook, from, to, val)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != val {
		t.Errorf("named-string source: expected passthrough, got %v", got)
	}
}
