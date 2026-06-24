package sandbox

import (
	"errors"
	"testing"
)

func TestRegisterAll_SetsEveryEntry(t *testing.T) {
	t.Parallel()

	got := map[string]any{}
	set := func(name string, value any) error {
		got[name] = value
		return nil
	}

	err := registerAll(set, map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatalf("registerAll = %v, want nil", err)
	}
	if len(got) != 2 || got["a"] != 1 || got["b"] != 2 {
		t.Errorf("registered = %v, want {a:1, b:2}", got)
	}
}

func TestRegisterAll_WrapsSetterError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("set failed")
	set := func(_ string, _ any) error { return sentinel }

	err := registerAll(set, map[string]any{"only": 1})
	if !errors.Is(err, sentinel) {
		t.Errorf("registerAll error = %v, want wrapping %v", err, sentinel)
	}
}
