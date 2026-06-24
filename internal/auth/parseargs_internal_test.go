package auth

import (
	"encoding/json"
	"testing"
)

type sampleArgs struct {
	Name string `json:"name"`
}

func TestParseAuthArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		wantNil  bool
		wantErr  bool
		wantName string
	}{
		{name: "valid", raw: `{"k":{"name":"a"}}`, wantName: "a"},
		{name: "absent key", raw: `{"other":{"name":"a"}}`, wantNil: true},
		{name: "null value", raw: `{"k":null}`, wantNil: true},
		{name: "empty object", raw: `{}`, wantNil: true},
		{name: "malformed top-level", raw: `{not-json`, wantErr: true},
		{name: "empty input", raw: ``, wantErr: true},
		{name: "wrong sub-type", raw: `{"k":"string-not-object"}`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkParseAuthArgs(t, tc.raw, tc.wantNil, tc.wantErr, tc.wantName)
		})
	}
}

// checkParseAuthArgs is a helper that reduces the cognitive complexity of the
// table-driven TestParseAuthArgs loop by housing the assertion branches here.
func checkParseAuthArgs(t *testing.T, raw string, wantNil, wantErr bool, wantName string) {
	t.Helper()

	got, err := parseAuthArgs[sampleArgs](json.RawMessage(raw), "k")
	if wantErr {
		if err == nil {
			t.Fatalf("want error, got nil (result %+v)", got)
		}

		return
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wantNil {
		if got != nil {
			t.Fatalf("want nil, got %+v", got)
		}

		return
	}

	if got == nil || got.Name != wantName {
		t.Fatalf("got %+v, want name %q", got, wantName)
	}
}
