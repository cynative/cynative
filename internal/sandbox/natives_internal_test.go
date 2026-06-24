package sandbox

import (
	"encoding/json"
	"testing"
)

func TestParseXMLString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want string // JSON form of the parsed object (json.Marshal sorts keys).
	}{
		{"attributes and text", `<a x="1"><b>hi</b></a>`, `{"a":{"-x":"1","b":"hi"}}`},
		{"repeated elements become an array", `<r><i>1</i><i>2</i></r>`, `{"r":{"i":["1","2"]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseXMLString(tt.xml)
			if err != nil {
				t.Fatalf("parseXMLString(%q): %v", tt.xml, err)
			}

			if js := mustJSONNatives(t, got); js != tt.want {
				t.Errorf("got %s, want %s", js, tt.want)
			}
		})
	}
}

func TestParseXMLString_Malformed(t *testing.T) {
	t.Parallel()

	if _, err := parseXMLString(`<a>`); err == nil {
		t.Fatal("expected an error for malformed XML, got nil")
	}
}

func TestNormalizeJSON_IntToFloat(t *testing.T) {
	t.Parallel()

	got, err := normalizeJSON(map[string]any{"n": int64(5)})
	if err != nil {
		t.Fatalf("normalizeJSON: %v", err)
	}

	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want map[string]any", got)
	}

	if _, isFloat := m["n"].(float64); !isFloat {
		t.Errorf("n is %T, want float64 (canonical JSON number)", m["n"])
	}
}

func TestNormalizeJSON_MarshalError(t *testing.T) {
	t.Parallel()

	cyclic := map[string]any{}
	cyclic["self"] = cyclic

	if _, err := normalizeJSON(cyclic); err == nil {
		t.Fatal("expected a marshal error for a cyclic value, got nil")
	}
}

func TestJmesSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data any
		expr string
		want string // JSON form of the result.
	}{
		{
			name: "nested key",
			data: map[string]any{"a": map[string]any{"b": int64(2)}},
			expr: "a.b",
			want: "2",
		},
		{
			name: "numeric filter survives int normalization",
			data: []any{map[string]any{"n": int64(1)}, map[string]any{"n": int64(50)}},
			expr: "[?n > `30`].n",
			want: "[50]",
		},
		{
			name: "no match yields null",
			data: map[string]any{"a": int64(1)},
			expr: "b",
			want: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := jmesSearch(tt.data, tt.expr)
			if err != nil {
				t.Fatalf("jmesSearch: %v", err)
			}

			if js := mustJSONNatives(t, got); js != tt.want {
				t.Errorf("got %s, want %s", js, tt.want)
			}
		})
	}
}

func TestJmesSearch_InvalidExpression(t *testing.T) {
	t.Parallel()

	if _, err := jmesSearch(map[string]any{"a": int64(1)}, "[0"); err == nil {
		t.Fatal("expected an error for an invalid JMESPath expression, got nil")
	}
}

func TestJmesSearch_NormalizeError(t *testing.T) {
	t.Parallel()

	cyclic := map[string]any{}
	cyclic["self"] = cyclic

	if _, err := jmesSearch(cyclic, "self"); err == nil {
		t.Fatal("expected a normalization error for a cyclic value, got nil")
	}
}

func mustJSONNatives(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	return string(b)
}
