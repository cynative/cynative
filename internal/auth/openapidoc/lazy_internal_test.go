package openapidoc

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

// eagerParam and eagerConvert are the parameter decoder this package used before parameters decoded lazily: every
// field but $ref decoded into any, a schema into a tree of Go maps. The oracle below holds the lazy decoder to it.
type eagerParam struct {
	Ref         string `json:"$ref"`
	Name        any    `json:"name"`
	In          any    `json:"in"`
	Required    any    `json:"required"`
	Description any    `json:"description"`
	Schema      any    `json:"schema"`
}

func eagerText(v any) string {
	s, _ := v.(string)
	return s
}

func eagerSchemaType(schema any) any {
	m, _ := schema.(map[string]any)
	return m["type"]
}

func eagerType(schema any, union bool) string {
	if s := eagerText(eagerSchemaType(schema)); s != "" {
		return s
	}
	m, _ := schema.(map[string]any)
	alts, _ := m["oneOf"].([]any)
	types := make([]string, 0, len(alts))
	for _, alt := range alts {
		types = append(types, eagerText(eagerSchemaType(alt)))
	}
	slices.Sort(types)
	if union && slices.Equal(types, []string{"integer", stringType}) {
		return stringType
	}
	return unknownType
}

func eagerConvert(p eagerParam, union bool) DocParam {
	return DocParam{
		Name:        eagerText(p.Name),
		In:          eagerText(p.In),
		Type:        eagerType(p.Schema, union),
		Required:    p.Required == true,
		Description: apiref.StripMarkup(eagerText(p.Description), apiref.MaxInputDescription),
	}
}

// oracleParams are parameter objects with case-variant keys, repeated keys, and non-string, non-object and
// malformed values, every shape the two decoders could disagree on.
func oracleParams() []string {
	values := []string{`"s"`, `5`, `true`, `false`, `null`, `[]`, `{}`, `"true"`, `["x"]`, `{"a":1}`}
	params := []string{
		`{}`,
		`{"NAME":"n","IN":"query","Required":true,"DESCRIPTION":"<b>d</b>","SCHEMA":{"type":"string"}}`,
		`{"name":"a","name":"b","in":"path","in":"query"}`,
		`{"name":"n","Name":"m","nAmE":"o"}`,
		`{"required": true }`, `{"required":1}`, `{"required":"yes"}`,
		`{"schema":{"Type":"string"}}`, `{"schema":{"type":"string","Type":"integer"}}`,
		`{"schema":{"type":"string","type":"integer"}}`, `{"schema":{"type":["string"]}}`,
		`{"schema":"string"}`, `{"schema":[{"type":"string"}]}`, `{"schema":5}`,
		`{"schema":{"oneOf":[{"type":"string"},{"type":"integer"}]}}`,
		`{"schema":{"oneOf":[{"type":"integer"},{"type":"string"}],"OneOf":[]}}`,
		`{"schema":{"OneOf":[{"type":"string"},{"type":"integer"}]}}`,
		`{"schema":{"oneOf":[{"Type":"string"},{"type":"integer"}]}}`,
		`{"schema":{"oneOf":[{"type":"string"},"integer"]}}`, `{"schema":{"oneOf":{"type":"string"}}}`,
		`{"schema":{"oneOf":[{"type":"string"},{"type":"integer"}],"oneOf":[{"type":"string"}]}}`,
		`{"schema":{"type":"","oneOf":[{"type":"string"},{"type":"integer"}]}}`,
		`{"description":"a &amp; <i>b</i>\n c"}`, `{"description":"<p>x"}`,
	}
	for _, field := range []string{"name", "in", "required", "description", "schema"} {
		for _, v := range values {
			params = append(params, fmt.Sprintf(`{%q:%s}`, field, v))
		}
	}
	return params
}

func TestLazyParams_MatchTheEagerDecode(t *testing.T) {
	t.Parallel()
	for _, raw := range oracleParams() {
		var eager eagerParam
		var lazy rawParam
		if err := json.Unmarshal([]byte(raw), &eager); err != nil {
			t.Fatalf("eager %s: %v", raw, err)
		}
		if err := json.Unmarshal([]byte(raw), &lazy); err != nil {
			t.Fatalf("lazy %s: %v", raw, err)
		}
		for _, union := range []bool{false, true} {
			d := &distiller{prof: &Profile{ScalarUnion: union}}
			if got, want := d.param(lazy), eagerConvert(eager, union); got != want {
				t.Errorf("%s (union %v): lazy %+v, eager %+v", raw, union, got, want)
			}
		}
	}
}

func TestParams_AComponentIsConvertedOnce(t *testing.T) {
	t.Parallel()
	doc := &rawDoc{}
	doc.Components.Parameters = map[string]rawParam{"p": {Name: json.RawMessage(`"p"`)}}
	d := &distiller{doc: doc, prof: &Profile{}, components: map[string]DocParam{}}
	refs := []rawParam{
		{Ref: paramRefPrefix + "p"},
		{Ref: paramRefPrefix + "p"},
		{Ref: paramRefPrefix + "missing"},
		{Ref: "#/components/schemas/p"},
	}
	if got := d.params(refs); len(got) != 2 || got[0].Name != "p" || got[1].Name != "p" {
		t.Fatalf("params = %+v", got)
	}
	// A converted entry is reused: changing the raw component afterwards does not change what a reference gets.
	doc.Components.Parameters["p"] = rawParam{Name: json.RawMessage(`"changed"`)}
	if got := d.params(refs[:1]); got[0].Name != "p" {
		t.Fatalf("component converted again: %+v", got)
	}
}
