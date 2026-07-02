package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/schema"
)

type reflectArgs struct {
	Method string `json:"method"         jsonschema:"enum=GET,enum=POST" jsonschema_description:"HTTP method, one of GET, POST."`
	URL    string `json:"url"                                            jsonschema_description:"Full URL."`
	Note   string `json:"note,omitempty"                                 jsonschema_description:"Optional note."`
}

func TestReflectParams_Shape(t *testing.T) {
	t.Parallel()

	s := schema.ReflectParams[reflectArgs]()
	if s.Type != "object" {
		t.Errorf("type = %q, want object", s.Type)
	}
	if s.AdditionalProperties == nil {
		t.Error("expected additionalProperties to be set (the false schema)")
	}

	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	if !req["method"] || !req["url"] {
		t.Errorf("required = %v, want method+url", s.Required)
	}
	if req["note"] {
		t.Errorf("note (omitempty) should not be required: %v", s.Required)
	}

	// Description survives despite the comma in the value.
	prop, ok := s.Properties.Get("method")
	if !ok {
		t.Fatal("method property missing")
	}
	if prop.Description != "HTTP method, one of GET, POST." {
		t.Errorf("method description = %q", prop.Description)
	}

	// Sanity: marshals to JSON with additionalProperties:false.
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"additionalProperties":false`) {
		t.Errorf("marshaled schema missing additionalProperties:false: %s", b)
	}
}
