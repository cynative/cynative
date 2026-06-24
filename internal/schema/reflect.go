package schema

import "github.com/invopop/jsonschema"

// ReflectParams builds a JSON Schema for a tool's argument struct T via
// reflection. The reflector settings are chosen for LLM tool-use:
//   - AllowAdditionalProperties:false emits additionalProperties:false, which
//     strict-mode providers require.
//   - DoNotReference:true inlines definitions instead of $ref/$defs, which many
//     tool-call schema validators reject.
//   - Anonymous:true omits the auto-generated $id.
//
// Descriptions are read from `jsonschema_description:"..."` struct tags; required
// fields are derived from json tags (an omitempty field is optional). It returns
// an error to satisfy the builder seam, though invopop's Reflect never fails.
func ReflectParams[T any]() (*jsonschema.Schema, error) {
	r := jsonschema.Reflector{
		Anonymous:                 true,
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}

	return r.Reflect(*new(T)), nil
}
