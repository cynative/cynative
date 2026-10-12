package azure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

// structuralMissError marks a classifier denial whose path names no resource the gate's catalog knows, the case
// where api_reference can show the operation's real path. Its text is the wrapped error's; Provider.AuthorizeAction
// adds the pointer, so a caller that classifies directly (the api_reference gate check) gets the bare text.
type structuralMissError struct {
	namespace string
	err       error
}

func (e *structuralMissError) Error() string { return e.err.Error() }
func (e *structuralMissError) Unwrap() error { return e.err }

// withReferencePointer appends the api_reference pointer to a structural miss and returns any other error as is.
func withReferencePointer(err error) error {
	var miss *structuralMissError
	if !errors.As(err, &miss) {
		return err
	}

	return fmt.Errorf("%w. %s", err, referencePointer(miss.namespace))
}

// referencePointer is the sentence that sends the model to api_reference. The namespace is truncated, then JSON
// encoded, so its echo is bounded and escaped before the sentence ends.
func referencePointer(namespace string) string {
	lookup := map[string]string{
		"connector": "azure",
		"operation": "<OperationId>",
		"service":   apiref.Truncate(namespace, apiref.MaxChoice),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(lookup) // A string map always encodes.

	return "For an operation's request template call api_reference with " +
		strings.TrimSuffix(buf.String(), "\n") + "."
}
