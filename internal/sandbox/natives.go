package sandbox

import (
	"encoding/json"
	"fmt"

	mxj "github.com/clbanning/mxj/v2"
	"github.com/grafana/sobek"
	"github.com/jmespath/go-jmespath"
)

// parseXMLString converts an XML document into a generic object, analogous to
// [json.Unmarshal] into map[string]any. Leaf values stay strings (XML is
// untyped); attributes are keyed "-name" and element text "#text" (mxj
// defaults). It calls only mxj.NewMapXml with defaults — never mxj's
// package-level setters — so those defaults stay read-only and concurrent calls
// are race-safe.
func parseXMLString(s string) (any, error) {
	m, err := mxj.NewMapXml([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("sandbox: parse xml: %w", err)
	}

	return map[string]any(m), nil
}

// normalizeJSON round-trips a value through JSON so JMESPath sees the canonical
// JSON data model: sobek exports integral JS numbers as int64, but go-jmespath
// type-asserts float64 in comparisons, so an un-normalized int64 silently breaks
// numeric filters (e.g. comparing n against 30).
func normalizeJSON(data any) (any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("sandbox: normalize jmespath input: %w", err)
	}

	var v any
	err = json.Unmarshal(b, &v)

	// Re-decoding json.Marshal output cannot fail; err (always nil here) is
	// returned without an `if` so the only reachable branch stays the marshal
	// error above — keeping this helper 100%-coverable with no seam.
	return v, err
}

// jmesSearch evaluates a JMESPath expression against data, normalizing data to
// the canonical JSON model first. A no-match yields (nil, nil), which the caller
// renders as JS null.
func jmesSearch(data any, expr string) (any, error) {
	norm, err := normalizeJSON(data)
	if err != nil {
		return nil, err
	}

	result, err := jmespath.Search(expr, norm)
	if err != nil {
		return nil, fmt.Errorf("sandbox: jmespath search: %w", err)
	}

	return result, nil
}

// xmlParse backs the global xml.parse(str): it converts an XML string into a JS
// object. A missing/undefined argument or malformed XML throws a JS exception
// the script can catch.
func (s *Sandbox) xmlParse(call sobek.FunctionCall) sobek.Value {
	arg := call.Argument(0)
	if sobek.IsUndefined(arg) || sobek.IsNull(arg) {
		panic(s.vm.NewTypeError("xml.parse: expected an XML string argument"))
	}

	obj, err := parseXMLString(arg.String())
	if err != nil {
		panic(s.vm.NewGoError(err))
	}

	return s.vm.ToValue(obj)
}

// jmespathSearch backs the global jmespath.search(data, expression): it
// evaluates a JMESPath expression against a JS value. Argument order matches the
// npm jmespath package (data first). A missing expression, an unmarshalable data
// value, or an invalid expression throws a JS exception.
func (s *Sandbox) jmespathSearch(call sobek.FunctionCall) sobek.Value {
	expr := call.Argument(1)
	if sobek.IsUndefined(expr) || sobek.IsNull(expr) {
		panic(s.vm.NewTypeError("jmespath.search: expected (data, expression) arguments"))
	}

	result, err := jmesSearch(call.Argument(0).Export(), expr.String())
	if err != nil {
		panic(s.vm.NewGoError(err))
	}

	return s.vm.ToValue(result)
}
