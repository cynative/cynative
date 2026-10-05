package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/schema"
)

// The tool is not exposed inside code_execution, so it implements Run only.
var _ schema.InvokableTool = (*apiReferenceTool)(nil)

const apiReferenceDescription = "Look up one connector API operation by exact name and get its protocol, inputs, " +
	"an http_request template with <placeholders>, response parsing and pagination. Read-only; sends nothing " +
	"to the connector. Supported: aws (restXml, restJson1, awsQuery, awsJson) and github."

const (
	apiReferenceNote = "Replace every <placeholder>; percent-encode query and form values " +
		"(encodeURIComponent), encode a path value segment by segment and keep the '/' between segments, " +
		"and in a JSON body replace a quoted string placeholder, quotes included, with JSON.stringify(value) and " +
		"give numbers and booleans as bare JSON values. Pagination fields name model members: send each one " +
		"under the wire_name and location its entry in inputs gives. <Name:unrendered> marks an input this " +
		"reference could not render. Check outcome and gaps even when no marker appears."
	budgetLimitation = "reference exceeds the output budget"
	// maxMinimalField bounds each identifier echoed in the minimal output.
	maxMinimalField = 200
)

type apiReferenceArgs struct {
	Connector string `json:"connector"         jsonschema_description:"Connector name, e.g. 'aws' or 'github'."`
	Service   string `json:"service,omitempty" jsonschema_description:"AWS only: the endpoint prefix from the request host, e.g. 'route53' or 'iam'."`                                                  //nolint:lll // struct tags are indivisible
	Model     string `json:"model,omitempty"   jsonschema_description:"AWS only: the model directory, to choose between models sharing an endpoint prefix (from an ambiguous result's choices)."`       //nolint:lll // struct tags are indivisible
	Operation string `json:"operation"         jsonschema_description:"Exact operation name: the Smithy name for AWS (e.g. 'ListHostedZones'), the OpenAPI operationId for GitHub (e.g. 'repos/get')."` //nolint:lll // struct tags are indivisible
}

type referenceOutput struct {
	Outcome         apiref.Outcome    `json:"outcome"`
	Reason          string            `json:"reason,omitempty"`
	Choices         []string          `json:"choices,omitempty"`
	Reference       *apiref.Reference `json:"reference,omitempty"`
	RequestTemplate map[string]any    `json:"request_template,omitempty"`
	Note            string            `json:"note,omitempty"`
}

type minimalOutput struct {
	Outcome     apiref.Outcome `json:"outcome"`
	Connector   string         `json:"connector"`
	Service     string         `json:"service,omitempty"`
	Operation   string         `json:"operation"`
	Limitations []string       `json:"limitations"`
}

type apiReferenceTool struct {
	info      *schema.ToolInfo
	providers []auth.Provider
}

// NewAPIReferenceTool builds the api_reference tool over the session's providers.
func NewAPIReferenceTool(providers []auth.Provider) schema.InvokableTool {
	return &apiReferenceTool{
		info: &schema.ToolInfo{
			Name:   "api_reference",
			Desc:   apiReferenceDescription,
			Params: schema.ReflectParams[apiReferenceArgs](),
		},
		providers: providers,
	}
}

// Info returns the tool's schema.
// UngatedIO marks the tool as an I/O tool registered without the approval
// decorator, so the agent audits it as ungated with redacted arguments.
func (t *apiReferenceTool) UngatedIO() {}

func (t *apiReferenceTool) Info() *schema.ToolInfo { return t.info }

// Run looks up the operation. Every outcome is a result string, never a Go error.
func (t *apiReferenceTool) Run(ctx context.Context, argumentsInJSON string) (string, error) {
	var args apiReferenceArgs
	if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
		return rejected(ctx, "invalid arguments: "+err.Error()), nil //nolint:nilerr // a result, not a Go error.
	}
	if args.Operation == "" {
		return rejected(ctx, "operation is required"), nil
	}
	res := auth.LookupReference(ctx, t.providers, apiref.Query{
		Connector: args.Connector, Service: args.Service, Model: args.Model, Operation: args.Operation,
	})
	if res.Outcome == apiref.OutcomeFound || res.Outcome == apiref.OutcomeIncomplete {
		audit.MarkProgress(ctx)
	} else {
		audit.MarkFailed(ctx)
	}
	out := referenceOutput{Outcome: res.Outcome, Reason: res.Reason, Choices: res.Choices, Reference: res.Reference}
	if res.Reference != nil {
		out.RequestTemplate = buildTemplate(res.Reference)
		out.Note = apiReferenceNote
	}

	return capped(out), nil
}

func rejected(ctx context.Context, reason string) string {
	audit.MarkFailed(ctx)

	return capped(referenceOutput{Outcome: apiref.OutcomeNotFound, Reason: reason})
}

// encode renders v without HTML escaping so <placeholders> stay readable.
func encode(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// The output structs hold only strings, bools, slices and string-keyed maps, so Encode cannot fail.
	_ = enc.Encode(v)

	return strings.TrimSuffix(buf.String(), "\n")
}

// capped bounds the output: text fields first, then progressively less of the reference, then a minimal answer.
func capped(out referenceOutput) string {
	out.Reason = apiref.Truncate(out.Reason, apiref.MaxReason)
	if len(out.Choices) > 0 {
		out.Choices = apiref.Choices(out.Choices)
	}
	s := encode(out)
	if len(s) <= apiref.MaxOutputBytes || out.Reference == nil {
		return s
	}
	ref := *out.Reference
	kept := slices.DeleteFunc(slices.Clone(ref.Inputs), func(in apiref.Input) bool { return !in.Required })
	ref.InputsTruncated = ref.InputsTruncated || len(kept) < len(ref.Inputs)
	ref.Inputs = kept
	out.Reference = &ref
	if s = encode(out); len(s) <= apiref.MaxOutputBytes {
		return s
	}
	for i := range ref.Inputs {
		ref.Inputs[i].Description = ""
	}
	if s = encode(out); len(s) <= apiref.MaxOutputBytes {
		return s
	}
	ref.Summary = ""
	if s = encode(out); len(s) <= apiref.MaxOutputBytes {
		return s
	}

	return encode(minimalOutput{
		Outcome:     apiref.OutcomeIncomplete,
		Connector:   apiref.Truncate(ref.Connector, maxMinimalField),
		Service:     apiref.Truncate(ref.Service, maxMinimalField),
		Operation:   apiref.Truncate(ref.Operation, maxMinimalField),
		Limitations: []string{budgetLimitation},
	})
}

// placeholder names an input, marking one the reference could not render.
func placeholder(in apiref.Input) string {
	if !in.Renderable {
		return "<" + in.Name + ":unrendered>"
	}

	return "<" + in.Name + ">"
}

// pathPlaceholder names a path label, marking it when the path input of that name could not be rendered.
func pathPlaceholder(ref *apiref.Reference, name string) string {
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationPath && in.Name == name {
			return placeholder(in)
		}
	}

	return "<" + name + ">"
}

// requiredAt lists the required inputs at a location.
func requiredAt(ref *apiref.Reference, loc apiref.Location) []apiref.Input {
	var out []apiref.Input
	for _, in := range ref.Inputs {
		if in.Required && in.Location == loc {
			out = append(out, in)
		}
	}

	return out
}

func paramPairs(ps []apiref.Param) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.Value == "" {
			out = append(out, p.Key)
		} else {
			out = append(out, p.Key+"="+p.Value)
		}
	}

	return out
}

func buildTemplate(ref *apiref.Reference) map[string]any {
	tpl := map[string]any{
		"method":        ref.Method,
		"url":           buildURL(ref),
		"auth_provider": ref.Connector,
	}
	var headers []map[string]string
	for _, h := range ref.FixedHeaders {
		headers = append(headers, map[string]string{"key": h.Key, "value": h.Value})
	}
	for _, in := range requiredAt(ref, apiref.LocationHeader) {
		headers = append(headers, map[string]string{"key": in.WireName, "value": placeholder(in)})
	}
	if len(headers) > 0 {
		tpl["headers"] = headers
	}
	if body := buildBody(ref); body != "" {
		tpl["body"] = body
	}
	if ref.AuthField != "" {
		tpl[ref.AuthField] = ref.AuthArgs
	}

	return tpl
}

func buildURL(ref *apiref.Reference) string {
	segs := strings.Split(ref.PathTemplate, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}"), "+")
			segs[i] = pathPlaceholder(ref, name)
		}
	}
	query := paramPairs(ref.FixedQuery)
	for _, in := range requiredAt(ref, apiref.LocationQuery) {
		query = append(query, in.WireName+"="+placeholder(in))
	}
	u := ref.Endpoint + strings.Join(segs, "/")
	if len(query) > 0 {
		u += "?" + strings.Join(query, "&")
	}

	return u
}

// bareTypes are the input types whose JSON placeholder is unquoted, so the substituted value stays a number or
// boolean.
//
//nolint:gochecknoglobals // immutable lookup table.
var bareTypes = map[string]bool{
	"integer": true, "long": true, "short": true, "byte": true, "float": true, "double": true,
	"intEnum": true, "number": true, "boolean": true,
}

// jsonBody renders the required members as a JSON object with keys sorted: a string-typed input gets a quoted
// placeholder, a numeric or boolean one a bare placeholder, and an unrenderable one a quoted marker.
func jsonBody(req []apiref.Input) string {
	sorted := slices.Clone(req)
	slices.SortStableFunc(sorted, func(a, b apiref.Input) int { return strings.Compare(a.WireName, b.WireName) })
	members := make([]string, 0, len(sorted))
	for _, in := range sorted {
		holder := placeholder(in)
		if !bareTypes[in.Type] || !in.Renderable {
			holder = encode(holder)
		}
		members = append(members, encode(in.WireName)+":"+holder)
	}

	return "{" + strings.Join(members, ",") + "}"
}

func buildBody(ref *apiref.Reference) string {
	req := requiredAt(ref, apiref.LocationBody)
	switch ref.BodyEncoding {
	case apiref.BodyForm:
		pairs := paramPairs(ref.FixedForm)
		for _, in := range req {
			pairs = append(pairs, in.WireName+"="+placeholder(in))
		}

		return strings.Join(pairs, "&")
	case apiref.BodyJSON:
		return jsonBody(req)
	case apiref.BodyNone:
	}
	// No encoding: required body members have no wire form, so list their placeholders.
	holders := make([]string, 0, len(req))
	for _, in := range req {
		holders = append(holders, placeholder(in))
	}

	return strings.Join(holders, " ")
}
