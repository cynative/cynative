package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/transport"
)

// The tool is not exposed inside code_execution, so it implements Run only.
var _ schema.InvokableTool = (*apiReferenceTool)(nil)

const apiReferenceDescription = "Look up one connector API operation by exact name and get its protocol, inputs, " +
	"an http_request template with <placeholders>, response parsing and pagination. Read-only. Supported: aws " +
	"(restXml, restJson1, awsQuery, awsJson), github, gitlab and gcp, from public vendor metadata, sending " +
	"nothing to the connector; and kubernetes. GitLab operation IDs are generated from the path, so an ID changes " +
	"when its path does. GCP operations are Discovery method ids such as compute.instances.list, and model picks " +
	"the Discovery version. kubernetes reads the configured cluster's own /openapi/v3 document with the " +
	"connector's credentials, so CRDs and aggregated APIs are covered: pass kubernetes_auth {}, model as the " +
	"apiVersion (apps/v1, or v1 for the core group) and operation as the operationId. Not covered: discovery " +
	"documents (/version, /api, /apis), operations without an operationId or outside the form this tool renders, " +
	"documents published outside /openapi/v3/<group-version>, over 10 MiB or over 100000 elements, aggregated " +
	"APIs whose server is not answering, and lookup by resource or verb. eks, gke and aks lookups are not " +
	"available yet."

const (
	apiReferenceNote = "Replace every <placeholder>; percent-encode query and form values and every path value " +
		"(encodeURIComponent, so a '/' inside a path value becomes %2F); only a <Name+> path value spans " +
		"segments: encode each segment and keep the '/' between them; " +
		"and in a JSON body replace a quoted string placeholder, quotes included, with JSON.stringify(value) and " +
		"give numbers and booleans as bare JSON values. Pagination fields name model members: send each one " +
		"under the wire_name and location its entry in inputs gives. <Name:unrendered> (or " +
		"<Name+:unrendered> for a greedy path label) marks an input this reference could not render. " +
		"Check outcome and gaps even when no marker appears."
	budgetLimitation = "reference exceeds the output budget"
	// maxMinimalField bounds each identifier echoed in the minimal output.
	maxMinimalField = 200
)

// apiReferenceArgs is the tool's schema. The auth blocks reuse http_request's structs and JSON names; Run never
// decodes them into these types (see lookupArgs and lookupBlocks).
type apiReferenceArgs struct {
	Connector string `json:"connector"         jsonschema_description:"Connector name: 'aws', 'github', 'gitlab', 'gcp' or 'kubernetes'."`
	Service   string `json:"service,omitempty" jsonschema_description:"AWS: the endpoint prefix from the request host, e.g. 'route53' or 'iam'. GCP, optional: the Discovery API name when the method id does not start with it, e.g. 'sqladmin' for 'sql.instances.list'. Kubernetes: leave empty."`                                                                                       //nolint:lll // struct tags are indivisible
	Model     string `json:"model,omitempty"   jsonschema_description:"AWS: the model directory, to choose between models sharing an endpoint prefix (from an ambiguous result's choices). GCP: the Discovery version label, e.g. 'v1' or 'beta'; without it the lookup searches the API's vN versions. Kubernetes, required: the apiVersion, e.g. 'apps/v1', or 'v1' for the core group."` //nolint:lll // struct tags are indivisible
	Operation string `json:"operation"         jsonschema_description:"Exact operation name: the Smithy name for AWS (e.g. 'ListHostedZones'), the OpenAPI operationId for GitHub (e.g. 'repos/get'), GitLab (e.g. 'getApiV4ProjectsIdMergeRequests') and Kubernetes (e.g. 'listAppsV1NamespacedDeployment'), the Discovery method id for GCP (e.g. 'compute.instances.list')."`            //nolint:lll // struct tags are indivisible

	AWSAuth        *auth.AWSAuthArgs        `json:"aws_auth,omitempty"        jsonschema_description:"Same shape as http_request's. The aws lookup reads public metadata and ignores it."`                                                 //nolint:lll // struct tags are indivisible
	GCPAuth        *auth.GCPAuthArgs        `json:"gcp_auth,omitempty"        jsonschema_description:"Same shape as http_request's. The gcp lookup reads public metadata and ignores it."`                                                 //nolint:lll // struct tags are indivisible
	EKSAuth        *auth.EKSAuthArgs        `json:"eks_auth,omitempty"        jsonschema_description:"Same shape as http_request's. eks lookups are not available yet."`                                                                   //nolint:lll // struct tags are indivisible
	GKEAuth        *auth.GKEAuthArgs        `json:"gke_auth,omitempty"        jsonschema_description:"Same shape as http_request's. gke lookups are not available yet."`                                                                   //nolint:lll // struct tags are indivisible
	AKSAuth        *auth.AKSAuthArgs        `json:"aks_auth,omitempty"        jsonschema_description:"Same shape as http_request's. aks lookups are not available yet."`                                                                   //nolint:lll // struct tags are indivisible
	KubernetesAuth *auth.KubernetesAuthArgs `json:"kubernetes_auth,omitempty" jsonschema_description:"Required for a kubernetes lookup: pass {}. The lookup reads the configured cluster's /openapi/v3 with the connector's credentials."` //nolint:lll // struct tags are indivisible
	AzureAuth      *auth.AzureAuthArgs      `json:"azure_auth,omitempty"      jsonschema_description:"Same shape as http_request's. azure lookups are not available yet."`                                                                 //nolint:lll // struct tags are indivisible
}

// lookupArgs is what Run decodes before routing: the four strings every connector shares.
type lookupArgs struct {
	Connector string `json:"connector"`
	Service   string `json:"service"`
	Model     string `json:"model"`
	Operation string `json:"operation"`
}

// lookupBlocks binds each auth block as raw bytes under the same JSON names, so a malformed block can never fail
// the call: only the connector the call names decodes its own block, in PrepareLookup.
type lookupBlocks struct {
	AWS        json.RawMessage `json:"aws_auth"`
	GCP        json.RawMessage `json:"gcp_auth"`
	EKS        json.RawMessage `json:"eks_auth"`
	GKE        json.RawMessage `json:"gke_auth"`
	AKS        json.RawMessage `json:"aks_auth"`
	Kubernetes json.RawMessage `json:"kubernetes_auth"`
	Azure      json.RawMessage `json:"azure_auth"`
}

// of returns the block named <name>_auth, nil when the call sent none or null.
func (b *lookupBlocks) of(name string) json.RawMessage {
	raw := map[string]json.RawMessage{
		"aws": b.AWS, "gcp": b.GCP, "eks": b.EKS, "gke": b.GKE, "aks": b.AKS, "kubernetes": b.Kubernetes,
		"azure": b.Azure,
	}[name]
	if string(raw) == "null" {
		return nil
	}

	return raw
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
	egress    *auth.Egress
	sink      audit.Sink
	newID     func() string
	execute   readExecutor
}

// readExecutor performs one credentialed read: transport.Client.ExecuteStructured in production.
type readExecutor func(ctx context.Context, arguments string, providers []auth.Provider) (*transport.Response, error)

type apiReferenceOption func(*apiReferenceTool)

// NewAPIReferenceTool builds the api_reference tool over the session's providers. egress routes a targeted
// lookup's credentialed reads as it routes http_request's (nil keeps the direct default), and sink receives their
// child audit records (nil writes none).
func NewAPIReferenceTool(providers []auth.Provider, egress *auth.Egress, sink audit.Sink) schema.InvokableTool {
	return newAPIReferenceTool(providers, egress, sink)
}

func newAPIReferenceTool(
	providers []auth.Provider, egress *auth.Egress, sink audit.Sink, opts ...apiReferenceOption,
) *apiReferenceTool {
	if egress == nil {
		egress = auth.NoProxy()
	}
	t := &apiReferenceTool{
		info: &schema.ToolInfo{
			Name:   "api_reference",
			Desc:   apiReferenceDescription,
			Params: schema.ReflectParams[apiReferenceArgs](),
		},
		providers: providers,
		egress:    egress,
		sink:      sink,
		newID:     uuid.NewString,
		execute:   transport.NewClient(transport.WithEgress(egress)).ExecuteStructured,
	}
	for _, o := range opts {
		o(t)
	}

	return t
}

// Info returns the tool's schema.
// UngatedIO marks the tool as an I/O tool registered without the approval
// decorator, so the agent audits it as ungated with redacted arguments.
func (t *apiReferenceTool) UngatedIO() {}

func (t *apiReferenceTool) Info() *schema.ToolInfo { return t.info }

// Run looks up the operation. Every outcome is a result string; the only Go error is a fatal audit-write failure
// during a targeted lookup, which must abort the run.
func (t *apiReferenceTool) Run(ctx context.Context, argumentsInJSON string) (string, error) {
	var args lookupArgs
	if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
		return rejected(ctx, "invalid arguments: "+err.Error()), nil //nolint:nilerr // a result, not a Go error.
	}
	if args.Operation == "" {
		return rejected(ctx, "operation is required"), nil
	}
	q := apiref.Query{Connector: args.Connector, Service: args.Service, Model: args.Model, Operation: args.Operation}
	// The arguments are valid JSON, and a json.RawMessage field takes any value, so this decode cannot fail.
	var blocks lookupBlocks
	_ = json.Unmarshal([]byte(argumentsInJSON), &blocks)
	if p, td, err := auth.TargetDocumenterFor(t.providers, args.Connector); err == nil {
		own := blocks.of(p.Name())
		_, public := p.(auth.OperationDocumenter)
		switch {
		case td != nil && own != nil:
			return t.targeted(ctx, p.Name(), td, q, own)
		case td != nil && !public:
			return rejected(
				ctx,
				p.Name()+"_auth is required for a "+p.Name()+" lookup; pass {} as in http_request",
			), nil
		case !public && own != nil:
			return t.answer(ctx, apiref.Result{
				Outcome: apiref.OutcomeUnsupported, Reason: "targeted lookups for this connector are not available yet",
			}), nil
		}
	}

	return t.answer(ctx, auth.LookupReference(ctx, t.providers, q)), nil
}

// answer marks the call's progress or failure by its outcome and renders it within the output budget.
func (t *apiReferenceTool) answer(ctx context.Context, res apiref.Result) string {
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

	return capped(out)
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

// pathPlaceholder names a path label, keeping the '+' of a greedy label so the note can say its value spans
// segments, and marking it when the first path input of that name could not be rendered.
func pathPlaceholder(ref *apiref.Reference, name string, greedy bool) string {
	label := name
	if greedy {
		label += "+"
	}
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationPath && in.Name == name {
			if !in.Renderable {
				return "<" + label + ":unrendered>"
			}

			break
		}
	}

	return "<" + label + ">"
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
		segs[i] = segmentPlaceholders(ref, s)
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

// segmentPlaceholders replaces every {label} in one path segment with its placeholder: a whole-segment label as in
// /things/{Id}, or one inside literal text as in GitLab's {file_name}.tgz.
func segmentPlaceholders(ref *apiref.Reference, seg string) string {
	var b strings.Builder
	for {
		open := strings.IndexByte(seg, '{')
		if open < 0 {
			break
		}
		end := strings.IndexByte(seg[open:], '}')
		if end < 0 {
			break
		}
		name, greedy := strings.CutSuffix(seg[open+1:open+end], "+")
		b.WriteString(seg[:open])
		b.WriteString(pathPlaceholder(ref, name, greedy))
		seg = seg[open+end+1:]
	}
	b.WriteString(seg)

	return b.String()
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
