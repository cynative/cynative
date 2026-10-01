// Package apiref holds the connector-neutral operation reference that the api_reference tool returns and the gate
// diagnostics cite. It imports only the standard library.
package apiref

import "strings"

// Outcome classifies the result of an operation lookup.
type Outcome string

// The lookup outcomes.
const (
	// OutcomeFound means the reference is complete.
	OutcomeFound Outcome = "found"
	// OutcomeIncomplete means the reference has blocking gaps.
	OutcomeIncomplete Outcome = "incomplete"
	// OutcomeNotFound means no operation matched.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeAmbiguous means several operations matched.
	OutcomeAmbiguous Outcome = "ambiguous"
	// OutcomeUnsupported means the connector or protocol has no reference support.
	OutcomeUnsupported Outcome = "unsupported"
	// OutcomeUnavailable means the metadata could not be loaded.
	OutcomeUnavailable Outcome = "unavailable"
)

// Output bounds, in runes unless noted.
const (
	// MaxSummary bounds an operation summary.
	MaxSummary = 600
	// MaxInputDescription bounds an input description.
	MaxInputDescription = 200
	// MaxPathEcho bounds an echoed request path.
	MaxPathEcho = 200
	// MaxGateDetail bounds the gate detail in a diagnostic.
	MaxGateDetail = 300
	// MaxReason bounds a result reason.
	MaxReason = 500
	// MaxChoice bounds one ambiguity choice.
	MaxChoice = 200
	// MaxChoices bounds the number of ambiguity choices.
	MaxChoices = 5
	// MaxOptionalInputs bounds the optional inputs listed.
	MaxOptionalInputs = 25
	// MaxCandidates bounds the candidates in a hint.
	MaxCandidates = 3
	// MaxOutputBytes bounds the whole tool output, in bytes.
	MaxOutputBytes = 8192
)

// PaginationUnspecified is the style for an operation whose metadata states no pagination.
const PaginationUnspecified = "unspecified"

// Query names the operation to look up.
type Query struct{ Connector, Service, Model, Operation string }

// Location is where an input travels on the wire.
type Location string

// The input locations.
const (
	// LocationPath is a path segment.
	LocationPath Location = "path"
	// LocationQuery is a query parameter.
	LocationQuery Location = "query"
	// LocationHeader is a request header.
	LocationHeader Location = "header"
	// LocationBody is a body member.
	LocationBody Location = "body"
)

// BodyEncoding is how the request body is encoded.
type BodyEncoding string

// The body encodings.
const (
	// BodyNone means no request body.
	BodyNone BodyEncoding = "none"
	// BodyForm means a form-encoded body.
	BodyForm BodyEncoding = "form"
	// BodyJSON means a JSON body.
	BodyJSON BodyEncoding = "json"
)

// Param is one fixed key and value pair.
type Param struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Input is one request input of an operation.
type Input struct {
	Name        string   `json:"name"`
	WireName    string   `json:"wire_name"`
	Location    Location `json:"location"`
	Required    bool     `json:"required"`
	Type        string   `json:"type"`
	Renderable  bool     `json:"-"`
	Description string   `json:"description,omitempty"`
}

// Response describes how responses are encoded and where the result sits.
type Response struct {
	Encoding string `json:"encoding"`
	Parse    string `json:"parse"`
}

// Pagination describes how an operation pages its results.
type Pagination struct {
	Style       string `json:"style"`
	InputToken  string `json:"input_token,omitempty"`
	OutputToken string `json:"output_token,omitempty"`
	Items       string `json:"items,omitempty"`
	PageSize    string `json:"page_size,omitempty"`
}

// Source identifies the metadata document a reference was read from.
type Source struct {
	Name     string `json:"name"`
	Document string `json:"document"`
	Version  string `json:"version,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// Reference is the full description of one operation.
type Reference struct {
	Connector       string            `json:"connector"`
	Service         string            `json:"service,omitempty"`
	Model           string            `json:"model,omitempty"`
	Operation       string            `json:"operation"`
	Protocol        string            `json:"protocol"`
	Method          string            `json:"method"`
	PathTemplate    string            `json:"path_template"`
	APIVersion      string            `json:"api_version,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	Endpoint        string            `json:"endpoint"`
	Inputs          []Input           `json:"inputs"`
	InputsTruncated bool              `json:"inputs_truncated,omitempty"`
	BodyEncoding    BodyEncoding      `json:"body_encoding"`
	FixedQuery      []Param           `json:"-"`
	FixedForm       []Param           `json:"-"`
	FixedHeaders    []Param           `json:"-"`
	AuthField       string            `json:"-"`
	AuthArgs        map[string]string `json:"-"`
	Response        Response          `json:"response"`
	Pagination      Pagination        `json:"pagination"`
	Source          Source            `json:"source"`
	Gaps            []string          `json:"gaps,omitempty"`
	Limitations     []string          `json:"limitations,omitempty"`
}

// Result is the api_reference lookup result.
type Result struct {
	Outcome   Outcome    `json:"outcome"`
	Reason    string     `json:"reason,omitempty"`
	Choices   []string   `json:"choices,omitempty"`
	Reference *Reference `json:"reference,omitempty"`
}

// OutcomeOf reports found for a reference with no blocking gaps and incomplete
// otherwise.
func OutcomeOf(r *Reference) Outcome {
	if len(r.Gaps) > 0 {
		return OutcomeIncomplete
	}
	return OutcomeFound
}

// Shape renders the request and response shape on one line, for a hint that
// tells the model which protocol an operation uses.
func (r *Reference) Shape() string {
	var b strings.Builder
	b.WriteString(r.Protocol + ": " + r.Method + " " + r.PathTemplate)
	var with []string
	for _, h := range r.FixedHeaders {
		with = append(with, "header "+h.Key+": "+h.Value)
	}
	if len(r.FixedForm) > 0 {
		pairs := make([]string, 0, len(r.FixedForm))
		for _, p := range r.FixedForm {
			pairs = append(pairs, p.Key+"="+p.Value)
		}
		with = append(with, "form body "+strings.Join(pairs, "&"))
	}
	if len(with) > 0 {
		b.WriteString(" with " + strings.Join(with, " and "))
	}
	b.WriteString("; responses are " + r.Response.Encoding)
	return b.String()
}
