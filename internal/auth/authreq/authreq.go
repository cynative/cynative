// Package authreq holds the narrowed, read-only projections the authorization
// gates receive in place of the two things they must never hold whole: the
// outbound [http.Request] the transport will send ([View] and the smaller
// [AuditView]), and the model's tool call ([ProviderArgs]). It is a stdlib-only
// leaf: internal/auth imports its own aws/gcp/azure subpackages, so a type
// declared there could not be shared with them without an import cycle.
package authreq

import (
	"net/http"
	"strings"
)

// View is the read-only projection of an outbound request handed to the
// authorization gates. Every field is derived from the [http.Request] the
// transport will send, and nothing here aliases that request: the header is
// cloned and the URL is flattened into strings.
//
// The query is carried unparsed, as RawQuery. There is deliberately no Query
// helper: GitLab parses fail-closed because Rack honors ';' as a separator and
// Go does not, while the Kubernetes and AWS gates match their own Go-based
// upstreams with the lenient parse. Those are correctly different, and one
// shared helper would impose a single policy on servers that disagree.
type View struct {
	Method      string
	Hostname    string
	Port        string
	Path        string
	EscapedPath string
	RawQuery    string
	Header      http.Header
	Body        string
}

// NewView projects req into the View handed to the read-only gates.
//
// req must be non-nil and carry a non-nil URL. [http.NewRequestWithContext]
// guarantees both at the transport's only call site, so this is a documented
// precondition rather than a validated one: returning an error here would put
// the projection inside the fail-closed reasoning it exists to stay out of.
//
// body is the exact string the request's body reader was built from. It is
// passed in rather than read from req because reading the request body here
// would consume the payload the signer and the wire still need.
//
// The authority is taken from the URL alone. The request's own authority field
// is never consulted: it is transport-owned and derived from the URL, and
// letting the two diverge is what cynative#243 and cynative#247 were.
func NewView(req *http.Request, body string) View {
	header := req.Header.Clone()
	if header == nil {
		header = http.Header{}
	}

	return View{
		Method:      req.Method,
		Hostname:    strings.ToLower(req.URL.Hostname()),
		Port:        req.URL.Port(),
		Path:        req.URL.Path,
		EscapedPath: req.URL.EscapedPath(),
		RawQuery:    req.URL.RawQuery,
		Header:      header,
		Body:        body,
	}
}

// AuditView is the minimal projection handed to a post-response auditor. The
// audit is advisory and reads only the classified route, so it gets its own
// type rather than the full View.
type AuditView struct {
	Method      string
	EscapedPath string
}

// NewAuditView projects req into the AuditView handed to a response auditor.
// Like NewView it requires a non-nil req with a non-nil URL. It is built after
// credential injection, preserving that the audit observes the request as sent.
func NewAuditView(req *http.Request) AuditView {
	return AuditView{
		Method:      req.Method,
		EscapedPath: req.URL.EscapedPath(),
	}
}
