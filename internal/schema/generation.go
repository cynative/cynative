package schema

// StopReason is why the backend stopped generating one response, normalized to
// the OpenAI chat-completions vocabulary. The constants are the wire spellings
// the llm adapter matches on, so they double as the mapping table.
type StopReason string

// The normalized stop reasons.
//
// StopUnspecified and StopOther are deliberately distinct. The first is an
// absence of evidence: the backend reported nothing, so the agent loop keeps its
// existing bounded retry. The second is a terminal classification cynative does
// not recognize, which the loop treats as futile to retry. Collapsing them would
// either disable the fix for backends that omit the field, or abandon runs on
// backends that report nothing.
const (
	StopUnspecified   StopReason = ""
	StopNormal        StopReason = "stop"
	StopLength        StopReason = "length"
	StopContentFilter StopReason = "content_filter"
	StopToolCalls     StopReason = "tool_calls"
	StopOther         StopReason = "other"
)

// Generation is one model response: the assistant turn plus what the backend
// reported about how generation ended. Generation metadata is not transcript
// content, which is why the stop reason lives here rather than on Message: a
// Message field would also be silently dropped by every clone site that rebuilds
// a message from Role and Content alone.
type Generation struct {
	// Message is the assistant turn. It may be nil: a backend can return a
	// successful response carrying no message, which the agent loop classifies as
	// a blank turn. Callers must not dereference it unchecked.
	Message *Message
	// StopReason is the normalized reason generation ended.
	StopReason StopReason
	// RawReason is the backend's finish_reason verbatim, empty when none was
	// reported. It is Bifrost's already-normalized value rather than the
	// provider's own string: Anthropic's max_tokens has become "length" by the
	// time it reaches here. It is backend-influenced text: escape and bound it
	// before rendering, and never hand it to a model unfenced.
	RawReason string
}
