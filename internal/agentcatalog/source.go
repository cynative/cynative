package agentcatalog

// Source identifies which tier an agent came from. The zero value is
// SourceProject, the highest precedence, which matches the order roots are
// registered in.
type Source int

// The three agent sources, in resolution order: first match wins.
const (
	SourceProject Source = iota
	SourceUser
	SourceBuiltin
)

// String returns the stable lowercase tier word used in the connector-style
// provenance line, the `agents list` SOURCE column, and the audit record. It is
// deliberately a string rather than the integer: the audit log must not carry an
// unstable enum value.
func (s Source) String() string {
	switch s {
	case SourceProject:
		return "project"
	case SourceUser:
		return "user"
	case SourceBuiltin:
		return "builtin"
	default:
		return "unknown"
	}
}
