package agentcatalog

// Source identifies which tier an agent came from. The zero value is SourceUser,
// the highest precedence, which matches the order roots are registered in.
type Source int

// The two agent sources, in resolution order: first match wins.
//
// There is deliberately no project tier. Agents are operator-authored
// configuration, and reading them from the working directory would mean a
// checkout could supply the prompt for a run, which is a trust boundary the
// feature does not need.
const (
	SourceUser Source = iota
	SourceBuiltin
)

// String returns the stable lowercase tier word used in the provenance line, the
// `agents list` SOURCE column, and the audit record. It is deliberately a string
// rather than the integer: the audit log must not carry an unstable enum value.
func (s Source) String() string {
	switch s {
	case SourceUser:
		return "user"
	case SourceBuiltin:
		return "builtin"
	default:
		return "unknown"
	}
}
