package agentcatalog

import "strings"

// The three section labels, in fixed order.
const (
	labelDescription  = "agent description:"
	labelUser         = "user instruction:"
	labelInstructions = "agent instructions:"
)

// Compose assembles the prompt for a run: three labelled sections, each label
// on its own line with its content on the next, separated by one blank line.
// The user instruction section is omitted entirely, separator included, when
// userInstruction is empty.
//
// No newline is appended after the body; whatever trailing bytes the body
// already carries are preserved, because the body passes through verbatim.
//
// The labels are always emitted, so the result is non-empty for any Definition.
// The CLI relies on that: a composed task is never "", which is what makes the
// bare-session Welcome skip structural rather than a new condition.
func Compose(d Definition, userInstruction string) string {
	var b strings.Builder

	b.WriteString(labelDescription)
	b.WriteString("\n")
	b.WriteString(d.Description)
	b.WriteString("\n\n")

	if userInstruction != "" {
		b.WriteString(labelUser)
		b.WriteString("\n")
		b.WriteString(userInstruction)
		b.WriteString("\n\n")
	}

	b.WriteString(labelInstructions)
	b.WriteString("\n")
	b.WriteString(d.Body)

	return b.String()
}
