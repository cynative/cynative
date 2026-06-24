package agent

import (
	"fmt"
	"regexp"
)

// untrustedTag is the delimiter that fences external tool output as untrusted
// data in the transcript.
const untrustedTag = "tool_output"

// escapeFence neutralizes any closing delimiter for tag — including whitespace
// and case variants like "</tag >" or "</TAG>" — so fenced content cannot break
// out of its boundary. All variants normalize to the single escaped spelling.
// Shared by wrapUntrusted and the verify.go finding/evidence fences.
func escapeFence(s, tag string) string {
	re := regexp.MustCompile(`(?i)</\s*` + regexp.QuoteMeta(tag) + `\s*>`)

	return re.ReplaceAllString(s, "<\\/"+tag+">")
}

// wrapUntrusted fences external tool output as untrusted data, tagging it with
// the producing tool for provenance and escaping the closing delimiter.
func wrapUntrusted(toolName, content string) string {
	return fmt.Sprintf(
		"<%s tool=%q>\n%s\n</%s>",
		untrustedTag,
		toolName,
		escapeFence(content, untrustedTag),
		untrustedTag,
	)
}

// pipedInputTag fences operator-piped stdin that the cli folds into the task as
// untrusted context alongside the positional instruction.
const pipedInputTag = "piped_input"

// WrapPipedInput fences operator-piped stdin as untrusted data, escaping the
// closing delimiter so the content cannot break out of its boundary. It is the
// task-assembly counterpart to wrapUntrusted's tool-output fencing.
func WrapPipedInput(content string) string {
	return fmt.Sprintf(
		"<%s>\n%s\n</%s>",
		pipedInputTag,
		escapeFence(content, pipedInputTag),
		pipedInputTag,
	)
}
