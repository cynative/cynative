// Package cynative exposes the embedded project README to the binary. It lives at
// the module root because go:embed cannot reference parent directories
// (`//go:embed ../README.md` is rejected by the toolchain), so only a root-level
// file can embed the root README.
package cynative

import (
	_ "embed"
	"strings"
)

//go:embed README.md
var readme string

const (
	aboutBeginMarker      = "<!-- BEGIN agent-about -->"
	aboutEndMarker        = "<!-- END agent-about -->"
	quickstartBeginMarker = "<!-- BEGIN quickstart-example -->"
	quickstartEndMarker   = "<!-- END quickstart-example -->"
	codeFence             = "```"
)

// About returns the curated, agent-facing product description embedded in the
// README between the agent-about markers, or "" when the markers are absent.
func About() string {
	return extractAbout(readme)
}

// extractAbout returns the text between the agent-about markers in src, trimmed of
// surrounding whitespace. It fails closed: a missing begin or end marker yields "".
func extractAbout(src string) string {
	start := strings.Index(src, aboutBeginMarker)
	if start < 0 {
		return ""
	}
	start += len(aboutBeginMarker)

	end := strings.Index(src[start:], aboutEndMarker)
	if end < 0 {
		return ""
	}

	return strings.TrimSpace(src[start : start+end])
}

// QuickstartExample returns the env lines from the README's "How to Run"
// quickstart block (between the quickstart markers, code fences stripped), or
// nil when the markers are absent. It is the single source for the not-configured
// onboarding hint, so the first-run guidance never drifts from the docs.
func QuickstartExample() []string {
	return extractQuickstart(readme)
}

// extractQuickstart returns the non-fence, non-blank lines between the quickstart
// markers in src. It fails closed: a missing begin or end marker yields nil.
func extractQuickstart(src string) []string {
	start := strings.Index(src, quickstartBeginMarker)
	if start < 0 {
		return nil
	}
	start += len(quickstartBeginMarker)

	end := strings.Index(src[start:], quickstartEndMarker)
	if end < 0 {
		return nil
	}

	var lines []string
	for line := range strings.SplitSeq(src[start:start+end], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, codeFence) {
			continue
		}
		lines = append(lines, trimmed)
	}

	return lines
}
