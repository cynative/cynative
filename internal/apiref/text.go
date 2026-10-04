package apiref

import (
	"html"
	"strings"
	"unicode/utf8"
)

// ellipsis marks a truncated string. Three ASCII dots, so the output stays
// ASCII-safe for every terminal.
const ellipsis = "..."

// StripMarkup turns vendor documentation (HTML in Smithy, Markdown-ish in
// OpenAPI) into one line of plain text: tags removed, entities decoded,
// whitespace collapsed, then truncated to maxRunes.
func StripMarkup(s string, maxRunes int) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>' && inTag:
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return Truncate(strings.Join(strings.Fields(html.UnescapeString(b.String())), " "), maxRunes)
}

// Truncate cuts s to at most maxRunes runes, replacing the tail with an
// ellipsis when it cuts. When maxRunes is below the ellipsis length the first
// max(maxRunes, 0) runes are returned with no ellipsis.
func Truncate(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	if maxRunes < len(ellipsis) {
		return string(runes[:max(maxRunes, 0)])
	}
	return string(runes[:maxRunes-len(ellipsis)]) + ellipsis
}
