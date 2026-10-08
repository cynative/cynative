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

// StripMarkupCut is StripMarkup for text of any length. When s is longer than maxBytes it is first cut at the last
// rune boundary at or below maxBytes, so the stripping and the field split work on at most maxBytes bytes, and the
// result then always ends with the ellipsis, even when the stripped prefix is short: a tag left open by the cut
// drops the rest of the prefix, as an open tag does in StripMarkup. maxRunes is at least the ellipsis length.
func StripMarkupCut(s string, maxBytes, maxRunes int) string {
	if len(s) <= maxBytes {
		return StripMarkup(s, maxRunes)
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	// The stripped text of at most maxBytes bytes has at most maxBytes runes, so this call never truncates.
	runes := []rune(StripMarkup(s[:end], maxBytes))
	if keep := maxRunes - len(ellipsis); len(runes) > keep {
		runes = runes[:keep]
	}

	return string(runes) + ellipsis
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
