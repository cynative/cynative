package cli

import "strings"

// sanitizeInline replaces every C0 control, DEL and C1 control in s with a
// single space, so the result is one line that cannot carry a terminal escape
// sequence.
//
// It exists because there is no reusable helper: agent.sanitizeMeta is
// unexported and guards the system prompt, and ui.formatConnector writes
// connector identity and posture to the terminal verbatim. Agent names,
// descriptions and paths are operator-authored but can come from a repository
// the operator did not write, so they are sanitized before display.
//
// It is applied to the provenance line, `agents list` output, the `agents show`
// stderr source line, and rendered errors that embed a path. It is NOT applied
// to `agents show` stdout, whose contract is the exact raw file bytes.
func sanitizeInline(s string) string {
	// U+2028/U+2029 are not C0/C1 controls but a renderer that honours them
	// still breaks the line, so a value carrying one could print on a line of
	// its own. Replaced for the same reason as a bare newline.
	const (
		lineSeparator      = '\u2028'
		paragraphSeparator = '\u2029'
	)

	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == lineSeparator || r == paragraphSeparator {
			return ' '
		}

		return r
	}, s)
}

// sanitizedError wraps an error whose message embeds an operator-visible path or
// filename, so cobra printing it cannot emit a terminal escape that a hostile
// repository put in a file name.
//
// Unwrap is what keeps this safe to apply: [errors.Is] still reaches the wrapped
// sentinels, so ExitCodeFor and every [errors.Is] check downstream behaves exactly
// as it did before the wrap.
type sanitizedError struct{ err error }

func (e sanitizedError) Error() string { return sanitizeInline(e.err.Error()) }

func (e sanitizedError) Unwrap() error { return e.err }

// sanitizeErr wraps err for display. A nil error stays nil so callers can wrap
// unconditionally.
func sanitizeErr(err error) error {
	if err == nil {
		return nil
	}

	return sanitizedError{err: err}
}
