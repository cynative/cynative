package agentcatalog

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// maxFileBytes caps a whole agent file. The reader supplies limit+1 bytes so
	// an oversized file is rejected rather than silently truncated into a
	// half-parsed prompt.
	maxFileBytes = 64 << 10
	// maxDescriptionBytes caps the trimmed description.
	maxDescriptionBytes = 256

	fenceLF   = "---\n"
	fenceCRLF = "---\r\n"
	fence     = "---"

	descriptionKey = "description"
	yamlStringTag  = "!!str"
	yamlMapTag     = "!!map"
)

// Definition is one resolved agent. Raw is the exact file bytes: `agents show`
// prints them and the audit record digests them. Source and Path are set by the
// catalog, not by Parse.
type Definition struct {
	Name        string
	Description string
	Body        string
	Raw         []byte
	Source      Source
	Path        string
}

// Parse validates raw as an agent file and returns its Definition. It is strict
// and closed-schema by design: the frontmatter must be exactly one YAML mapping
// carrying exactly the description key, so a future frontmatter field (a model
// or tool override) written against a newer cynative fails loudly here instead
// of being silently ignored.
func Parse(name string, raw []byte) (Definition, error) {
	if len(raw) > maxFileBytes {
		return Definition{}, fmt.Errorf("%w: file exceeds %d bytes", ErrAgentInvalid, maxFileBytes)
	}
	if !utf8.Valid(raw) {
		return Definition{}, fmt.Errorf("%w: file is not valid UTF-8", ErrAgentInvalid)
	}

	front, body, err := splitFrontmatter(string(raw))
	if err != nil {
		return Definition{}, err
	}

	desc, err := parseDescription(front)
	if err != nil {
		return Definition{}, err
	}

	if strings.TrimSpace(body) == "" {
		return Definition{}, fmt.Errorf("%w: body is empty", ErrAgentInvalid)
	}

	return Definition{ //nolint:exhaustruct // Source and Path are the catalog's to set.
		Name:        name,
		Description: desc,
		Body:        body,
		Raw:         raw,
	}, nil
}

// splitFrontmatter returns the frontmatter text and the body. The opening fence
// must be the very first bytes (no BOM, no blank line, no leading space), and
// the closing fence must be a standalone --- line. The body is every byte after
// the closing fence's line ending, preserved verbatim.
func splitFrontmatter(src string) (string, string, error) {
	var rest string

	switch {
	case strings.HasPrefix(src, fenceCRLF):
		rest = src[len(fenceCRLF):]
	case strings.HasPrefix(src, fenceLF):
		rest = src[len(fenceLF):]
	default:
		return "", "", fmt.Errorf("%w: file must begin with a --- frontmatter fence", ErrAgentInvalid)
	}

	for offset := 0; ; {
		idx := strings.IndexByte(rest[offset:], '\n')
		if idx < 0 {
			return "", "", fmt.Errorf("%w: frontmatter is not closed by a --- line", ErrAgentInvalid)
		}

		line := rest[offset : offset+idx]
		lineEnd := offset + idx + 1

		if strings.TrimSuffix(line, "\r") == fence {
			return rest[:offset], rest[lineEnd:], nil
		}

		offset = lineEnd
	}
}

// parseDescription validates the frontmatter shape and returns the trimmed
// description. It walks the yaml.Node tree rather than decoding into a struct:
// yaml.v3's KnownFields(true) still coerces `description: 123` into "123", so
// only an explicit !!str tag check rejects a non-string scalar.
func parseDescription(front string) (string, error) {
	dec := yaml.NewDecoder(strings.NewReader(front))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%w: frontmatter is empty", ErrAgentInvalid)
		}

		return "", fmt.Errorf("%w: frontmatter is not valid YAML: %w", ErrAgentInvalid, err)
	}

	// A second document means the closing fence was a document separator inside
	// a multi-document stream rather than the end of this agent's frontmatter.
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: frontmatter must be a single YAML document", ErrAgentInvalid)
	}

	value, err := soleDescriptionValue(&doc)
	if err != nil {
		return "", err
	}

	return validateDescription(value)
}

// soleDescriptionValue returns the value node of the mapping's only key, which
// must be `description`.
//
// The exactly-one-pair check is the load-bearing one, and each of these was
// measured against yaml.v3 rather than assumed:
//   - A DUPLICATE key yields four content entries, not an error: decoding into
//     a yaml.Node does not report duplicates the way struct decoding does. The
//     pair count is the only thing that catches it.
//   - An ALIAS is RESOLVED by the decoder into a plain ScalarNode with the
//     target's tag, so a Kind check does NOT see yaml.AliasNode. An alias needs
//     its anchor defined in the same document, which means a second key, so the
//     pair count catches that too. An undefined anchor is a decode error.
//   - A MERGE key arrives as the literal key "<<", caught by the key-name check.
//   - A top-level SEQUENCE is caught by the MappingNode check below, where
//     len(Content) would otherwise be misleading.
func soleDescriptionValue(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%w: frontmatter must be a single YAML document", ErrAgentInvalid)
	}

	mapping := doc.Content[0]
	// The tag is checked as well as the kind: a !custom-tagged mapping is still
	// a MappingNode, so a kind check alone would admit it.
	if mapping.Kind != yaml.MappingNode || mapping.Tag != yamlMapTag {
		return nil, fmt.Errorf("%w: frontmatter must be an untagged mapping", ErrAgentInvalid)
	}

	const pairLen = 2
	if len(mapping.Content) != pairLen {
		return nil, fmt.Errorf("%w: frontmatter must contain exactly one key, %q", ErrAgentInvalid, descriptionKey)
	}

	key, value := mapping.Content[0], mapping.Content[1]
	if key.Kind != yaml.ScalarNode || key.Tag != yamlStringTag || key.Value != descriptionKey {
		return nil, fmt.Errorf("%w: the only allowed frontmatter key is %q", ErrAgentInvalid, descriptionKey)
	}

	return value, nil
}

// validateDescription enforces the description contract: a genuine string
// scalar, trimmed exactly once, non-empty after trimming, single-line,
// control-free, and within the byte limit.
func validateDescription(value *yaml.Node) (string, error) {
	if value.Kind != yaml.ScalarNode || value.Tag != yamlStringTag {
		return "", fmt.Errorf("%w: %q must be a string", ErrAgentInvalid, descriptionKey)
	}

	desc := strings.TrimSpace(value.Value)
	if desc == "" {
		return "", fmt.Errorf("%w: %q is empty", ErrAgentInvalid, descriptionKey)
	}
	if len(desc) > maxDescriptionBytes {
		return "", fmt.Errorf("%w: %q exceeds %d bytes", ErrAgentInvalid, descriptionKey, maxDescriptionBytes)
	}
	if strings.ContainsFunc(desc, isControlRune) {
		return "", fmt.Errorf("%w: %q must be a single control-free line", ErrAgentInvalid, descriptionKey)
	}

	return desc, nil
}

// isControlRune reports whether r is a C0 control, DEL, a C1 control, or a
// Unicode line/paragraph separator.
//
// U+2028 and U+2029 are not control characters by the C0/C1 definition, but a
// renderer that honours them splits the line anyway. A description carrying one
// could therefore break out of its `agents list` row and print attacker-chosen
// text on a line of its own, which is exactly what the single-line rule exists
// to prevent. yaml.v3 decodes the escaped forms, so `description: "a\u2028b"`
// reaches this check as a real separator.
func isControlRune(r rune) bool {
	const (
		lineSeparator      = '\u2028'
		paragraphSeparator = '\u2029'
	)

	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
		r == lineSeparator || r == paragraphSeparator
}
