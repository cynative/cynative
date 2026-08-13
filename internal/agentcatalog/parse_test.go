package agentcatalog_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

const goodFile = "---\ndescription: Finds public data stores.\n---\nCheck S3 and RDS.\n"

func TestParse_Valid(t *testing.T) {
	t.Parallel()

	def, err := agentcatalog.Parse("public-exposure", []byte(goodFile))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if def.Name != "public-exposure" {
		t.Errorf("Name = %q, want %q", def.Name, "public-exposure")
	}
	if def.Description != "Finds public data stores." {
		t.Errorf("Description = %q", def.Description)
	}
	if def.Body != "Check S3 and RDS.\n" {
		t.Errorf("Body = %q, want body preserved verbatim including trailing newline", def.Body)
	}
	if string(def.Raw) != goodFile {
		t.Errorf("Raw must be the exact file bytes")
	}
}

func TestParse_CRLF(t *testing.T) {
	t.Parallel()

	src := "---\r\ndescription: Windows authored.\r\n---\r\nBody line.\r\n"

	def, err := agentcatalog.Parse("win", []byte(src))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if def.Description != "Windows authored." {
		t.Errorf("Description = %q", def.Description)
	}
	if def.Body != "Body line.\r\n" {
		t.Errorf("Body = %q, want CRLF preserved", def.Body)
	}
}

// A body with no final newline is valid and is preserved byte for byte.
func TestParse_BodyWithoutFinalNewline(t *testing.T) {
	t.Parallel()

	def, err := agentcatalog.Parse("n", []byte("---\ndescription: d\n---\nno trailing newline"))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if def.Body != "no trailing newline" {
		t.Fatalf("Body = %q, want the exact bytes with no newline appended", def.Body)
	}
}

func TestParse_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{"no frontmatter", "Just a body.\n"},
		{"leading blank line", "\n---\ndescription: x\n---\nbody\n"},
		{"leading space", " ---\ndescription: x\n---\nbody\n"},
		{"BOM", "\ufeff---\ndescription: x\n---\nbody\n"},
		{"unterminated frontmatter", "---\ndescription: x\nbody\n"},
		{"empty frontmatter", "---\n---\nbody\n"},
		{"missing description", "---\ntitle: x\n---\nbody\n"},
		{"unknown extra key", "---\ndescription: x\nmodel: gpt-5\n---\nbody\n"},
		{"duplicate description", "---\ndescription: a\ndescription: b\n---\nbody\n"},
		{"description not a string", "---\ndescription: 123\n---\nbody\n"},
		{"description bool", "---\ndescription: true\n---\nbody\n"},
		{"description null", "---\ndescription:\n---\nbody\n"},
		{"description a mapping", "---\ndescription:\n  a: b\n---\nbody\n"},
		{"description a sequence", "---\ndescription:\n  - a\n---\nbody\n"},
		{"description empty after trim", "---\ndescription: \"   \"\n---\nbody\n"},
		{"description with control char", "---\ndescription: \"a\\u0007b\"\n---\nbody\n"},
		// U+2028/U+2029 are not C0/C1 controls, but a renderer that honours them
		// splits the line, letting a description break out of its agents list row.
		{"description with U+2028 line separator", "---\ndescription: \"a\\u2028b\"\n---\nbody\n"},
		{"description with U+2029 paragraph separator", "---\ndescription: \"a\\u2029b\"\n---\nbody\n"},
		{"custom tag on the value", "---\ndescription: !!binary aGk=\n---\nbody\n"},
		{"custom tag on the mapping", "---\n!custom\ndescription: x\n---\nbody\n"},
		{"custom tag on the key", "---\n!custom description: x\n---\nbody\n"},
		{"merge key", "---\n<<: {description: a}\n---\nbody\n"},
		// Rejected as a YAML decode error: the anchor is undefined.
		{"alias to an undefined anchor", "---\ndescription: *anchor\n---\nbody\n"},
		// Two shapes of defined alias. The two-key form is rejected by the pair
		// count; the one-pair form (anchor on the key, alias as the value) is
		// rejected because the resolved value node carries the KEY's tag, so the
		// key-name check fires. Neither is rejected by a Kind check: yaml.v3
		// resolves an alias into a plain scalar, never a yaml.AliasNode.
		{"alias, two keys", "---\na: &x hi\ndescription: *x\n---\nbody\n"},
		{"alias, one pair", "---\n&x description: *x\n---\nbody\n"},
		// A second document INSIDE the frontmatter. The naive fixture
		// "---\ndescription: x\n---\nbody\n---\ndescription: y\n---\n" is NOT
		// this case: the first standalone --- closes the frontmatter, so
		// everything after it is body and the file is legitimately valid. The
		// separator here is not the exact closing fence, so it stays inside the
		// frontmatter and reaches the decoder as a second document.
		{"second document inside frontmatter", "---\ndescription: x\n--- # second\ndescription: y\n---\nbody\n"},
		{"top level sequence", "---\n- a\n---\nbody\n"},
		{"blank body", "---\ndescription: x\n---\n   \n"},
		{"empty body", "---\ndescription: x\n---\n"},
		{"invalid utf8", "---\ndescription: x\n---\n\xff\xfe body\n"},
		{"description too long", "---\ndescription: " + strings.Repeat("a", 257) + "\n---\nbody\n"},
		{"file too large", "---\ndescription: x\n---\n" + strings.Repeat("a", 64<<10)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := agentcatalog.Parse("n", []byte(tc.src))
			if err == nil {
				t.Fatalf("Parse(%q) = nil error, want ErrAgentInvalid", tc.name)
			}
			if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
				t.Fatalf("Parse(%q) error = %v, want ErrAgentInvalid", tc.name, err)
			}
		})
	}
}

func TestParse_DescriptionTrimmedOnce(t *testing.T) {
	t.Parallel()

	def, err := agentcatalog.Parse("n", []byte("---\ndescription: \"  spaced  \"\n---\nbody\n"))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if def.Description != "spaced" {
		t.Fatalf("Description = %q, want %q", def.Description, "spaced")
	}
}

// The naive multi-document fixture is legitimately VALID: the first standalone
// --- closes the frontmatter, so the rest is body. Pinning that keeps someone
// from "fixing" the parser to reject it.
func TestParse_FenceInBodyIsBody(t *testing.T) {
	t.Parallel()

	src := "---\ndescription: x\n---\nbody\n---\nmore\n"

	def, err := agentcatalog.Parse("n", []byte(src))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil: a --- after the closing fence is body", err)
	}
	if def.Body != "body\n---\nmore\n" {
		t.Fatalf("Body = %q, want everything after the first closing fence", def.Body)
	}
}
