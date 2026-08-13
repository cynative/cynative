package agentcatalog_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/agentcatalog"
)

// FuzzParse pins panic-freedom and the fail-closed contract: any input Parse
// accepts must have a non-empty single-line control-free description within the
// byte limit and a non-blank body, so no malformed file can mint a usable
// Definition. make check never passes -fuzz, so these seeds are the whole gate:
// each one drives a distinct rejection branch.
func FuzzParse(f *testing.F) {
	f.Add("---\ndescription: ok\n---\nbody\n")
	f.Add("---\r\ndescription: ok\r\n---\r\nbody\r\n")
	f.Add("no frontmatter at all")
	f.Add("---\ndescription: ok\n")
	f.Add("---\n---\nbody\n")
	f.Add("---\ndescription: 123\n---\nbody\n")
	f.Add("---\ndescription: ok\nextra: 1\n---\nbody\n")
	f.Add("---\ndescription: ok\n---\n   \n")
	f.Add("---\na: &x hi\ndescription: *x\n---\nbody\n")
	f.Add("---\n&x description: *x\n---\nbody\n")
	f.Add("---\ndescription: ok\n--- # two\ndescription: two\n---\nbody\n")
	f.Add("---\ndescription: \"\"\n---\nbody\n")
	f.Add("\ufeff---\ndescription: ok\n---\nbody\n")
	f.Add("---\n<<: {description: a}\n---\nbody\n")
	f.Add("---\n!custom description: x\n---\nbody\n")
	f.Add("---\ndescription: \"a\\u2028b\"\n---\nbody\n")

	f.Fuzz(func(t *testing.T, src string) {
		def, err := agentcatalog.Parse("n", []byte(src))
		if err != nil {
			if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
				t.Fatalf("error %v is not ErrAgentInvalid", err)
			}

			return
		}

		if def.Description == "" {
			t.Fatal("accepted a file with an empty description")
		}
		if len(def.Description) > 256 {
			t.Fatalf("accepted an over-long description: %d bytes", len(def.Description))
		}
		if strings.TrimSpace(def.Body) == "" {
			t.Fatal("accepted a file with a blank body")
		}
		if strings.ContainsFunc(def.Description, func(r rune) bool {
			return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
				r == '\u2028' || r == '\u2029'
		}) {
			t.Fatalf("accepted a description containing a control character: %q", def.Description)
		}
		if !utf8.ValidString(def.Description) || !utf8.ValidString(def.Body) {
			t.Fatal("accepted invalid UTF-8")
		}
	})
}
