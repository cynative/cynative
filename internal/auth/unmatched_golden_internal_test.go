package auth

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	"github.com/cynative/cynative/internal/cache"
)

// goldenMultiSegmentDocs adds the two multi-segment label positions to the hint diagnostics.
const goldenMultiSegmentDocs = `{"info":{"version":"9"},"paths":{
"/repos/{owner}/{repo}/contents/{path}":{"get":{"operationId":"repos/get-content",
"parameters":[{"name":"path","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}]}},
"/repos/{owner}/{repo}/branches/{branch}/protection":{"get":{"operationId":"repos/get-branch-protection",
"parameters":[{"name":"branch","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}]}}}}`

func goldenGithubProvider(t *testing.T, raw []byte) *githubProvider {
	t.Helper()
	p := newGithubProvider("t", githubhardening.BaselineExposure(), nil)
	p.docs = newDocsCache(t.TempDir(), func(context.Context) ([]byte, error) { return raw, nil })

	return p
}

// TestGithubUnmatchedGolden records the whole diagnostic a GitHub table miss produces, byte for byte, so the hint
// and its formatting can only change on purpose.
func TestGithubUnmatchedGolden(t *testing.T) {
	t.Parallel()
	providers := map[string]*githubProvider{
		"fixture": goldenGithubProvider(t, docsFixture(t)),
		"multi":   goldenGithubProvider(t, []byte(goldenMultiSegmentDocs)),
	}
	cases := map[string][3]string{
		"wrong method":       {"fixture", "DELETE", "/repos/o/r"},
		"no match":           {"fixture", "GET", "/nope/x/y/z"},
		"two candidates":     {"fixture", "DELETE", "/repos/o/r/issues"},
		"HEAD near miss":     {"fixture", "HEAD", "/repo/o/r"},
		"multi-segment tail": {"multi", "PUT", "/repos/o/r/contents/a/b/c"},
		"multi-segment mid":  {"multi", "PUT", "/repos/o/r/branches/feat/x/protection"},
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		c := cases[name]
		v := authreq.View{Method: c[1], Hostname: "api.github.com", Path: c[2], EscapedPath: c[2]}
		um := &authreq.UnmatchedRequestError{
			Err: errors.New("github_hardening: cannot classify request as read or write: " + c[1] + " " + c[2]),
		}
		p := providers[c[0]]
		b.WriteString(name + ": " + ExplainUnmatched(t.Context(), "github", v, []Provider{p}, um).Error() + "\n")
	}
	checkUnmatchedGolden(t, []byte(b.String()))
}

// checkUnmatchedGolden compares got with the committed golden byte for byte. A missing golden is recorded and the
// test fails, so a first run writes it and every later run, CI included, compares.
func checkUnmatchedGolden(t *testing.T, got []byte) {
	t.Helper()
	path := filepath.Join("github", "testdata", "golden", "unmatched.txt")
	want, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if wErr := os.WriteFile(path, got, cache.FilePerm); wErr != nil {
			t.Fatal(wErr)
		}
		t.Fatalf("recorded %s; review it, then run the test again", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("unmatched diagnostics differ from the golden:\ngot:\n%s\nwant:\n%s", got, want)
	}
}
