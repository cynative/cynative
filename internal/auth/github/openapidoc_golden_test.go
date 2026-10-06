package github_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/github"
	"github.com/cynative/cynative/internal/auth/openapidoc"
	"github.com/cynative/cynative/internal/cache"
)

// goldenSynth returns a description that reaches the reference branches the four-operation fixture does not:
// a required non-JSON body, a skipped optional body, an alternate server on an operation and on a path item, every
// parameter location, truncated optional inputs, a case-only ambiguity and both multi-segment label positions.
func goldenSynth() string {
	many := make([]string, 0, 30)
	for i := range 30 {
		many = append(many, `{"name":"p`+strconv.Itoa(i)+`","in":"query","schema":{"type":"string"}}`)
	}

	return `{"info":{"version":"9"},"servers":[{"url":"https://api.github.com"}],"paths":{
"/gap":{"post":{"operationId":"gap/post","requestBody":{"required":true,"content":{"text/plain":{}}}}},
"/skip":{"post":{"operationId":"skip/post",
"requestBody":{"content":{"application/json":{"schema":{"type":"array"}}}}}},
"/srv":{"get":{"operationId":"srv/get","servers":[{"url":"https://uploads.github.com/"}]}},
"/pi":{"servers":[{"url":"https://pi.example/"}],"get":{"operationId":"pi/get"}},
"/params/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
{"$ref":"#/components/parameters/q"}],
"get":{"operationId":"params/get","parameters":[{"name":"X-Trace","in":"header","schema":{"type":"string"}},
{"name":"ids","in":"query","required":true,"schema":{"type":"array"}},
{"name":"c","in":"cookie","schema":{"type":"string"}}],
"responses":{"201":{"content":{"text/zeta":{},"text/alpha":{}}}}}},
"/many":{"get":{"operationId":"many/get","parameters":[` + strings.Join(many, ",") + `]}},
"/case1":{"get":{"operationId":"dup/X"}},"/case2":{"get":{"operationId":"dup/x"}},
"/repos/{owner}/{repo}/contents/{path}":{"get":{"operationId":"repos/get-content",
"parameters":[{"name":"path","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}]}},
"/repos/{owner}/{repo}/branches/{branch}/protection":{"get":{"operationId":"repos/get-branch-protection",
"parameters":[{"name":"branch","in":"path","required":true,"x-multi-segment":true,"schema":{"type":"string"}}]}}},
"components":{"parameters":{"q":{"name":"q","in":"query","schema":{"type":"boolean"}}}}}`
}

// goldenSynthServer is a description whose only server is set at document level, away from api.github.com.
const goldenSynthServer = `{"info":{"version":"9"},"servers":[{"url":"https://ghe.example/api/v3"}],
"paths":{"/d":{"get":{"operationId":"d/get"}}}}`

func goldenRaw(t *testing.T, source string) []byte {
	t.Helper()
	switch source {
	case "synth":
		return []byte(goldenSynth())
	case "synth-server":
		return []byte(goldenSynthServer)
	}
	raw, err := os.ReadFile("testdata/openapi-docs.json")
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

// The goldens reach the docs code only through these five helpers, so moving that code changes nothing below them.
func goldenSerialize(t *testing.T, raw []byte) []byte {
	t.Helper()
	d, err := github.DistillDocs(raw)
	if err != nil {
		t.Fatal(err)
	}

	return d.Serialize()
}

func goldenReference(t *testing.T, raw []byte, op string) apiref.Result {
	t.Helper()
	d, err := github.DistillDocs(raw)
	if err != nil {
		t.Fatal(err)
	}

	return github.Reference(d, apiref.Query{Connector: "github", Operation: op})
}

func goldenHint(t *testing.T, raw []byte, v authreq.View) apiref.Hint {
	t.Helper()
	d, err := github.DistillDocs(raw)
	if err != nil {
		t.Fatal(err)
	}

	return github.Hint(d, v)
}

// cachedReference looks op up in docs read back from their serialized cache form, as a warm docs.json is.
func cachedReference(t *testing.T, serialized []byte, op string) apiref.Result {
	t.Helper()
	d, err := openapidoc.Unmarshal(serialized)
	if err != nil {
		t.Fatal(err)
	}

	return github.Reference(d, apiref.Query{Connector: "github", Operation: op})
}

func cachedHint(t *testing.T, serialized []byte, v authreq.View) apiref.Hint {
	t.Helper()
	d, err := openapidoc.Unmarshal(serialized)
	if err != nil {
		t.Fatal(err)
	}

	return github.Hint(d, v)
}

// checkGolden compares got with testdata/golden/name byte for byte. A missing golden is recorded and the test
// fails, so a first run writes the files and every later run, CI included, compares against the committed copy.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	want, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if mkErr := os.MkdirAll(filepath.Dir(path), cache.DirPerm); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(path, got, cache.FilePerm); wErr != nil {
			t.Fatal(wErr)
		}
		t.Fatalf("recorded %s; review it, then run the test again", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden:\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}

func goldenJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	return append(b, '\n')
}

func TestDocsGolden_Serialized(t *testing.T) {
	t.Parallel()
	checkGolden(t, "docs-fixture.json", goldenSerialize(t, goldenRaw(t, "fixture")))
	checkGolden(t, "docs-synth.json", goldenSerialize(t, goldenRaw(t, "synth")))
}

// goldenRef is a reference result with every field the JSON form hides projected next to it.
type goldenRef struct {
	Result       apiref.Result     `json:"result"`
	FixedHeaders []apiref.Param    `json:"fixed_headers,omitempty"`
	FixedQuery   []apiref.Param    `json:"fixed_query,omitempty"`
	FixedForm    []apiref.Param    `json:"fixed_form,omitempty"`
	AuthField    string            `json:"auth_field,omitempty"`
	AuthArgs     map[string]string `json:"auth_args,omitempty"`
	Renderable   []bool            `json:"renderable,omitempty"`
}

func projectRef(res apiref.Result) goldenRef {
	g := goldenRef{Result: res}
	if ref := res.Reference; ref != nil {
		g.FixedHeaders, g.FixedQuery, g.FixedForm = ref.FixedHeaders, ref.FixedQuery, ref.FixedForm
		g.AuthField, g.AuthArgs = ref.AuthField, ref.AuthArgs
		for _, in := range ref.Inputs {
			g.Renderable = append(g.Renderable, in.Renderable)
		}
	}

	return g
}

// goldenRefCases names each reference case's source and operation.
func goldenRefCases() map[string][2]string {
	return map[string][2]string{
		"fixture repos/get":               {"fixture", "repos/get"},
		"fixture issues/list-for-repo":    {"fixture", "issues/list-for-repo"},
		"fixture issues/create":           {"fixture", "issues/create"},
		"fixture markdown/render":         {"fixture", "markdown/render"},
		"fixture case-insensitive":        {"fixture", "REPOS/GET"},
		"fixture not found":               {"fixture", "nope/none"},
		"synth body gap":                  {"synth", "gap/post"},
		"synth optional body skipped":     {"synth", "skip/post"},
		"synth alternate server":          {"synth", "srv/get"},
		"synth path-item server":          {"synth", "pi/get"},
		"synth document server":           {"synth-server", "d/get"},
		"synth params":                    {"synth", "params/get"},
		"synth optional inputs truncated": {"synth", "many/get"},
		"synth ambiguous":                 {"synth", "DUP/X"},
		"synth multi-segment path":        {"synth", "repos/get-content"},
	}
}

func TestDocsGolden_References(t *testing.T) {
	t.Parallel()
	got := map[string]goldenRef{}
	for name, c := range goldenRefCases() {
		got[name] = projectRef(goldenReference(t, goldenRaw(t, c[0]), c[1]))
	}
	checkGolden(t, "references.json", goldenJSON(t, got))
}

// goldenHintOut is every field of a hint.
type goldenHintOut struct {
	Candidates  []string `json:"candidates"`
	Operation   string   `json:"operation"`
	NoReference bool     `json:"no_reference"`
	// Note is omitted when empty, so GitHub, which never sets it, records the bytes it recorded before Note existed.
	Note string `json:"note,omitempty"`
}

func hintOut(h apiref.Hint) goldenHintOut {
	return goldenHintOut{Candidates: h.Candidates, Operation: h.Operation, NoReference: h.NoReference, Note: h.Note}
}

func hintView(method, path string) authreq.View {
	return authreq.View{Method: method, Hostname: "api.github.com", Path: path, EscapedPath: path}
}

// goldenHintCases names each hint case's source, method and path.
func goldenHintCases() map[string][3]string {
	return map[string][3]string{
		"fixture wrong method":         {"fixture", "DELETE", "/repos/o/r"},
		"fixture no match":             {"fixture", "GET", "/nope/x/y/z"},
		"fixture two candidates":       {"fixture", "DELETE", "/repos/o/r/issues"},
		"fixture HEAD near miss":       {"fixture", "HEAD", "/repo/o/r"},
		"fixture OPTIONS near miss":    {"fixture", " Options ", "/repo/o/r"},
		"synth multi-segment tail":     {"synth", "PUT", "/repos/o/r/contents/a/b/c"},
		"synth multi-segment empty":    {"synth", "PUT", "/repos/o/r/contents"},
		"synth multi-segment mid-path": {"synth", "PUT", "/repos/o/r/branches/feat/x/protection"},
	}
}

func TestDocsGolden_Hints(t *testing.T) {
	t.Parallel()
	got := map[string]goldenHintOut{}
	for name, c := range goldenHintCases() {
		got[name] = hintOut(goldenHint(t, goldenRaw(t, c[0]), hintView(c[1], c[2])))
	}
	checkGolden(t, "hints.json", goldenJSON(t, got))
}

// TestDocsGolden_WarmCache reads the committed serialized docs back the way a warm docs.json is read and checks
// that every reference and hint matches the one built from a fresh distill, so a cache written by an older binary
// stays valid.
func TestDocsGolden_WarmCache(t *testing.T) {
	t.Parallel()
	serialized := map[string][]byte{}
	for _, src := range []string{"fixture", "synth"} {
		b, err := os.ReadFile(filepath.Join("testdata", "golden", "docs-"+src+".json"))
		if err != nil {
			t.Fatal(err)
		}
		serialized[src] = b
	}
	for name, c := range goldenRefCases() {
		b, ok := serialized[c[0]]
		if !ok {
			continue
		}
		want := goldenJSON(t, projectRef(goldenReference(t, goldenRaw(t, c[0]), c[1])))
		if got := goldenJSON(t, projectRef(cachedReference(t, b, c[1]))); !bytes.Equal(got, want) {
			t.Errorf("%s: cached reference differs:\ngot:\n%s\nwant:\n%s", name, got, want)
		}
	}
	for name, c := range goldenHintCases() {
		v := hintView(c[1], c[2])
		want := goldenJSON(t, hintOut(goldenHint(t, goldenRaw(t, c[0]), v)))
		if got := goldenJSON(t, hintOut(cachedHint(t, serialized[c[0]], v))); !bytes.Equal(got, want) {
			t.Errorf("%s: cached hint differs:\ngot:\n%s\nwant:\n%s", name, got, want)
		}
	}
}

func TestDistillDocs_RejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"not json", `{"paths":{}}`} {
		if d, err := github.DistillDocs([]byte(raw)); err == nil || d != nil {
			t.Errorf("%s: docs %v, err %v", raw, d, err)
		}
	}
}
