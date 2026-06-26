package ui

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"charm.land/glamour/v2/styles"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// newTestUI constructs a UI with injected fakes suitable for parallel tests.
func newTestUI(
	t *testing.T,
	input string,
	renderFn func(string, string) (string, error),
) (*UI, *bytes.Buffer) {
	t.Helper()

	errBuf := &bytes.Buffer{}
	if renderFn == nil {
		renderFn = func(text, _ string) (string, error) { return text, nil }
	}

	u := &UI{ //nolint:exhaustruct // in set below; controller/isDark/detectOnce/detectDark zero-valued.
		render:  renderFn,
		in:      nil,
		promptW: errBuf,
		errW:    errBuf,
	}
	u.in = newScannerLineReader(u, strings.NewReader(input))

	return u, errBuf
}

// fakeLineReader is a scripted lineReader capturing the prompts and history
// flags it was called with.
type fakeLineReader struct {
	lines      []string
	idx        int
	gotPrompts []string
	gotHistory []bool
}

func (f *fakeLineReader) ReadLine(prompt string, withHistory bool) (string, bool) {
	f.gotPrompts = append(f.gotPrompts, prompt)
	f.gotHistory = append(f.gotHistory, withHistory)
	if f.idx >= len(f.lines) {
		return "", false
	}
	line := f.lines[f.idx]
	f.idx++

	return line, true
}

func TestAdaptiveStyleConfig_Dark(t *testing.T) {
	t.Parallel()

	cfg := adaptiveStyleConfig(true)

	if cfg.Document.Color != nil {
		t.Errorf("dark: Document.Color must be nil (inherit terminal fg), got %v", *cfg.Document.Color)
	}
	if cfg.Heading.Color == nil || *cfg.Heading.Color != "39" {
		t.Errorf("dark: want Heading.Color 39 (dark accent), got %v", cfg.Heading.Color)
	}
	if cfg.Code.BackgroundColor == nil || *cfg.Code.BackgroundColor != "236" {
		t.Errorf("dark: want inline-code dark chip bg 236, got %v", cfg.Code.BackgroundColor)
	}
	if cfg.CodeBlock.Chroma == nil {
		t.Error("dark: CodeBlock.Chroma must stay non-nil (highlighting intact)")
	}
}

func TestAdaptiveStyleConfig_Light(t *testing.T) {
	t.Parallel()

	cfg := adaptiveStyleConfig(false)

	if cfg.Document.Color != nil {
		t.Errorf("light: Document.Color must be nil (inherit terminal fg), got %v", *cfg.Document.Color)
	}
	if cfg.Heading.Color == nil || *cfg.Heading.Color != "27" {
		t.Errorf("light: want Heading.Color 27 (light accent), got %v", cfg.Heading.Color)
	}
	// The inline-code dark-chip override applies in the light variant too.
	if cfg.Code.BackgroundColor == nil || *cfg.Code.BackgroundColor != "236" {
		t.Errorf("light: want inline-code dark chip bg 236 (override), got %v", cfg.Code.BackgroundColor)
	}
	if cfg.CodeBlock.Chroma == nil {
		t.Error("light: CodeBlock.Chroma must stay non-nil (highlighting intact)")
	}
}

// TestAdaptiveStyleConfig_DoesNotMutateGlobals guards the shallow-copy contract:
// building the adaptive config must never clear the colors on glamour's package
// globals.
func TestAdaptiveStyleConfig_DoesNotMutateGlobals(t *testing.T) {
	t.Parallel()

	_ = adaptiveStyleConfig(true)
	_ = adaptiveStyleConfig(false)

	if styles.DarkStyleConfig.Document.Color == nil {
		t.Error("DarkStyleConfig.Document.Color was mutated to nil")
	}
	if styles.LightStyleConfig.Document.Color == nil {
		t.Error("LightStyleConfig.Document.Color was mutated to nil")
	}
}

func TestRenderOrRaw_Success(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", func(text, _ string) (string, error) {
		return "rendered:" + text, nil
	})

	got := u.RenderOrRaw("hello", "dark")
	if got != "rendered:hello" {
		t.Errorf("expected 'rendered:hello', got %q", got)
	}
}

func TestRenderOrRaw_Fallback(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", func(string, string) (string, error) {
		return "", errors.New("render boom")
	})

	got := u.RenderOrRaw("hello world", "dark")
	if got != "hello world" {
		t.Errorf("expected raw fallback, got: %q", got)
	}
}

func TestRenderMessage_Output(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	var buf bytes.Buffer

	msg := schema.AssistantMessage("Hello World", nil)
	u.RenderMessage(msg, "dark", &buf)

	if !strings.Contains(buf.String(), "Hello World") {
		t.Errorf("expected output to contain 'Hello World', got: %q", buf.String())
	}
}

func TestRenderMessage_EmptyContent(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	var buf bytes.Buffer

	msg := &schema.Message{Role: schema.Assistant} //nolint:exhaustruct // empty content branch under test
	u.RenderMessage(msg, "dark", &buf)

	if buf.Len() != 0 {
		t.Errorf("expected no output for empty content, got: %q", buf.String())
	}
}

func TestRenderMessage_Nil(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	var buf bytes.Buffer

	u.RenderMessage(nil, "dark", &buf)

	if buf.Len() != 0 {
		t.Errorf("expected no output for nil message, got: %q", buf.String())
	}
}

func TestPrintToolCall_WritesToErrW(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "", nil)

	u.PrintToolCall("my_tool", `{"key":"value"}`, "dark")

	if !strings.Contains(errBuf.String(), "my_tool") {
		t.Errorf("expected tool name in errW output, got: %q", errBuf.String())
	}
}

func TestPrintToolCall_RenderError(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "", func(string, string) (string, error) {
		return "", errors.New("render boom")
	})

	// Should not panic; falls back to plain text.
	u.PrintToolCall("test_tool", `{"key":"value"}`, "dark")

	if !strings.Contains(errBuf.String(), "test_tool") {
		t.Errorf("expected tool name in fallback output, got: %q", errBuf.String())
	}
}

func TestPrintToolCall_InvalidJSON(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "", nil)

	// Invalid JSON in arguments should not panic; pretty-printing is skipped.
	u.PrintToolCall("test_tool", `{bad json}`, "dark")

	if !strings.Contains(errBuf.String(), "test_tool") {
		t.Errorf("expected tool name in output, got: %q", errBuf.String())
	}
}

func TestPromptToolApproval_Yes(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "y\n", nil)

	if u.PromptToolApproval("test_tool", `{}`, "dark", false) != tools.ApproveOnce {
		t.Error("expected approval for 'y' input")
	}
}

func TestPromptToolApproval_Yes_Long(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "yes\n", nil)

	if u.PromptToolApproval("test_tool", `{}`, "dark", false) != tools.ApproveOnce {
		t.Error("expected approval for 'yes' input")
	}
}

func TestPromptToolApproval_No(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "n\n", nil)

	if u.PromptToolApproval("test_tool", `{}`, "dark", false) != tools.Deny {
		t.Error("expected denial for 'n' input")
	}
}

func TestPromptToolApproval_EOF(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	if u.PromptToolApproval("test_tool", `{}`, "dark", false) != tools.Deny {
		t.Error("expected denial on EOF")
	}
}

func TestPromptToolApproval_WritesPromptToErrW(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "y\n", nil)

	u.PromptToolApproval("my_tool", `{}`, "dark", false)

	if !strings.Contains(errBuf.String(), "Execute?") {
		t.Errorf("expected 'Execute?' in errW, got: %q", errBuf.String())
	}
}

func TestPromptToolApproval_All(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "a\n", nil)
	if got := u.PromptToolApproval("test_tool", `{}`, "dark", false); got != tools.ApproveSession {
		t.Errorf("got %v, want ApproveSession", got)
	}
}

func TestPromptToolApproval_AlreadyGranted_AutoApprovesWithoutReadingInput(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "should-not-be-read\n", nil)

	if got := u.PromptToolApproval("code_execution", `{"code":"x"}`, "dark", true); got != tools.ApproveOnce {
		t.Errorf("granted path got %v, want ApproveOnce", got)
	}
	if !strings.Contains(errBuf.String(), "Auto-approved (session)") {
		t.Errorf("granted path output = %q, want session note", errBuf.String())
	}
	if in, ok := u.PromptUserInput("> "); !ok || in != "should-not-be-read" {
		t.Errorf("granted path consumed input; PromptUserInput got (%q,%v)", in, ok)
	}
}

func TestClosedChan_IsAlreadyClosed(t *testing.T) {
	t.Parallel()

	ch := closedChan()
	select {
	case _, ok := <-ch:
		if ok {
			t.Errorf("closedChan must be closed, got a value")
		}
	default:
		t.Errorf("closedChan must be ready (closed), but the read blocked")
	}
}

func TestParseDecision_Table(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]tools.Decision{
		"y":       tools.ApproveOnce,
		"yes":     tools.ApproveOnce,
		"Y":       tools.ApproveOnce,
		"a":       tools.ApproveSession,
		"  a  ":   tools.ApproveSession,
		"all":     tools.ApproveSession,
		"ALL":     tools.ApproveSession,
		"n":       tools.Deny,
		"":        tools.Deny,
		"garbage": tools.Deny,
	} {
		if got := parseDecision(in); got != want {
			t.Errorf("parseDecision(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAutoApproveToolCall_ReturnsApproveOnce(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	if u.AutoApproveToolCall("test_tool", `{"key":"value"}`, "dark", false) != tools.ApproveOnce {
		t.Error("expected AutoApproveToolCall to return ApproveOnce")
	}
}

func TestAutoApproveToolCall_WritesToErrW(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "", nil)

	u.AutoApproveToolCall("test_tool", `{}`, "dark", false)

	if !strings.Contains(errBuf.String(), "Auto-approved") {
		t.Errorf("expected 'Auto-approved' in errW, got: %q", errBuf.String())
	}
}

func TestPromptUserInput_Success(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "  hello world  \n", nil)

	input, ok := u.PromptUserInput("prompt> ")
	if !ok {
		t.Fatal("expected ok=true")
	}

	if input != "hello world" {
		t.Errorf("expected trimmed 'hello world', got %q", input)
	}
}

func TestPromptUserInput_EOF(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)

	input, ok := u.PromptUserInput("prompt> ")
	if ok {
		t.Fatal("expected ok=false on EOF")
	}

	if input != "" {
		t.Errorf("expected empty input on EOF, got %q", input)
	}
}

func TestPromptUserInput_WritesPromptToErrW(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "answer\n", nil)

	u.PromptUserInput("ask> ")

	if !strings.Contains(errBuf.String(), "ask>") {
		t.Errorf("expected prompt in errW, got: %q", errBuf.String())
	}
}

func TestFormatToolCall_CodeRendersReadably(t *testing.T) {
	t.Parallel()

	out := formatToolCall("code_execution", `{"code":"const x = 1;\nconsole.log(x)"}`)

	if !strings.Contains(out, "```javascript") {
		t.Errorf("expected a javascript code fence, got: %s", out)
	}

	if !strings.Contains(out, "const x = 1;\nconsole.log(x)") {
		t.Errorf("expected unescaped script, got: %s", out)
	}
}

func TestFormatToolCall_RegularToolRendersJSON(t *testing.T) {
	t.Parallel()

	out := formatToolCall("http_request", `{"method":"GET"}`)

	if !strings.Contains(out, "```json") || !strings.Contains(out, `"method": "GET"`) {
		t.Errorf("expected indented JSON, got: %s", out)
	}
}

func TestFormatToolCall_EmptyCodeFallsBackToJSON(t *testing.T) {
	t.Parallel()

	out := formatToolCall("x", `{"code":""}`)

	if !strings.Contains(out, "```json") {
		t.Errorf("empty code should render as JSON, got: %s", out)
	}
}

func TestFormatToolCall_BadJSONRendersRaw(t *testing.T) {
	t.Parallel()

	out := formatToolCall("x", "not-json")

	if !strings.Contains(out, "not-json") {
		t.Errorf("expected raw arguments, got: %s", out)
	}
}

// richMarkdown exercises every element type that could plausibly carry ANSI:
// heading, list, bold/emph/inline, a fenced code block (chroma highlighting),
// a GFM table (borders), a link, and a blockquote.
const richMarkdown = "# Heading\n\n" +
	"- one\n- two\n\n" +
	"Some **bold**, *emph*, and `inline` code.\n\n" +
	"```go\nfunc main() {\n\tprintln(\"hi\")\n}\n```\n\n" +
	"| A | B |\n|---|---|\n| 1 | 2 |\n\n" +
	"[a link](https://example.com)\n\n" +
	"> a quote\n"

// TestRenderResolved_NottySmokeHappyPath integration-tests the glamour shell
// adapter's happy path with a real built-in style, so the renderer is not left
// wholly untested by virtue of living in the gate-excluded shell file.
func TestRenderResolved_NottySmokeHappyPath(t *testing.T) {
	t.Parallel()

	out, err := renderResolved("# hello", "notty", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "hello") {
		t.Fatalf("rendered output missing content: %q", out)
	}
}

// TestRenderResolved_NottyEmitsNoANSI is the regression test for the
// code-block/table no-ANSI gap: the notty style must emit zero ANSI for every
// element type.
func TestRenderResolved_NottyEmitsNoANSI(t *testing.T) {
	t.Parallel()

	out, err := renderResolved(richMarkdown, "notty", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(out, "\x1b[") {
		t.Fatalf("notty output must contain no ANSI escape sequences, got: %q", out)
	}
}

// TestResolveStyle_OffTTYCoercesGarbageStyle proves the wiring: off-TTY, even an
// unknown configured style is coerced to notty, so rendering succeeds with zero
// ANSI rather than erroring on the unknown style. It skips when stdout is a TTY
// (so it never flakes); under `go test` stdout is a pipe, so it runs.
func TestResolveStyle_OffTTYCoercesGarbageStyle(t *testing.T) {
	t.Parallel()

	if stdoutIsTTY() {
		t.Skip("stdout is a TTY; off-TTY style coercion is not exercised here")
	}

	resolved := resolveStyle("this-style-does-not-exist", stdoutIsTTY(), "")
	if resolved != "notty" {
		t.Fatalf("off-TTY should coerce to notty, got: %q", resolved)
	}

	out, err := renderResolved("# hi\n\n- one\n", resolved, false)
	if err != nil {
		t.Fatalf("off-TTY should render without error, got: %v", err)
	}

	if strings.Contains(out, "\x1b[") {
		t.Fatalf("off-TTY output must contain no ANSI, got: %q", out)
	}
}

func TestResolveStyle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured string
		isTTY      bool
		noColor    string
		want       string
	}{
		{name: "non-TTY default forces notty", configured: "dark", isTTY: false, noColor: "", want: "notty"},
		{name: "non-TTY with NO_COLOR forces notty", configured: "dark", isTTY: false, noColor: "1", want: "notty"},
		{name: "non-TTY custom style forces notty", configured: "light", isTTY: false, noColor: "", want: "notty"},
		// noColor "" models both unset and set-but-empty (os.Getenv returns "" for both).
		{name: "TTY empty/unset NO_COLOR keeps configured", configured: "dark", isTTY: true, noColor: "", want: "dark"},
		{name: "TTY no NO_COLOR keeps custom style", configured: "pink", isTTY: true, noColor: "", want: "pink"},
		{name: "TTY with NO_COLOR forces notty", configured: "dark", isTTY: true, noColor: "1", want: "notty"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := resolveStyle(tc.configured, tc.isTTY, tc.noColor); got != tc.want {
				t.Errorf("resolveStyle(%q, %v, %q) = %q, want %q",
					tc.configured, tc.isTTY, tc.noColor, got, tc.want)
			}
		})
	}
}

// TestRenderResolved_AdaptiveEmitsAccent proves the adaptive path wires
// adaptiveStyleConfig into glamour: the dark variant colors a level-2 heading
// with the dark accent (256-color 39). (Note: h1 has its own 228-on-63 chip, so
// the sample uses "##" to exercise the base heading accent.)
func TestRenderResolved_AdaptiveEmitsAccent(t *testing.T) {
	t.Parallel()

	out, err := renderResolved("## Title\n\nbody text here\n", adaptiveStyle, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "38;5;39") {
		t.Errorf("adaptive dark h2 should use accent 39; got: %q", out)
	}
}

// TestRenderResolved_NottyNoANSI proves non-adaptive styles pass through to
// glamour unchanged. The sample is link-free on purpose: glamour emits OSC 8
// hyperlinks (\x1b]) even under notty, so a link-bearing sample would contain
// ANSI; a link-free sample renders with zero escape sequences.
func TestRenderResolved_NottyNoANSI(t *testing.T) {
	t.Parallel()

	out, err := renderResolved("# Title\n\nplain **bold** paragraph\n", "notty", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("notty (link-free) must emit no escape sequences; got: %q", out)
	}
}

// TestRenderAdaptive_SkipsDetectionForNonAdaptive proves the only-when-adaptive
// guard: under go test stdout is not a TTY, so resolveStyle coerces any style to
// notty and detection must be skipped. (The positive path — adaptive on a real
// TTY detecting once — is verified by the live smoke, since forcing a TTY in a
// unit test is not worth an extra seam.)
func TestRenderAdaptive_SkipsDetectionForNonAdaptive(t *testing.T) {
	t.Parallel()

	calls := 0
	u := &UI{detectDark: func() bool { calls++; return true }} //nolint:exhaustruct // only the seam is exercised.

	out, err := u.renderAdaptive("# x\n", "dark")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 0 {
		t.Errorf("detection must be skipped when style resolves to notty; got %d calls", calls)
	}
	if !strings.Contains(out, "x") {
		t.Errorf("renderAdaptive should still render content; got: %q", out)
	}
}

func TestFormatFooter_SessionLine(t *testing.T) {
	t.Parallel()

	// A "session" scope: chrome carries plural model/tool calls, a singular
	// sub-agent, plural verifiers; the token line is labeled and always shows total.
	s := metrics.Stats{
		Elapsed: 3100 * time.Millisecond, RoundTrips: 2, ToolCalls: 4, Subagents: 1, Verifiers: 2,
		Provider: "vertex", Model: "gemini-3-pro",
		Usage: schema.Usage{ //nolint:exhaustruct // no cache write under test.
			PromptTokens: 5300, CompletionTokens: 100, TotalTokens: 5400, CachedReadTokens: 0,
		},
	}
	out := formatFooter(s, "session")

	for _, want := range []string{
		"3.1s", "2 model calls", "4 tool calls", "1 sub-agent", "2 verifiers", "vertex/gemini-3-pro",
		"\n   session ", "5.3k fresh in", "0 cached", "100 out", "5.4k total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("session footer missing %q; got:\n%s", want, out)
		}
	}
	for _, absent := range []string{"\n   turn", "\x1b["} {
		if strings.Contains(out, absent) {
			t.Errorf("session footer must not contain %q; got:\n%s", absent, out)
		}
	}
}

func TestFormatFooter_TurnLine(t *testing.T) {
	t.Parallel()

	// A "turn" scope: same shape, labeled "turn", chrome reflects this snapshot, the
	// total is always shown (a turn line is now self-contained — no session line beside it).
	turn := metrics.Stats{
		Elapsed: 4000 * time.Millisecond, RoundTrips: 1, ToolCalls: 1, Subagents: 2, Verifiers: 1,
		Provider: "anthropic", Model: "claude-opus-4-8",
		Usage: schema.Usage{
			PromptTokens: 4600, CompletionTokens: 100, TotalTokens: 4700,
			CachedReadTokens: 3600, CachedWriteTokens: 500,
		},
	}
	out := formatFooter(turn, "turn")

	for _, want := range []string{
		"4.0s", "1 model call", "1 tool call", "2 sub-agents", "1 verifier",
		"\n   turn ", "1.0k fresh in (500 cache write)", "3.6k cached", "100 out", "4.7k total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("turn footer missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\n   session") {
		t.Errorf("turn footer must not contain a session line; got:\n%s", out)
	}
}

func TestFormatFooter_CacheWriteIsParentheticalNotSegment(t *testing.T) {
	t.Parallel()

	s := metrics.Stats{ //nolint:exhaustruct // minimal + cache write.
		Elapsed: time.Second, RoundTrips: 1, Provider: "p", Model: "m",
		Usage: schema.Usage{ //nolint:exhaustruct // completion zero under test.
			PromptTokens: 100, TotalTokens: 100, CachedReadTokens: 60, CachedWriteTokens: 40,
		},
	}
	out := formatFooter(s, "session")
	// fresh = 100 − 60 = 40; write annotated INSIDE fresh, before the first "·".
	if !strings.Contains(out, "40 fresh in (40 cache write) · 60 cached") {
		t.Errorf("want cache-write parenthetical subset of fresh; got:\n%s", out)
	}
	if strings.Contains(out, "· 40 cache write") {
		t.Errorf("cache write must not be an additive segment; got:\n%s", out)
	}
}

func TestFormatFooter_FreshClampAndNoCacheWrite(t *testing.T) {
	t.Parallel()

	s := metrics.Stats{ //nolint:exhaustruct // minimal; cached > prompt.
		Elapsed: time.Second, RoundTrips: 1, Provider: "p", Model: "m",
		Usage: schema.Usage{ //nolint:exhaustruct // completion/cache-write zero.
			PromptTokens: 50, TotalTokens: 50, CachedReadTokens: 60,
		},
	}
	out := formatFooter(s, "turn")
	if !strings.Contains(out, "0 fresh in · 60 cached") {
		t.Errorf("want clamped 0 fresh in; got:\n%s", out)
	}
	if strings.Contains(out, "cache write") {
		t.Errorf("cache write must be hidden at zero; got:\n%s", out)
	}
}

func TestFormatFooter_NoUsageOmitsTokenLine(t *testing.T) {
	t.Parallel()

	s := metrics.Stats{ //nolint:exhaustruct // zero usage.
		Elapsed: time.Second, RoundTrips: 1, ToolCalls: 0, Provider: "p", Model: "m",
	}
	out := formatFooter(s, "session")
	if strings.Contains(out, "fresh in") {
		t.Errorf("token line must be omitted when the scope has no usage; got: %q", out)
	}
	for _, want := range []string{"1 model call", "0 tool calls"} { // singular rt, plural tc(0).
		if !strings.Contains(out, want) {
			t.Errorf("chrome missing %q; got: %q", want, out)
		}
	}
}

func TestFormatFooter_TotalOnlyShowsTotal(t *testing.T) {
	t.Parallel()

	// A provider reporting only TotalTokens: fresh/cached/out are all zero, so the
	// line must still show its total — otherwise it reads "0 ... 0 out" despite real usage.
	s := metrics.Stats{ //nolint:exhaustruct // total-only usage.
		RoundTrips: 1, Provider: "p", Model: "m",
		Usage: schema.Usage{TotalTokens: 1200}, //nolint:exhaustruct // total only.
	}
	out := formatFooter(s, "turn")
	if !strings.Contains(out, "\n   turn ") {
		t.Errorf("want a labeled turn line; got:\n%s", out)
	}
	if !strings.Contains(out, "0 fresh in · 0 cached · 0 out · 1.2k total") {
		t.Errorf("total-only line must show its total; got:\n%s", out)
	}
}

func TestFormatFooter_TotalFallsBackWhenUnset(t *testing.T) {
	t.Parallel()

	// A provider that reports prompt/completion but leaves TotalTokens unset (0): the
	// displayed total must fall back to prompt+completion (mirroring the metrics budget
	// basis), never a misleading "· 0 total" on a token-bearing turn.
	s := metrics.Stats{ //nolint:exhaustruct // total unset on purpose.
		RoundTrips: 1, Provider: "p", Model: "m",
		Usage: schema.Usage{PromptTokens: 1200, CompletionTokens: 300}, //nolint:exhaustruct // TotalTokens unset.
	}
	out := formatFooter(s, "turn")
	if !strings.Contains(out, "1.2k fresh in · 0 cached · 300 out · 1.5k total") {
		t.Errorf("total must fall back to prompt+completion (1.5k); got:\n%s", out)
	}
	if strings.Contains(out, "· 0 total") {
		t.Errorf("must not show a misleading 0 total; got:\n%s", out)
	}
}

func TestHumanInt_Scales(t *testing.T) {
	t.Parallel()

	cases := map[int]string{
		0:         "0",
		999:       "999",
		1_500:     "1.5k",
		19_600:    "19.6k",
		2_000_000: "2.0M", // exercises the >= 1_000_000 branch (otherwise uncovered).
	}
	for in, want := range cases {
		if got := humanInt(in); got != want {
			t.Errorf("humanInt(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderFooter_WritesToErrW(t *testing.T) {
	t.Parallel()

	u, errBuf := newTestUI(t, "", nil)
	s := metrics.Stats{ //nolint:exhaustruct // minimal.
		Elapsed: time.Second, RoundTrips: 1, Provider: "p", Model: "m",
	}
	u.RenderFooter(s, "session")
	if !strings.Contains(errBuf.String(), "1 model call") {
		t.Errorf("RenderFooter output = %q", errBuf.String())
	}
}

func TestHasUsage_Branches(t *testing.T) {
	t.Parallel()

	// Each OR term independently makes hasUsage true (a provider may report only
	// TotalTokens, or only completion); all-zero is false.
	cases := []struct {
		name   string
		u      schema.Usage
		expect bool
	}{
		{"prompt only", schema.Usage{PromptTokens: 1}, true},         //nolint:exhaustruct // one field.
		{"completion only", schema.Usage{CompletionTokens: 1}, true}, //nolint:exhaustruct // one field.
		{"total only", schema.Usage{TotalTokens: 1}, true},           //nolint:exhaustruct // one field.
		{"all zero", schema.Usage{}, false},                          //nolint:exhaustruct // zero usage.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasUsage(tc.u); got != tc.expect {
				t.Errorf("hasUsage(%s) = %v, want %v", tc.name, got, tc.expect)
			}
		})
	}
}

func TestWithInput_OverridesReader(t *testing.T) {
	t.Parallel()

	// promptW must be non-nil: PromptUserInput writes the prompt before reading.
	u := assemble(
		&UI{promptW: io.Discard},
		WithInput(strings.NewReader("yes\n")),
	) //nolint:exhaustruct // in/promptW only
	if got, _ := u.PromptUserInput("> "); got != "yes" {
		t.Errorf("PromptUserInput read %q, want %q", got, "yes")
	}
}

func TestFormatBanner_Plain(t *testing.T) {
	t.Parallel()

	out := formatBanner()
	for _, want := range []string{
		"|___/", // distinctive figlet art row.
		"Connectors",
		strings.Repeat("─", 48),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "agentic security research") {
		t.Errorf("banner must no longer contain the old tagline:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain banner must not contain ANSI: %q", out)
	}
}

func TestRenderBanner_WritesPlain(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	u := &UI{} //nolint:exhaustruct // RenderBanner needs no fields.
	u.RenderBanner(&buf)

	if !strings.Contains(buf.String(), "Connectors") {
		t.Errorf("banner not written: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("banner must contain no ANSI: %q", buf.String())
	}
}

func TestFormatConnector(t *testing.T) {
	t.Parallel()

	t.Run("all_fields", func(t *testing.T) {
		t.Parallel()

		v := ConnectorView{
			State:    ConnectorOK,
			Name:     "aws",
			Posture:  "access=default(read-only) · enforced=client · policy=arn:aws:iam::aws:policy/SecurityAudit",
			Identity: "774148217555 · arn:aws:iam::774148217555:user/x",
			Managed:  "eks",
		}
		got := formatConnector(v)
		want := "  ✓ aws         access=default(read-only) · enforced=client · " +
			"policy=arn:aws:iam::aws:policy/SecurityAudit · 774148217555 · arn:aws:iam::774148217555:user/x · (+eks)\n"
		if got != want {
			t.Fatalf("formatConnector =\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("warn_glyph", func(t *testing.T) {
		t.Parallel()

		got := formatConnector(ConnectorView{
			State: ConnectorWarn, Name: "github", Posture: "default=write", Identity: "@me",
		})
		if !strings.Contains(got, "⚠") {
			t.Errorf("warn glyph missing: %q", got)
		}
		if !strings.Contains(got, " · @me") {
			t.Errorf("identity delimiter missing: %q", got)
		}
	})

	t.Run("error_glyph", func(t *testing.T) {
		t.Parallel()

		got := formatConnector(ConnectorView{State: ConnectorError, Name: "azure", Posture: "no usable credentials"})
		if !strings.Contains(got, "✗") {
			t.Errorf("error glyph missing: %q", got)
		}
	})
}

func TestRenderConnector_Writes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	u := &UI{} //nolint:exhaustruct // RenderConnector needs no fields.
	u.RenderConnector(&buf, ConnectorView{State: ConnectorOK, Name: "gcp", Posture: "roles/viewer", Identity: "proj"})
	if !strings.Contains(buf.String(), "gcp") || !strings.Contains(buf.String(), "roles/viewer") {
		t.Errorf("connector not written: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("connector must contain no ANSI: %q", buf.String())
	}
}

func TestFormatLLM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    LLMStatus
		want []string
		not  []string
	}{
		{
			"ok",
			LLMStatus{ //nolint:exhaustruct // zero-valued fields not relevant to test
				State: ConnectorOK, Provider: "anthropic", Model: "claude-opus-4-8",
			},
			[]string{"LLM", "✓", "anthropic", "claude-opus-4-8"},
			[]string{"✗"},
		},
		{
			"runtime error with hint",
			LLMStatus{ //nolint:exhaustruct // zero-valued fields not relevant to test
				State:    ConnectorError,
				Provider: "anthropic",
				Model:    "claude-opus-4-8",
				Reason:   "invalid credentials (HTTP 401)",
				Hint:     "Check ANTHROPIC_API_KEY.",
			},
			[]string{
				"✗", "anthropic", "claude-opus-4-8", "invalid credentials (HTTP 401)",
				"Check ANTHROPIC_API_KEY.",
			},
			nil,
		},
		{
			"not configured onboarding",
			LLMStatus{ //nolint:exhaustruct // zero-valued fields not relevant to test
				NotConfigured: true,
				Example: []string{
					"export CYNATIVE_LLM_PROVIDER=openai",
					"export CYNATIVE_LLM_MODEL=gpt-5.5",
				},
			},
			[]string{
				"No LLM provider configured", "export CYNATIVE_LLM_PROVIDER=openai",
				"docs/providers/README.md",
			},
			nil,
		},
		{
			"error without hint",
			LLMStatus{ //nolint:exhaustruct // hint intentionally empty.
				State: ConnectorError, Provider: "openai", Model: "gpt-5.5", Reason: "quota exceeded",
			},
			[]string{"✗", "openai", "gpt-5.5", "quota exceeded"},
			[]string{"     "},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := formatLLM(tt.s)
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q; got:\n%s", w, out)
				}
			}
			for _, n := range tt.not {
				if strings.Contains(out, n) {
					t.Errorf("output should not contain %q; got:\n%s", n, out)
				}
			}
			if strings.Contains(out, "\x1b[") {
				t.Errorf("must not contain ANSI: %q", out)
			}
		})
	}
}

func TestWithPromptWriter_RoutesPromptsAwayFromFooter(t *testing.T) {
	t.Parallel()

	promptBuf := &bytes.Buffer{}
	footerBuf := &bytes.Buffer{}
	u := assemble(&UI{ //nolint:exhaustruct // fields under test only
		render: func(text, _ string) (string, error) { return text, nil },
		errW:   footerBuf,
	}, WithPromptWriter(promptBuf), WithInput(strings.NewReader("")))

	u.PrintToolCall("my_tool", `{}`, "dark")
	u.RenderFooter(metrics.Stats{}, "session") //nolint:exhaustruct // empty stats render the no-token footer.

	if !strings.Contains(promptBuf.String(), "my_tool") {
		t.Errorf("tool preview should go to promptW, got promptW=%q", promptBuf.String())
	}
	if strings.Contains(footerBuf.String(), "my_tool") {
		t.Errorf("tool preview must not go to the footer writer, got footer=%q", footerBuf.String())
	}
}

func TestSplitInlinePrompt(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, pre, inline string }{
		{"\n> ", "\n", "> "},
		{"Execute? ", "", "Execute? "},
		{"\n\n> ", "\n\n", "> "},
		{"", "", ""},
	}
	for _, c := range cases {
		pre, inline := splitInlinePrompt(c.in)
		if pre != c.pre || inline != c.inline {
			t.Errorf("splitInlinePrompt(%q) = (%q,%q), want (%q,%q)", c.in, pre, inline, c.pre, c.inline)
		}
	}
}

func TestReadLine_PrintsPrefixAndForwards(t *testing.T) {
	t.Parallel()

	u, buf := newTestUI(t, "", nil)
	fake := &fakeLineReader{lines: []string{"hello"}}
	u.in = fake

	got, ok := u.readLine("\n> ", true)
	if !ok || got != "hello" {
		t.Fatalf("readLine = (%q,%v), want (hello,true)", got, ok)
	}
	if buf.String() != "\n" {
		t.Errorf("prefix written = %q, want %q", buf.String(), "\n")
	}
	if len(fake.gotPrompts) != 1 || fake.gotPrompts[0] != "> " {
		t.Errorf("inline prompt forwarded = %v, want [> ]", fake.gotPrompts)
	}
	if len(fake.gotHistory) != 1 || fake.gotHistory[0] != true {
		t.Errorf("withHistory forwarded = %v, want [true]", fake.gotHistory)
	}
}

func TestScannerLineReader_OptionOrderRoutesPromptToCurrentWriter(t *testing.T) {
	t.Parallel()

	// WithInput is applied BEFORE WithPromptWriter; the inline prompt must still
	// reach the WithPromptWriter buffer, not the os.Stderr default.
	promptBuf := &bytes.Buffer{}
	u := assemble(&UI{ //nolint:exhaustruct // fields under test only
		render: func(text, _ string) (string, error) { return text, nil },
		errW:   io.Discard,
	}, WithInput(strings.NewReader("answer\n")), WithPromptWriter(promptBuf))

	got, ok := u.in.ReadLine("> ", false)
	if !ok || got != "answer" {
		t.Fatalf("ReadLine = (%q,%v), want (answer,true)", got, ok)
	}
	if !strings.Contains(promptBuf.String(), "> ") {
		t.Errorf("inline prompt should reach promptW, got %q", promptBuf.String())
	}
}

func TestScannerLineReader_EOF(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil) // empty input → immediate EOF
	got, ok := u.in.ReadLine("> ", false)
	if ok || got != "" {
		t.Errorf("ReadLine on EOF = (%q,%v), want (\"\",false)", got, ok)
	}
}

func TestPromptToolApproval_ForwardsNoHistory_AndDeniesOnEOF(t *testing.T) {
	t.Parallel()

	u, _ := newTestUI(t, "", nil)
	fake := &fakeLineReader{} // no lines → ok=false
	u.in = fake

	if d := u.PromptToolApproval("t", "{}", "dark", false); d != tools.Deny {
		t.Errorf("approval on EOF = %v, want Deny", d)
	}
	if len(fake.gotHistory) != 1 || fake.gotHistory[0] != false {
		t.Errorf("approval withHistory = %v, want [false]", fake.gotHistory)
	}
}

func TestMapReadResult(t *testing.T) {
	t.Parallel()

	if got, ok := mapReadResult("hi", nil); !ok || got != "hi" {
		t.Errorf("nil err = (%q,%v), want (hi,true)", got, ok)
	}
	if got, ok := mapReadResult("pasted", errPaste); !ok || got != "pasted" {
		t.Errorf("errPaste = (%q,%v), want (pasted,true)", got, ok)
	}
	if got, ok := mapReadResult("", io.EOF); ok || got != "" {
		t.Errorf("io.EOF = (%q,%v), want (\"\",false)", got, ok)
	}
	if got, ok := mapReadResult("partial", errors.New("boom")); ok || got != "" {
		t.Errorf("generic err = (%q,%v), want (\"\",false)", got, ok)
	}
}

func TestBoundedHistory_OrderAndDropEmpty(t *testing.T) {
	t.Parallel()

	h := newBoundedHistory()
	h.Add("first")
	h.Add("   ") // whitespace-only dropped
	h.Add("")    // empty dropped
	h.Add("second")

	if h.Len() != 2 {
		t.Fatalf("Len = %d, want 2", h.Len())
	}
	if h.At(0) != "second" || h.At(1) != "first" {
		t.Errorf("At(0)=%q At(1)=%q, want second/first", h.At(0), h.At(1))
	}
}

func TestBoundedHistory_RingEviction(t *testing.T) {
	t.Parallel()

	h := newBoundedHistory()
	for i := range historyCapacity + 5 {
		h.Add("e" + strconv.Itoa(i))
	}
	if h.Len() != historyCapacity {
		t.Fatalf("Len = %d, want %d", h.Len(), historyCapacity)
	}
	if h.At(0) != "e"+strconv.Itoa(historyCapacity+4) {
		t.Errorf("most recent = %q, want e%d", h.At(0), historyCapacity+4)
	}
	// At(historyCapacity-1) reads the least-recent surviving entry; it is the ONLY
	// call that exercises At's i<0 wrap branch (head=5, i=5-99=-94 → +100 → 6 →
	// entries[6] = "e5"). Required for 100% coverage of boundedHistory.At.
	if h.At(historyCapacity-1) != "e5" {
		t.Errorf("least-recent = %q, want e5", h.At(historyCapacity-1))
	}
}

func TestBoundedHistory_AtPanicsOutOfRange(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Errorf("At out of range did not panic")
		}
	}()
	newBoundedHistory().At(0) // empty → out of range
}

func TestNoHistory(t *testing.T) {
	t.Parallel()

	var h history = noHistory{}
	h.Add("ignored")
	if h.Len() != 0 {
		t.Errorf("noHistory.Len = %d, want 0", h.Len())
	}
	if h.At(3) != "" {
		t.Errorf("noHistory.At = %q, want \"\"", h.At(3))
	}
}

func TestHistoryFor(t *testing.T) {
	t.Parallel()

	shared := newBoundedHistory()
	shared.Add("x")
	if historyFor(true, shared).Len() != 1 {
		t.Errorf("withHistory=true should return the shared history")
	}
	if historyFor(false, shared).Len() != 0 {
		t.Errorf("withHistory=false should return noHistory")
	}
}

func TestWithTerminalEditor_PinsPromptWriter(t *testing.T) {
	t.Parallel()

	rw := &bytes.Buffer{} // *bytes.Buffer satisfies io.ReadWriter
	u := assemble(&UI{    //nolint:exhaustruct // fields under test only
		render: func(text, _ string) (string, error) { return text, nil },
	}, WithTerminalEditor(rw, 0))

	if u.promptW != rw {
		t.Errorf("WithTerminalEditor must pin promptW to the terminal writer")
	}
	u.PrintToolCall("my_tool", "{}", "dark")
	if !strings.Contains(rw.String(), "my_tool") {
		t.Errorf("tool preview must reach the terminal writer, got %q", rw.String())
	}
}

func TestWithInterruptCheck_Sets(t *testing.T) {
	t.Parallel()

	u := assemble(&UI{promptW: &bytes.Buffer{}}, //nolint:exhaustruct // only the probe is under test.
		WithInterruptCheck(func() bool { return true }))
	if !u.isInterrupted() {
		t.Error("WithInterruptCheck did not install the probe")
	}
}

func TestIsInterrupted_NilSafe(t *testing.T) {
	t.Parallel()

	u := &UI{} //nolint:exhaustruct // no interrupt probe installed.
	if u.isInterrupted() {
		t.Error("a nil interrupt probe must read false")
	}
}

func TestPromptToolApproval_FallbackInterruptedPrePrintDenies(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	u := &UI{ //nolint:exhaustruct // controller nil → fallback path; only the probe matters.
		render:      func(text, _ string) (string, error) { return text, nil },
		promptW:     buf,
		interrupted: func() bool { return true },
	}
	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("already-interrupted fallback got %v, want Deny", got)
	}
	if buf.Len() != 0 {
		t.Errorf("must not print when denied before the prompt: %q", buf.String())
	}
}

func TestPromptToolApproval_FallbackGrantedInterruptedAfterPrintDenies(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	buf := &bytes.Buffer{}
	u := &UI{ //nolint:exhaustruct // controller nil → fallback path.
		render:      func(text, _ string) (string, error) { return text, nil },
		promptW:     buf,
		interrupted: func() bool { return calls.Add(1) > 1 },
	}
	if got := u.PromptToolApproval("t", "{}", "dark", true); got != tools.Deny {
		t.Errorf("granted fallback interrupted-after-print got %v, want Deny", got)
	}
	if strings.Contains(buf.String(), "Auto-approved") {
		t.Errorf("must not auto-approve when a stop raced in: %q", buf.String())
	}
}

func TestPromptToolApproval_FallbackInterruptedAfterPrintDenies(t *testing.T) {
	t.Parallel()

	// A stop races in during PrintToolCall on the NON-granted path: the shared
	// post-print isInterrupted() guard (call 2) must deny before readLine is reached.
	var calls atomic.Int64
	buf := &bytes.Buffer{}
	u := &UI{ //nolint:exhaustruct // controller nil → fallback path.
		render:      func(text, _ string) (string, error) { return text, nil },
		promptW:     buf,
		interrupted: func() bool { return calls.Add(1) > 1 }, // pre-print false, post-print true.
	}
	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("shared post-print interrupt on non-granted path got %v, want Deny", got)
	}
	if strings.Contains(buf.String(), "Execute?") {
		t.Errorf("must not reach readLine prompt when denied at post-print: %q", buf.String())
	}
}

func TestPromptToolApproval_FallbackInterruptedAfterReadDenies(t *testing.T) {
	t.Parallel()

	// The operator types "y" and a graceful stop trips after readLine returns: the
	// post-read isInterrupted() guard (call 3) must deny (interrupt dominates), so a
	// SIGINT racing approval never runs the tool — the agent loop has no checkpoint
	// between approval and t.Run. Calls: (1) pre-print false, (2) post-print false,
	// (3) post-read true.
	var calls atomic.Int64
	u, _ := newTestUI(t, "y\n", nil)
	u.interrupted = func() bool { return calls.Add(1) > 2 } // post-read true only (call 3).

	if got := u.PromptToolApproval("t", "{}", "dark", false); got != tools.Deny {
		t.Errorf("a stop racing the typed answer must deny, got %v", got)
	}
}

func TestRenderLLM_OutputsFormatted(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	u := &UI{}
	u.RenderLLM(&buf, LLMStatus{
		State:    ConnectorOK,
		Provider: "anthropic",
		Model:    "claude-3-5-sonnet",
	})

	output := buf.String()
	if !strings.Contains(output, "anthropic") {
		t.Fatalf("output missing provider: %s", output)
	}
	if !strings.Contains(output, "claude-3-5-sonnet") {
		t.Fatalf("output missing model: %s", output)
	}
	if strings.Contains(output, "\x1b[") {
		t.Errorf("output contains ANSI codes: %s", output)
	}
}

func TestPrimeIfAdaptive_DetectsWhenAdaptiveAndController(t *testing.T) {
	t.Parallel()

	calls := 0
	u := &UI{ //nolint:exhaustruct // only the seam + controller are exercised.
		detectDark: func() bool { calls++; return true },
		controller: &fakeController{}, //nolint:exhaustruct // presence is all that matters.
	}

	u.primeIfAdaptive(adaptiveStyle)
	u.primeIfAdaptive(adaptiveStyle) // idempotent via detectOnce.

	if calls != 1 {
		t.Fatalf("detection should run exactly once; got %d calls", calls)
	}
	if !u.isDark {
		t.Errorf("isDark should be cached true from the seam")
	}
}

func TestPrimeIfAdaptive_SkipsWithoutController(t *testing.T) {
	t.Parallel()

	calls := 0
	u := &UI{detectDark: func() bool { calls++; return true }} //nolint:exhaustruct // controller nil.

	u.primeIfAdaptive(adaptiveStyle)

	if calls != 0 {
		t.Fatalf("no controller means no watcher to protect; want 0 calls, got %d", calls)
	}
}

func TestPrimeIfAdaptive_SkipsNonAdaptive(t *testing.T) {
	t.Parallel()

	calls := 0
	u := &UI{ //nolint:exhaustruct // only the seam + controller are exercised.
		detectDark: func() bool { calls++; return true },
		controller: &fakeController{}, //nolint:exhaustruct // presence is all that matters.
	}

	u.primeIfAdaptive(notTTYStyle)

	if calls != 0 {
		t.Fatalf("non-adaptive style must skip detection; got %d calls", calls)
	}
}
