// Package ui handles terminal rendering, markdown styling, and interactive user prompts.
package ui

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"charm.land/glamour/v2/ansi"
	"charm.land/glamour/v2/styles"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// errPaste is the core sentinel for a fully bracketed-pasted line. The line
// editor shell normalizes term.ErrPasteIndicator to it before mapping, so a
// pasted line is treated as data, not EOF. Core never names the term value.
var errPaste = errors.New("ui: pasted line")

// mapReadResult maps a term.ReadLine outcome to the seam's (line, ok). A nil
// error or a paste indicator is a successful read; [io.EOF] (Ctrl-C/Ctrl-D) or any
// other error is ok=false.
func mapReadResult(line string, err error) (string, bool) {
	if err == nil || errors.Is(err, errPaste) {
		return line, true
	}

	return "", false
}

// history mirrors golang.org/x/term's History interface (identical method set),
// so a value is assignable to a term.History field in the shell without core
// importing term. Index 0 is the most-recently added entry.
type history interface {
	Add(entry string)
	Len() int
	At(idx int) string
}

// historyCapacity bounds the question-prompt ring buffer.
const historyCapacity = 100

// boundedHistory is a fixed-capacity ring of input lines whose Add drops
// empty/whitespace-only lines. It is for the single-goroutine prompt path only.
type boundedHistory struct {
	entries []string
	head    int
	size    int
}

func newBoundedHistory() *boundedHistory {
	return &boundedHistory{entries: make([]string, historyCapacity), head: 0, size: 0}
}

func (h *boundedHistory) Add(entry string) {
	if strings.TrimSpace(entry) == "" {
		return
	}
	h.head = (h.head + 1) % historyCapacity
	h.entries[h.head] = entry
	if h.size < historyCapacity {
		h.size++
	}
}

func (h *boundedHistory) Len() int { return h.size }

func (h *boundedHistory) At(idx int) string {
	if idx < 0 || idx >= h.size {
		panic(fmt.Sprintf("ui: history index [%d] out of range [0,%d)", idx, h.size))
	}
	i := h.head - idx
	if i < 0 {
		i += historyCapacity
	}

	return h.entries[i]
}

// noHistory disables recall and recording (used at the approval prompt).
type noHistory struct{}

func (noHistory) Add(string)    {}
func (noHistory) Len() int      { return 0 }
func (noHistory) At(int) string { return "" }

// historyFor returns the shared history when withHistory, else a disabled one.
func historyFor(withHistory bool, shared history) history {
	if withHistory {
		return shared
	}

	return noHistory{}
}

// lineReader reads one edited line of input, printing the inline prompt itself.
// withHistory enables up/down recall and recording of the submitted line; the
// approval prompt passes false. ok is false on EOF or read error.
type lineReader interface {
	ReadLine(prompt string, withHistory bool) (line string, ok bool)
}

// scannerLineReader is the cooked-mode reader backing non-editor inputs (tests,
// piped/headless, non-unix). It prints the inline prompt to the UI's current
// prompt writer (resolved at read time, so option order is irrelevant) and reads
// one line. It has no editing or history; withHistory is ignored.
type scannerLineReader struct {
	sc *bufio.Scanner
	w  func() io.Writer
}

// newScannerLineReader builds a scanner reader whose prompt writer tracks u's
// current promptW at read time.
func newScannerLineReader(u *UI, r io.Reader) *scannerLineReader {
	return &scannerLineReader{sc: bufio.NewScanner(r), w: func() io.Writer { return u.promptW }}
}

func (s *scannerLineReader) ReadLine(prompt string, _ bool) (string, bool) {
	fmt.Fprint(s.w(), prompt)
	if !s.sc.Scan() {
		return "", false
	}

	return s.sc.Text(), true
}

// splitInlinePrompt separates a leading run of newlines from the inline prompt.
// term.Terminal counts every prompt rune as a visible cell, so a literal '\n' in
// the prompt corrupts its cursor math; the prefix is printed in cooked mode
// before raw mode and only the inline part becomes the terminal prompt.
func splitInlinePrompt(prompt string) (string, string) {
	i := 0
	for i < len(prompt) && prompt[i] == '\n' {
		i++
	}

	return prompt[:i], prompt[i:]
}

// readLine prints any leading-newline spacing to the prompt writer in cooked
// mode, then delegates to the line reader with the inline prompt.
func (u *UI) readLine(prompt string, withHistory bool) (string, bool) {
	pre, inline := splitInlinePrompt(prompt)
	if pre != "" {
		fmt.Fprint(u.promptW, pre)
	}

	return u.in.ReadLine(inline, withHistory)
}

// Controller is the terminal controller surface the UI needs for single-key
// approval during a turn. The concrete *TerminalController (unix shell) satisfies
// it; it is nil on non-editor runs (scanner path / --auto-approve), where the
// line-edited fallback approval is used instead.
type Controller interface {
	// Interrupted reports whether a graceful stop was requested this turn.
	Interrupted() bool
	// BeginApproval arms a single-key approval window: the watcher delivers the
	// operator's y/a/n decision on the returned channel, or signals interrupted
	// when Esc/Ctrl-C is pressed. cleanup disarms the window and is idempotent.
	BeginApproval() (decision <-chan tools.Decision, interrupted <-chan struct{}, cleanup func())
}

// closedChan returns an already-closed struct{} channel. A BeginApproval on a
// degraded turn (no watcher) hands this back as the interrupt channel so the
// approval select denies at once instead of blocking on a channel nothing feeds.
func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)

	return ch
}

// UI holds the seams for terminal rendering, stdin reading, and prompt output.
// Construct one with New() for production use, or build directly with injected
// fakes for tests.
type UI struct {
	render     func(text, style string) (string, error) // markdown rendering; shell default is glamour.
	in         lineReader                               // interaction input; must not be recreated per call.
	promptW    io.Writer                                // where prompts and tool-call previews are written.
	errW       io.Writer                                // diagnostics/footer writer (always os.Stderr).
	controller Controller                               // editor-tty controller for single-key approval; nil otherwise.
	isDark     bool                                     // cached terminal-background detection (dark) for adaptive.
	detectOnce sync.Once                                // guards the one-time background detection.
	detectDark func() bool                              // background-detection seam; shell default detectDarkBackground.
	// interrupted reports a graceful stop on the no-controller (cooked) path, where
	// there is no keystroke watcher; nil (no-op) on UIs without an interrupt source.
	interrupted func() bool
}

// Option configures a UI built by New.
type Option func(*UI)

// WithInput overrides the interaction input reader with a cooked scanner over r.
// It does not enable line editing; that is WithTerminalEditor. (New defaults the
// reader to [os.Stdin]; the unix-TTY production path is wired via WithTerminalEditor.)
func WithInput(r io.Reader) Option {
	return func(u *UI) { u.in = newScannerLineReader(u, r) }
}

// WithPromptWriter overrides where interactive prompts and tool-call previews are
// written (production default [os.Stderr], or /dev/tty when stdin is piped).
func WithPromptWriter(w io.Writer) Option {
	return func(u *UI) { u.promptW = w }
}

// WithController installs the editor-tty controller used for single-key approval.
// When set, PromptToolApproval reads one keystroke via the controller's watcher
// instead of the line-edited fallback.
func WithController(c Controller) Option {
	return func(u *UI) { u.controller = c }
}

// WithInterruptCheck installs the graceful-stop probe used by the cooked fallback
// approval (no keystroke watcher), so a typed-prompt approval can deny on a stop.
func WithInterruptCheck(f func() bool) Option {
	return func(u *UI) { u.interrupted = f }
}

// isInterrupted reports a graceful stop; nil-safe so UIs without an interrupt source
// (most tests, --auto-approve) always read false.
func (u *UI) isInterrupted() bool { return u.interrupted != nil && u.interrupted() }

// assemble applies opts to base and returns it. Kept in the covered core so a
// shell New that forgets to apply options is caught by the coverage gate.
func assemble(base *UI, opts ...Option) *UI {
	for _, opt := range opts {
		opt(base)
	}

	return base
}

// primeIfAdaptive runs the one-time terminal background detection up front, but only
// when the resolved style is adaptive AND a keystroke watcher exists (controller !=
// nil) — the only configuration that can race the watcher against lipgloss's OSC
// probe. It is idempotent via detectOnce; non-controller UIs skip it and
// detect lazily on first render as before.
func (u *UI) primeIfAdaptive(resolved string) {
	if resolved != adaptiveStyle || u.controller == nil {
		return
	}
	u.detectOnce.Do(func() { u.isDark = u.detectDark() })
}

// notTTYStyle is the glamour style name for no-ANSI output. It is forced when
// stdout is not a terminal or NO_COLOR is set; it mirrors glamour's
// styles.NoTTYStyle constant.
const notTTYStyle = "notty"

// adaptiveStyle is the glamour style name for cynative's default rendering: body
// text inherits the terminal foreground, accents follow the detected background.
const adaptiveStyle = "adaptive"

// adaptiveStyleConfig returns glamour's dark (isDark) or light (!isDark) style,
// adjusted for cross-terminal readability: body text inherits the terminal
// foreground (Document.Color cleared), and inline code uses the dark chip in
// both variants because glamour's light inline-code chip is ~2.3:1. Headings and
// links keep the background-appropriate palette; code-block chroma is untouched
// so syntax highlighting stays intact. The shallow struct copy means only the
// returned value is mutated; glamour's package globals are never modified.
func adaptiveStyleConfig(isDark bool) ansi.StyleConfig {
	cfg := styles.LightStyleConfig
	if isDark {
		cfg = styles.DarkStyleConfig
	}
	cfg.Document.Color = nil               // body text -> terminal foreground (always contrasts).
	cfg.Code = styles.DarkStyleConfig.Code // inline code -> dark chip, readable on any background.

	return cfg
}

// resolveStyle decides the effective glamour style. A non-TTY stdout always
// forces the no-ANSI "notty" style; on a TTY, a non-empty NO_COLOR forces
// "notty"; otherwise the user-configured style wins.
func resolveStyle(configured string, isTTY bool, noColor string) string {
	if !isTTY || noColor != "" {
		return notTTYStyle
	}

	return configured
}

// RenderOrRaw renders markdown via u.render, falling back to raw text on error.
func (u *UI) RenderOrRaw(text, style string) string {
	out, err := u.render(text, style)
	if err != nil {
		return text
	}

	return out
}

// RenderMessage writes the message's text content to w, rendering markdown.
func (u *UI) RenderMessage(msg *schema.Message, style string, w io.Writer) {
	if msg == nil {
		return
	}
	text := msg.Text()
	if text == "" {
		return
	}

	fmt.Fprint(w, u.RenderOrRaw(text, style))
}

// PrintToolCall formats and prints a tool call to u.promptW.
func (u *UI) PrintToolCall(name, arguments, style string) {
	fmt.Fprint(u.promptW, u.RenderOrRaw(formatToolCall(name, arguments), style))
}

// PromptToolApproval asks the user to approve a tool call interactively. When the
// tool already holds a session grant (alreadyGranted), it prints the call plus a
// session-approved note and returns ApproveOnce without reading input — the grant
// is already latched in the decorator, so re-returning ApproveSession would be
// redundant.
func (u *UI) PromptToolApproval(name, arguments, style string, alreadyGranted bool) tools.Decision {
	if u.controller != nil {
		return u.approveSingleKey(name, arguments, style, alreadyGranted)
	}

	// Fallback (no editor controller — the scanner path: headless, piped, or
	// non-unix; --auto-approve swaps the prompter upstream, never reaching here):
	// a typed approval prompt guarded by the signal-backed interrupt probe. The read
	// itself is plain blocking (a graceful stop cannot cancel it mid-prompt; the cbreak
	// path can), but three probe checks deny on a stop: (1) pre-print, to skip the
	// preview entirely when already tripped; (2) shared post-print, covering both the
	// granted and non-granted paths — a stop that races in during a large preview is
	// caught here before any read or approve; (3) post-read, so a SIGINT racing a y/a
	// keystroke fails closed — the agent loop has no checkpoint between an approval and
	// the inner tool run. SIGINT also works via the cooked-mode ISIG. EOF and any
	// non-yes/all answer deny.
	if u.isInterrupted() { // (1) pre-print: already tripped → deny before printing or reading.
		return tools.Deny
	}
	u.PrintToolCall(name, arguments, style)
	if u.isInterrupted() { // (2) shared post-print: a stop raced in during the print → deny before reading or approving.
		return tools.Deny
	}

	if alreadyGranted {
		fmt.Fprintf(u.promptW, "↳ Auto-approved (session)\n")

		return tools.ApproveOnce
	}

	raw, ok := u.readLine("Execute? [y]es once / [a]ll this session / [N]o: ", false)
	if !ok {
		return tools.Deny
	}
	if u.isInterrupted() { // (3) post-read: a stop raced in with the typed answer → deny (interrupt dominates).
		return tools.Deny
	}

	return parseDecision(raw)
}

// approveSingleKey reads one keystroke via the controller's watcher. It fails
// closed: an already-tripped interrupt denies before any read (even on the
// alreadyGranted fast-path), a stop that races in during the granted-call print
// denies on a post-print re-check, and an Esc/Ctrl-C during the prompt denies this
// call (the agent loop also halts at its next checkpoint).
func (u *UI) approveSingleKey(name, arguments, style string, alreadyGranted bool) tools.Decision {
	if u.controller.Interrupted() { // D5: already tripped → deny, no read.
		return tools.Deny
	}

	u.PrintToolCall(name, arguments, style)
	if alreadyGranted {
		if u.controller.Interrupted() { // a stop that raced in during the print still denies the granted call.
			return tools.Deny
		}
		fmt.Fprintf(u.promptW, "↳ Auto-approved (session)\n")

		return tools.ApproveOnce
	}

	// Arm the watcher's approval window BEFORE the prompt is visible: the watcher reads
	// the tty for the whole turn but ignores y/a/n until approvalActive is set, so an
	// operator who presses a key the instant the prompt appears must have it buffered as
	// a decision rather than decoded-and-dropped.
	dec, intr, cleanup := u.controller.BeginApproval()
	defer cleanup()
	fmt.Fprintf(u.promptW, "Execute? [y]es once / [a]ll this session / [N]o: ")
	// Interrupt dominates: a stop already requested denies without consuming a decision.
	select {
	case <-intr:
		return tools.Deny
	default:
	}
	select {
	case <-intr:
		return tools.Deny
	case d := <-dec:
		// A decision and an interrupt can both be ready; re-check the shared state so a stop
		// that raced in with the keystroke still wins (the watcher trips state before closing intr).
		if u.controller.Interrupted() {
			return tools.Deny
		}
		// The single key was consumed with echo off and supplies no newline (unlike the
		// scanner path's Enter); end the prompt line so the next output starts fresh.
		fmt.Fprintln(u.promptW)

		return d
	}
}

// parseDecision maps a raw prompt answer to a Decision, failing closed: anything
// that is not an explicit yes or all is a denial.
func parseDecision(raw string) tools.Decision {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "y", "yes":
		return tools.ApproveOnce
	case "a", "all":
		return tools.ApproveSession
	default:
		return tools.Deny
	}
}

// AutoApproveToolCall prints the tool call and auto-approves it. The session grant
// is irrelevant here — --auto-approve approves every call unconditionally.
func (u *UI) AutoApproveToolCall(name, arguments, style string, _ bool) tools.Decision {
	u.PrintToolCall(name, arguments, style)
	fmt.Fprintf(u.promptW, "Auto-approved\n")

	return tools.ApproveOnce
}

// PromptUserInput prints the given prompt to u.promptW and reads a line from u.in.
// It returns the trimmed input and true on success, or ("", false) on EOF/error.
func (u *UI) PromptUserInput(prompt string) (string, bool) {
	line, ok := u.readLine(prompt, true)
	if !ok {
		return "", false
	}

	return strings.TrimSpace(line), true
}

// formatToolCall renders a tool call as markdown. A code_execution-style payload
// (a non-empty "code" field) is shown as a readable script block so the host can
// review it before approving; other tools render their arguments as JSON.
func formatToolCall(name, arguments string) string {
	if code, ok := codePayload(arguments); ok {
		return fmt.Sprintf("🔧 Tool Call: `%s`\n\n```javascript\n%s\n```\n", name, code)
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(arguments), "", "  "); err == nil {
		arguments = buf.String()
	}

	return fmt.Sprintf("🔧 Tool Call: `%s`\n\n```json\n%s\n```\n", name, arguments)
}

// codePayload returns the script when arguments carry a non-empty "code" field.
func codePayload(arguments string) (string, bool) {
	var probe struct {
		Code string `json:"code"`
	}

	if err := json.Unmarshal([]byte(arguments), &probe); err != nil || probe.Code == "" {
		return "", false
	}

	return probe.Code, true
}

// ConnectorState is the visual state of a connector inventory line. The glyph
// mapping is a UI concern owned here so the CLI can map auth's outcome without ui
// importing auth.
type ConnectorState int

const (
	// ConnectorOK is an available connector (✓).
	ConnectorOK ConnectorState = iota
	// ConnectorWarn is available but loud, e.g. github writes broadened (⚠).
	ConnectorWarn
	// ConnectorError is a connector that failed to register or was skipped (✗).
	ConnectorError
)

// ConnectorView is one rendered inventory line. For ConnectorError, Posture holds
// the skip/error reason and Identity is empty.
type ConnectorView struct {
	State    ConnectorState
	Name     string
	Posture  string
	Identity string
	// Managed is a managed sub-connector folded onto this line (e.g. "eks"),
	// rendered as a "(+eks)" suffix; empty when none.
	Managed string
}

// connectorGlyph maps a state to its leading glyph.
func connectorGlyph(s ConnectorState) string {
	var g string
	switch s {
	case ConnectorOK:
		g = "✓"
	case ConnectorWarn:
		g = "⚠"
	case ConnectorError:
		g = "✗"
	}

	return g
}

// formatConnector renders one inventory line ("  <glyph> <name> <posture> · <identity> · (+managed)",
// identity and managed omitted when empty), at the terminal-default foreground.
func formatConnector(v ConnectorView) string {
	out := fmt.Sprintf("  %s %-11s %s", connectorGlyph(v.State), v.Name, v.Posture)
	if v.Identity != "" {
		out += " · " + v.Identity
	}
	if v.Managed != "" {
		out += " · (+" + v.Managed + ")"
	}

	return out + "\n"
}

// RenderConnector writes one inventory line to w.
func (u *UI) RenderConnector(w io.Writer, v ConnectorView) {
	fmt.Fprint(w, formatConnector(v))
}

// LLMStatus is the LLM startup status block. It is rendered in its OWN "LLM"
// section (below Connectors) so a cloud-hosted model vendor shown here as the
// model is never read as the cloud connector. State/Provider/Model drive the
// status line; Reason/Hint annotate a failure; NotConfigured switches to the
// first-run onboarding block fed by Example (the README quickstart lines).
type LLMStatus struct {
	State         ConnectorState
	Provider      string
	Model         string
	Reason        string
	Hint          string
	NotConfigured bool
	Example       []string
}

// formatLLM renders the LLM section (header + rule + status line or onboarding
// block) at the terminal-default foreground, no ANSI — mirroring formatBanner /
// formatConnector.
func formatLLM(s LLMStatus) string {
	var b strings.Builder
	b.WriteString("\n  LLM\n")
	b.WriteString("  " + strings.Repeat("─", bannerRuleWidth) + "\n")

	if s.NotConfigured {
		b.WriteString("  ✗ No LLM provider configured.\n\n")
		b.WriteString("  Set your provider, model and an API key. For example:\n\n")
		for _, line := range s.Example {
			b.WriteString("      " + line + "\n")
		}
		b.WriteString("\n  …or create ~/.cynative/config.yaml. See docs/providers/README.md\n")
		b.WriteString("  for all 23+ supported providers.\n")

		return b.String()
	}

	line := "  " + connectorGlyph(s.State) + " " + s.Provider
	if s.Model != "" {
		line += "   " + s.Model
	}
	if s.Reason != "" {
		line += "   " + s.Reason
	}
	b.WriteString(line + "\n")
	if s.Hint != "" {
		b.WriteString("     " + s.Hint + "\n")
	}

	return b.String()
}

// RenderLLM writes the LLM status section to w.
func (u *UI) RenderLLM(w io.Writer, s LLMStatus) {
	fmt.Fprint(w, formatLLM(s))
}

// wordmark is the Standard-figlet rendering of "cynative" (generated by
// `figlet -f Standard cynative`, trailing whitespace stripped). It is pure ASCII,
// so it renders identically on a TTY, under notty/NO_COLOR, and when redirected.
// The lone backtick in row 3 is concatenated in because a raw literal cannot hold
// it; formatBanner adds the 2-space banner indent per row.
const wordmark = `                         _   _
   ___ _   _ _ __   __ _| |_(_)_   _____
  / __| | | | '_ \ / _` + "`" + ` | __| \ \ / / _ \
 | (__| |_| | | | | (_| | |_| |\ V /  __/
  \___|\__, |_| |_|\__,_|\__|_| \_/ \___|
       |___/`

// bannerRuleWidth is the width, in box-drawing characters, of the banner's rule.
const bannerRuleWidth = 48

// formatBanner renders the startup banner to a string at the terminal-default
// foreground (no ANSI): the figlet wordmark (each row 2-space indented), a blank
// line, the "Connectors" section header, and a horizontal rule. The connector
// inventory lines are streamed below it by the CLI.
func formatBanner() string {
	var b strings.Builder
	for line := range strings.SplitSeq(wordmark, "\n") {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n  Connectors\n")
	b.WriteString("  " + strings.Repeat("─", bannerRuleWidth) + "\n")

	return b.String()
}

// RenderBanner writes the startup banner to w.
func (u *UI) RenderBanner(w io.Writer) {
	fmt.Fprint(w, formatBanner())
}

// RenderFooter writes the operational footer to u.errW at the terminal-default
// foreground: a chrome line, then (when the scope reported usage) one token line
// labeled with the given scope word ("turn" or "session").
func (u *UI) RenderFooter(s metrics.Stats, label string) {
	fmt.Fprint(u.errW, formatFooter(s, label))
}

// labelFieldWidth left-justifies the token-line label so "turn"/"session" align in
// one column. It is len("session"), the wider label.
const labelFieldWidth = 7

// formatFooter renders a single-scope footer at the terminal-default foreground:
// the chrome line, then one token line labeled `label` (with the running total)
// when the scope reported any usage. The token block is omitted when usage is zero.
func formatFooter(s metrics.Stats, label string) string {
	var b strings.Builder
	writeChrome(&b, s)
	if hasUsage(s.Usage) {
		writeTokenLine(&b, label, s)
	}

	return b.String() + "\n"
}

// writeChrome appends the activity line: duration, model/tool-call counts,
// optional sub-agent/verifier segments, and provider/model.
func writeChrome(b *strings.Builder, s metrics.Stats) {
	fmt.Fprintf(
		b, "── %s · %d model %s · %d tool %s",
		humanDuration(s.Elapsed),
		s.RoundTrips, plural(s.RoundTrips, "call", "calls"),
		s.ToolCalls, plural(s.ToolCalls, "call", "calls"),
	)
	if s.Subagents > 0 {
		fmt.Fprintf(b, " · %d %s", s.Subagents, plural(s.Subagents, "sub-agent", "sub-agents"))
	}
	if s.Verifiers > 0 {
		fmt.Fprintf(b, " · %d %s", s.Verifiers, plural(s.Verifiers, "verifier", "verifiers"))
	}
	fmt.Fprintf(b, " · %s/%s", s.Provider, s.Model)
}

// writeTokenLine appends a labeled token line. Input is split into fresh
// (PromptTokens − CachedReadTokens, clamped at 0) vs cached (CachedReadTokens,
// always shown). Cache-write is a parenthetical subset of fresh when > 0. The
// total is always appended (each footer shows exactly one scope); it falls back
// to prompt+completion when the provider leaves TotalTokens unset, mirroring the
// metrics budget basis so a token-bearing turn never reads "· 0 total".
func writeTokenLine(b *strings.Builder, label string, s metrics.Stats) {
	u := s.Usage
	fresh := max(0, u.PromptTokens-u.CachedReadTokens)
	fmt.Fprintf(b, "\n   %-*s  %s fresh in", labelFieldWidth, label, humanInt(fresh))
	if u.CachedWriteTokens > 0 {
		fmt.Fprintf(b, " (%s cache write)", humanInt(u.CachedWriteTokens))
	}
	total := u.TotalTokens
	if total == 0 {
		total = u.PromptTokens + u.CompletionTokens
	}
	fmt.Fprintf(b, " · %s cached · %s out · %s total",
		humanInt(u.CachedReadTokens), humanInt(u.CompletionTokens), humanInt(total))
}

// hasUsage reports whether a Usage carries any token counts worth a token line.
func hasUsage(u schema.Usage) bool {
	return u.PromptTokens > 0 || u.CompletionTokens > 0 || u.TotalTokens > 0
}

// humanDuration formats a duration as seconds with one decimal (e.g. "12.3s").
func humanDuration(d time.Duration) string {
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// Thresholds for humanInt's k/M suffixes.
const (
	oneMillion  = 1_000_000
	oneThousand = 1_000
)

// humanInt formats a token count with a k/M suffix (one decimal) above 1000.
func humanInt(n int) string {
	switch {
	case n >= oneMillion:
		return fmt.Sprintf("%.1fM", float64(n)/oneMillion)
	case n >= oneThousand:
		return fmt.Sprintf("%.1fk", float64(n)/oneThousand)
	default:
		return strconv.Itoa(n)
	}
}

// plural returns one when n == 1, else many.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}

	return many
}
