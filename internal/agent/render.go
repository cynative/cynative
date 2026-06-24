package agent

import (
	"fmt"
	"io"
	"strings"

	"github.com/cynative/cynative/internal/schema"
)

// renderTurn writes one assistant turn: prose through the markdown renderer, and
// each tool call as a one-line notice to the verbose writer (when set).
func (a *Agent) renderTurn(msg *schema.Message, w io.Writer) {
	if text := msg.Text(); text != "" {
		a.renderer(schema.AssistantMessage(text, nil), a.style, w)
	}

	if a.verbose == nil {
		return
	}
	for _, tc := range msg.ToolCalls() {
		fmt.Fprintf(a.verbose, "\n🔧 %s %s\n", tc.Name, tc.Arguments)
	}
}

// renderTodos renders the current todo list as a markdown checklist to w — the
// owning run's output. A sub-run's plan therefore renders to the sub-run's
// writer (verbose stderr, or discarded), keeping concurrent runs from
// interleaving on the main transcript.
func (a *Agent) renderTodos(todos []todo, w io.Writer) {
	var b strings.Builder
	b.WriteString("## 📋 Investigation plan\n\n")
	for _, td := range todos {
		fmt.Fprintf(&b, "- [%s] %s\n", checkMark(td.Status), td.Content)
	}
	a.renderer(schema.AssistantMessage(b.String(), nil), a.style, w)
}

// renderTaskStart announces a delegated sub-task on w — the parent run's
// output, so the bracket shows up in the transcript that delegated the work.
func (a *Agent) renderTaskStart(description string, w io.Writer) {
	a.renderer(schema.AssistantMessage("▶ Delegating sub-task: "+description, nil), a.style, w)
}

// renderTaskEnd closes a sub-task bracket on w. ok reports whether the sub-run
// returned without a Go error.
func (a *Agent) renderTaskEnd(ok bool, w io.Writer) {
	notice := "■ Sub-task complete"
	if !ok {
		notice = "■ Sub-task failed"
	}
	a.renderer(schema.AssistantMessage(notice, nil), a.style, w)
}

// checkMark renders a checkbox glyph for a todo status.
func checkMark(s todoStatus) string {
	switch s {
	case todoCompleted:
		return "x"
	case todoInProgress:
		return "~"
	case todoPending:
		return " "
	default:
		return " "
	}
}
