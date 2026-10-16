package agent

import (
	"strings"

	"github.com/cynative/cynative/internal/schema"
)

// historyAnswer builds the assistant turn the Q&A history keeps for an answer.
// It carries the answer text and, when the turn returned any, the aggregate
// reasoning text, because some backends require every earlier assistant turn
// to come back with its reasoning. The reasoning details are left out: their
// signatures and encrypted payloads were issued against the full working
// transcript, which history does not keep, so only the text can be replayed
// against the shorter one.
func historyAnswer(answer string, r *schema.ReasoningBlock) *schema.Message {
	msg := schema.AssistantMessage(answer, nil)
	if r != nil && r.Text != nil {
		msg.Content = append([]schema.Block{schema.ReasoningBlock{Text: r.Text}}, msg.Content...)
	}

	return msg
}

// unansweredPrefix introduces a question that ended in a host-written notice.
const unansweredPrefix = "Earlier question, which ended without an answer: "

// withUnanswered prepends the questions that ended in a host-written notice to
// the next question, so the model keeps their context. History holds no turn for
// them (the notice is not a model turn), and folding them into this one user
// message keeps the transcript alternating between user and assistant turns.
func withUnanswered(unanswered []string, task string) string {
	if len(unanswered) == 0 {
		return task
	}

	var b strings.Builder
	for _, q := range unanswered {
		b.WriteString(unansweredPrefix + q + "\n\n")
	}
	b.WriteString(task)

	return b.String()
}
