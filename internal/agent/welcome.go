package agent

import (
	"context"
	"errors"
	"time"

	"github.com/cynative/cynative/internal/schema"
)

// welcomeTimeout bounds the best-effort interactive welcome generation. Generous
// because reasoning models can take tens of seconds; a true hang still skips
// rather than blocking.
const welcomeTimeout = 60 * time.Second

// ErrWelcomeTimedOut is returned by Welcome when the welcome Generate call
// timed out (the welcome context expired) but the parent context is still live.
// The caller treats this as a soft skip: the session proceeds without a greeting.
var ErrWelcomeTimedOut = errors.New("welcome timed out")

// welcomeUserInstruction asks for a terse greeting plus numbered, reply-by-number
// example questions grounded in the connected environment already described in the
// (shared) system prompt.
const welcomeUserInstruction = "Greet me in one short sentence, then propose exactly two or three " +
	"concrete example questions I could ask, each grounded in my connected environment described above. " +
	"Number them 1., 2., 3. and end with a brief line inviting me to reply with just the number to ask " +
	"one, or to type my own question. Be terse: no preamble, no markdown headings."

// Welcome composes the interactive session opener: it generates a greeting +
// numbered example questions (NO tools, bounded by welcomeTimeout) reusing the
// enriched system prompt. On success it records the exchange in session history
// (so the user can reply with a number) and RETURNS the greeting text WITHOUT
// rendering it — the caller renders the LLM status line first, then the greeting,
// controlling stream order. A Generate failure is returned (no longer swallowed)
// so the caller can render the LLM ✗ block and abort; an empty/nil response
// returns ("", nil) (liveness OK, no greeting). The round-trip is counted in all
// cases.
func (a *Agent) Welcome(ctx context.Context) (string, error) {
	timeout := a.welcomeTimeoutD
	if timeout <= 0 {
		timeout = welcomeTimeout
	}

	wctx, cancel := context.WithTimeout(ctx, timeout)
	resp, err := a.model.Generate(wctx, []*schema.Message{
		schema.SystemMessage(a.systemPrompt),
		schema.UserMessage(welcomeUserInstruction),
	}, nil)
	cancel()
	a.metrics.AddRoundTrip()

	if err != nil {
		if ctx.Err() == nil && wctx.Err() == context.DeadlineExceeded {
			return "", ErrWelcomeTimedOut
		}

		return "", err
	}
	if resp == nil || resp.Text() == "" {
		return "", nil
	}

	text := resp.Text()
	a.history = append(a.history,
		schema.UserMessage(welcomeUserInstruction),
		schema.AssistantMessage(text, nil))

	return text, nil
}
