package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cynative/cynative/internal/agent"
)

// TestExitCodeFor pins the process exit-code contract scripted callers depend
// on: 0 for success, 130 for a graceful interrupt, 2 for a run that completed
// without producing an answer, and 1 for everything else.
func TestExitCodeFor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: 0},
		{name: "generic error", err: errors.New("boom"), want: 1},
		{name: "interrupt", err: agent.ErrInterrupted, want: exitInterrupted},
		{
			name: "wrapped interrupt",
			err:  fmt.Errorf("research run failed: %w", agent.ErrInterrupted),
			want: exitInterrupted,
		},
		{name: "no answer", err: agent.ErrNoAnswer, want: exitNoAnswer},
		{name: "wrapped no answer", err: fmt.Errorf("x: %w", agent.ErrNoAnswer), want: exitNoAnswer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := ExitCodeFor(tc.err); got != tc.want {
				t.Errorf("ExitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestExitNoAnswerValue pins the documented number itself: it is a public
// contract (README), so a renumbering must be deliberate, not incidental.
func TestExitNoAnswerValue(t *testing.T) {
	t.Parallel()

	if exitNoAnswer != 2 {
		t.Errorf("exitNoAnswer = %d, want 2", exitNoAnswer)
	}
}
