package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// welcomeAgent builds an Agent (via New, so it carries a real enriched system
// prompt) wired with the given model, the echo renderer, and a metrics
// accumulator the test can inspect.
func welcomeAgent(t *testing.T, model schema.ChatModel) (*Agent, *metrics.Accumulator) {
	t.Helper()

	cfg := baseConfig()
	cfg.Model = model
	cfg.Connectors = map[string]ConnectorMeta{"eks": {Identity: "cluster/prod", Posture: "view"}}

	a := newAgent(t, cfg)
	a.renderer = echoRenderer
	acc := metrics.NewAccumulator("p", "m")
	a.metrics = acc

	return a, acc
}

func TestWelcome_Success(t *testing.T) {
	t.Parallel()

	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("hello! try: 1. list buckets", nil)}}
	a, acc := welcomeAgent(t, model)

	got, err := a.Welcome(context.Background())
	if err != nil {
		t.Fatalf("Welcome: %v", err)
	}
	if got != "hello! try: 1. list buckets" {
		t.Errorf("greeting = %q, want the model text returned (not rendered)", got)
	}
	if len(a.history) != 2 {
		t.Fatalf("history length = %d, want 2", len(a.history))
	}
	if a.history[0].Role != schema.User || a.history[0].Text() != welcomeUserInstruction {
		t.Errorf("history[0] = %+v, want the welcome user instruction", a.history[0])
	}
	if a.history[1].Role != schema.Assistant || !strings.Contains(a.history[1].Text(), "list buckets") {
		t.Errorf("history[1] = %+v, want the greeting", a.history[1])
	}
	if rt := acc.Snapshot().RoundTrips; rt != 1 {
		t.Errorf("RoundTrips = %d, want 1", rt)
	}
}

func TestWelcome_ErrorReturned(t *testing.T) {
	t.Parallel()

	a, acc := welcomeAgent(t, &errModel{})

	_, err := a.Welcome(context.Background())
	if err == nil {
		t.Fatal("Welcome must RETURN the error now, not swallow it")
	}
	if len(a.history) != 0 {
		t.Errorf("history length = %d, want 0 on error", len(a.history))
	}
	if rt := acc.Snapshot().RoundTrips; rt != 1 {
		t.Errorf("RoundTrips = %d, want 1 (always counted)", rt)
	}
}

func TestWelcome_EmptyTextReturnsEmpty(t *testing.T) {
	t.Parallel()

	model := &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("", nil)}}
	a, acc := welcomeAgent(t, model)

	got, err := a.Welcome(context.Background())
	if got != "" || err != nil {
		t.Fatalf("Welcome empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if len(a.history) != 0 {
		t.Errorf("history length = %d, want 0 on empty text", len(a.history))
	}
	if rt := acc.Snapshot().RoundTrips; rt != 1 {
		t.Errorf("RoundTrips = %d, want 1", rt)
	}
}

// blockingModel blocks in Generate until the context is done, then returns
// the context's error. Used to simulate a welcome that times out.
type blockingModel struct{}

var _ schema.ChatModel = (*blockingModel)(nil)

func (*blockingModel) Generate(
	ctx context.Context,
	_ []*schema.Message,
	_ []*schema.ToolInfo,
) (*schema.Message, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}

func TestWelcome_TimedOut_ReturnsSentinel(t *testing.T) {
	t.Parallel()

	// Build an agent with a very short welcome timeout; the blocking model will
	// cause the timeout to fire before returning a response.
	a, _ := welcomeAgent(t, &blockingModel{})

	// Override the welcome timeout to 1 ms so the test doesn't actually wait 60 s.
	a.welcomeTimeoutD = 1 * time.Millisecond

	// The parent context is alive; only the welcome context expires.
	_, err := a.Welcome(context.Background())
	if err == nil {
		t.Fatal("Welcome must return an error on timeout")
	}
	if !errors.Is(err, ErrWelcomeTimedOut) {
		t.Errorf("Welcome timeout error = %v, want errors.Is ErrWelcomeTimedOut", err)
	}
}

// TestConfigWelcomeTimeout_SetsField verifies that Config.WelcomeTimeout is
// wired onto the agent by New (zero stays zero, so the const default applies).
func TestConfigWelcomeTimeout_SetsField(t *testing.T) {
	t.Parallel()

	cfg := baseConfig()
	cfg.Model = &scriptedModel{msgs: []*schema.Message{schema.AssistantMessage("hi", nil)}}

	// Positive duration: field must be set.
	cfg.WelcomeTimeout = 5 * time.Millisecond
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.welcomeTimeoutD != 5*time.Millisecond {
		t.Errorf("welcomeTimeoutD = %v, want 5ms", a.welcomeTimeoutD)
	}

	// Zero duration: field stays zero (the const default is used).
	cfg.WelcomeTimeout = 0
	a2, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a2.welcomeTimeoutD != 0 {
		t.Errorf("zero duration must leave welcomeTimeoutD zero, got %v", a2.welcomeTimeoutD)
	}
}
