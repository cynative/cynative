package llm

import (
	"context"
	"strings"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// loggerConfigured builds a chat model with opts and returns the logger it
// handed to the Bifrost backend factory.
func loggerConfigured(t *testing.T, opts ...ChatModelOption) bschemas.Logger {
	t.Helper()

	var cfg bschemas.BifrostConfig
	factory := func(_ context.Context, c bschemas.BifrostConfig) (BifrostBackend, error) {
		cfg = c

		return &BifrostBackendMock{ShutdownFunc: func() {}}, nil
	}
	acct := &FileAccount{Entry: ProviderEntry{Provider: "openai", Model: "m"}}

	if _, err := NewBifrostChatModel(
		context.Background(),
		acct,
		append(opts, WithBackendFactory(factory))...); err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	return cfg.Logger
}

func TestWithLogRedactor_WiresTheBifrostLogger(t *testing.T) {
	t.Parallel()

	redact := func(s string) string { return strings.ReplaceAll(s, "SECRET", "[R]") }
	l, ok := loggerConfigured(t, WithLogRedactor(redact)).(redactingLogger)
	if !ok || l.redact("SECRET") != "[R]" {
		t.Fatalf("logger = %#v, want a redactingLogger using the configured func", l)
	}
}

func TestWithLogRedactor_NilKeepsIdentity(t *testing.T) {
	t.Parallel()

	l, ok := loggerConfigured(t, WithLogRedactor(nil)).(redactingLogger)
	if !ok || l.redact("SECRET") != "SECRET" {
		t.Errorf("logger = %#v, want a redactingLogger that leaves lines unchanged", l)
	}
}
