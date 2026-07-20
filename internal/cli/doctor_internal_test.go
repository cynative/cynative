package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/ui"
)

func TestDoctor_OK(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		onStatus(auth.ConnectorStatus{ //nolint:exhaustruct // display fields only.
			Name: "github", Available: true, Identity: "@me", Posture: "default=read",
		})

		return nil
	}

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	buf, err := runWithArgs(t, d, []string{"doctor"})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("doctor must write diagnostics to stderr only; stdout = %q", buf.String())
	}
	if u.bannerCalls != 1 {
		t.Errorf("RenderBanner called %d times, want 1", u.bannerCalls)
	}
	if len(u.connectorViews) != 1 || u.connectorViews[0].Name != "github" {
		t.Errorf("connectorViews = %+v, want one github view", u.connectorViews)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("llmStatuses = %+v, want one OK status", u.llmStatuses)
	}
	if !strings.Contains(errBuf.String(), "Doctor: ready") {
		t.Errorf("stderr missing Doctor: ready; got %q", errBuf.String())
	}
}

func TestDoctor_LLMInvalid(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.loadConfig = func(string) (config.Config, error) {
		return config.Config{}, nil //nolint:exhaustruct // empty LLM triggers ValidateLLM
	}

	_, err := runWithArgs(t, d, []string{"doctor"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(u.llmStatuses) != 1 || !u.llmStatuses[0].NotConfigured {
		t.Errorf("llmStatuses = %+v, want NotConfigured onboarding status", u.llmStatuses)
	}
	if ExitCodeFor(err) != 1 {
		t.Errorf("ExitCodeFor = %d, want 1", ExitCodeFor(err))
	}
}

func TestDoctor_ConfigLoadError(t *testing.T) {
	t.Parallel()

	loadErr := errors.New("no config")
	d := testDeps()
	d.loadConfig = func(string) (config.Config, error) {
		return config.Config{}, loadErr //nolint:exhaustruct // error path
	}

	_, err := runWithArgs(t, d, []string{"doctor"})
	if !errors.Is(err, loadErr) {
		t.Fatalf("err = %v, want %v", err, loadErr)
	}
}

func TestDoctor_NoConnectors(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	_, err := runWithArgs(t, d, []string{"doctor"})
	if err != nil {
		t.Fatalf("doctor with no connectors must succeed when LLM is valid: %v", err)
	}
	if !strings.Contains(errBuf.String(), "(no connectors detected)") {
		t.Errorf("stderr missing empty-inventory notice; got %q", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "Doctor: ready") {
		t.Errorf("stderr missing Doctor: ready; got %q", errBuf.String())
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("llmStatuses = %+v, want OK", u.llmStatuses)
	}
}

func TestDoctor_VerbosePassedToProviders(t *testing.T) {
	t.Parallel()

	d := testDeps()
	got := captureHardening(d)

	_, err := runWithArgs(t, d, []string{"doctor", "-v"})
	if err != nil {
		t.Fatalf("doctor -v: %v", err)
	}
	if !got.verbose {
		t.Error("doctor -v must pass verbose=true to getProviders")
	}
}

func TestDoctor_RejectsExtraArgs(t *testing.T) {
	t.Parallel()

	_, err := runWithArgs(t, testDeps(), []string{"doctor", "extra"})
	if err == nil {
		t.Fatal("doctor with extra args must error")
	}
}

func TestDoctor_Help(t *testing.T) {
	t.Parallel()

	buf, err := runWithArgs(t, testDeps(), []string{"doctor", "--help"})
	if err != nil {
		t.Fatalf("doctor --help: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Validate configuration", "connector", "verbose"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor help missing %q; got:\n%s", want, out)
		}
	}
}

func TestDoctor_DoesNotCallChatModel(t *testing.T) {
	t.Parallel()

	d := testDeps()
	called := false
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		called = true

		return nil, errors.New("chat model must not be constructed")
	}

	_, err := runWithArgs(t, d, []string{"doctor"})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if called {
		t.Fatal("doctor must not construct a chat model")
	}
}
