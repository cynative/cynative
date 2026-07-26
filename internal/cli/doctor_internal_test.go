package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

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
	if got := u.llmStatuses[0].Reason; got != "configuration valid; connectivity not tested" {
		t.Errorf("LLM Reason = %q, want connectivity-not-tested wording", got)
	}
	out := errBuf.String()
	if !strings.Contains(out, "Doctor: ready") {
		t.Errorf("stderr missing Doctor: ready; got %q", out)
	}
	if !strings.Contains(out, "live read-only network calls") {
		t.Errorf("stderr missing live-network note; got %q", out)
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
}

func TestDoctor_ActionableConnectorFailure(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
		onStatus(auth.ConnectorStatus{ //nolint:exhaustruct // actionable skip.
			Name: "aws", Reason: "aws_hardening: skipped (config load failed): boom", Actionable: true,
		})
		onStatus(auth.ConnectorStatus{ //nolint:exhaustruct // healthy connector.
			Name: "github", Available: true, Identity: "@me",
		})

		return nil
	}

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	_, err := runWithArgs(t, d, []string{"doctor"})
	if !errors.Is(err, ErrDoctorNotReady) {
		t.Fatalf("err = %v, want ErrDoctorNotReady", err)
	}
	if ExitCodeFor(err) != 1 {
		t.Errorf("ExitCodeFor = %d, want 1", ExitCodeFor(err))
	}
	out := errBuf.String()
	if !strings.Contains(out, "Doctor: not ready (connector failures: aws)") {
		t.Errorf("stderr missing actionable failure summary; got %q", out)
	}
	if strings.Contains(out, "Doctor: ready\n") {
		t.Errorf("must not print Doctor: ready on actionable failure; got %q", out)
	}
}

func TestDoctor_AmbientSkipDoesNotFailEvenWhenVerbose(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"doctor"}, {"doctor", "-v"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			d := testDeps()
			d.getProviders = func(_ auth.HardeningConfig, _ bool, onStatus func(auth.ConnectorStatus)) []auth.Provider {
				// Ambient absence: shown under -v, but Actionable=false so readiness
				// must stay green either way.
				onStatus(auth.ConnectorStatus{ //nolint:exhaustruct // ambient skip.
					Name: "gcp", Reason: "gcp_hardening: skipped (no usable credentials)", Actionable: false,
				})

				return nil
			}

			var errBuf bytes.Buffer

			d.errOut = &errBuf

			_, err := runWithArgs(t, d, args)
			if err != nil {
				t.Fatalf("%v: %v", args, err)
			}
			if !strings.Contains(errBuf.String(), "Doctor: ready") {
				t.Errorf("%v: want Doctor: ready; got %q", args, errBuf.String())
			}
		})
	}
}

func TestConnectorHealthFromViews(t *testing.T) {
	t.Parallel()

	h := connectorHealthFromViews([]ui.ConnectorView{
		{State: ui.ConnectorOK, Name: "github"},                    //nolint:exhaustruct // ok line
		{State: ui.ConnectorError, Name: "gcp", Actionable: false}, //nolint:exhaustruct // ambient
		{State: ui.ConnectorError, Name: "aws", Actionable: true},  //nolint:exhaustruct // fail
		{State: ui.ConnectorWarn, Name: "gitlab"},                  //nolint:exhaustruct // warn ok
	})
	if h.ok() {
		t.Fatal("health with actionable failure must not be ok")
	}
	if got, want := strings.Join(h.actionableFailures, ","), "aws"; got != want {
		t.Errorf("actionableFailures = %q, want %q", got, want)
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
	for _, want := range []string{"Validate configuration", "connector", "verbose", "live-llm", "live read-only"} {
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

func TestDoctor_LiveLLM_OK(t *testing.T) {
	t.Parallel()

	const nonce = "DOCTOR-TESTNONCE"

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newDoctorProbeNonce = func() string { return nonce }
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs/calls not pre-set
			responses: []*schema.Message{schema.AssistantMessage(nonce, nil)},
		}, nil
	}

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if err != nil {
		t.Fatalf("doctor --live-llm: %v", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("llmStatuses = %+v, want one OK status", u.llmStatuses)
	}
	if got := u.llmStatuses[0].Reason; got != "configuration valid; connectivity verified" {
		t.Errorf("LLM Reason = %q, want connectivity-verified wording", got)
	}
	if !strings.Contains(errBuf.String(), "Doctor: ready") {
		t.Errorf("stderr missing Doctor: ready; got %q", errBuf.String())
	}
}

func TestDoctor_LiveLLM_CaseInsensitiveNonce(t *testing.T) {
	t.Parallel()

	const nonce = "DOCTOR-AbCdEf"

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newDoctorProbeNonce = func() string { return nonce }
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs unused
			responses: []*schema.Message{schema.AssistantMessage(strings.ToLower(nonce), nil)},
		}, nil
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if err != nil {
		t.Fatalf("doctor --live-llm with case-folded echo: %v", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorOK {
		t.Errorf("llmStatuses = %+v, want one OK status", u.llmStatuses)
	}
}

func TestDoctor_LiveLLM_InitFailure(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return nil, errors.New("bifrost init failed")
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("llmStatuses = %+v, want one Error status", u.llmStatuses)
	}
	if ExitCodeFor(err) != 1 {
		t.Errorf("ExitCodeFor = %d, want 1", ExitCodeFor(err))
	}
}

func TestDoctor_LiveLLM_GenerateFailure(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newDoctorProbeNonce = func() string { return "DOCTOR-TESTNONCE" }
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // responses unused
			errs: []error{errors.New("provider down")},
		}, nil
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("llmStatuses = %+v, want one Error status", u.llmStatuses)
	}
}

func TestDoctor_LiveLLM_VerbosePrintsDetails(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newDoctorProbeNonce = func() string { return "DOCTOR-TESTNONCE" }
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // responses unused
			errs: []error{errors.New("upstream timeout from gateway")},
		}, nil
	}

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm", "-v"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if !strings.Contains(errBuf.String(), "details: upstream timeout from gateway") {
		t.Errorf("stderr missing verbose details; got %q", errBuf.String())
	}
}

func TestDoctor_LiveLLM_InitFailureVerbosePrintsDetails(t *testing.T) {
	t.Parallel()

	const leak = "sk-ABCDEFGHIJ0123456789abcd"
	d := testDeps()
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return nil, errors.New("bifrost init failed: Incorrect API key: " + leak)
	}

	var errBuf bytes.Buffer

	d.errOut = &errBuf

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm", "-v"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	out := errBuf.String()
	if !strings.Contains(out, "details:") {
		t.Errorf("stderr missing verbose details; got %q", out)
	}
	if strings.Contains(out, leak) {
		t.Errorf("verbose details must redact credential-shaped text; got %q", out)
	}
	if !strings.Contains(out, "[REDACTED:llm-api-key]") {
		t.Errorf("verbose details missing llm-api-key redaction; got %q", out)
	}
}

func TestDoctorLiveProbeConfig(t *testing.T) {
	t.Parallel()

	cfg := validCfg()
	cfg.LLM.NetworkConfig.MaxRetries = 3
	cfg.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds = 300

	got := doctorLiveProbeConfig(cfg, 30*time.Second)
	if got.LLM.NetworkConfig.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d, want 0", got.LLM.NetworkConfig.MaxRetries)
	}
	if got.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds != 30 {
		t.Errorf("timeout = %d, want 30", got.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds)
	}
	if cfg.LLM.NetworkConfig.MaxRetries != 3 {
		t.Error("doctorLiveProbeConfig must not mutate the caller's config")
	}

	tiny := doctorLiveProbeConfig(cfg, time.Millisecond)
	if tiny.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds != 1 {
		t.Errorf("sub-second timeout must clamp to 1s, got %d",
			tiny.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds)
	}
}

func TestDoctor_LiveLLM_NonceMismatch(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.newDoctorProbeNonce = func() string { return "DOCTOR-EXPECTED" }
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &fakeChatModel{ //nolint:exhaustruct // errs unused
			responses: []*schema.Message{schema.AssistantMessage("unrelated answer", nil)},
		}, nil
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].Reason != "live probe response mismatch" {
		t.Errorf("llmStatuses = %+v, want mismatch reason", u.llmStatuses)
	}
}

func TestDoctor_LiveLLM_SkippedWhenValidateLLMFails(t *testing.T) {
	t.Parallel()

	called := false
	d := testDeps()
	d.loadConfig = func(string) (config.Config, error) {
		return config.Config{}, nil //nolint:exhaustruct // empty LLM triggers ValidateLLM
	}
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		called = true

		return nil, errors.New("must not construct")
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if called {
		t.Fatal("--live-llm must not probe before ValidateLLM passes")
	}
}

func TestDoctor_LiveLLM_BoundsProbeContext(t *testing.T) {
	t.Parallel()

	d := testDeps()
	var remaining time.Duration
	var hadDeadline bool
	gotRetries := -1
	var gotTimeout int
	d.newChatModel = func(ctx context.Context, cfg config.Config, _ func(schema.Usage)) (chatModel, error) {
		if dl, ok := ctx.Deadline(); ok {
			hadDeadline = true
			remaining = time.Until(dl)
		}
		gotRetries = cfg.LLM.NetworkConfig.MaxRetries
		gotTimeout = cfg.LLM.NetworkConfig.DefaultRequestTimeoutInSeconds

		return &fakeChatModel{ //nolint:exhaustruct // errs unused
			responses: []*schema.Message{schema.AssistantMessage("DOCTOR-TEST-DEFAULT", nil)},
		}, nil
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if err != nil {
		t.Fatalf("doctor --live-llm: %v", err)
	}
	// Pin the production const (~30s): a wrong default would hang diagnostics.
	if !hadDeadline || remaining <= 29*time.Second || remaining > 30*time.Second {
		t.Fatalf("hadDeadline=%v remaining=%v, want in (29s, 30s]", hadDeadline, remaining)
	}
	if gotRetries != 0 {
		t.Errorf("MaxRetries = %d, want 0 for the live probe", gotRetries)
	}
	if gotTimeout != 30 {
		t.Errorf("DefaultRequestTimeoutInSeconds = %d, want 30", gotTimeout)
	}
}

func TestDoctor_LiveLLM_ProbeTimeout(t *testing.T) {
	t.Parallel()

	u := &fakeUI{} //nolint:exhaustruct // recorders zero.
	d := testDeps()
	d.ui = u
	d.doctorLiveProbeTimeout = time.Millisecond
	d.newChatModel = func(context.Context, config.Config, func(schema.Usage)) (chatModel, error) {
		return &seqBlockThenAnswerModel{answer: "unused"}, nil //nolint:exhaustruct // calls zero
	}

	_, err := runWithArgs(t, d, []string{"doctor", "--live-llm"})
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Fatalf("err = %v, want ErrLLMUnavailable", err)
	}
	if len(u.llmStatuses) != 1 || u.llmStatuses[0].State != ui.ConnectorError {
		t.Errorf("llmStatuses = %+v, want one Error status", u.llmStatuses)
	}
}

func TestSilenceGracefulStop_DoctorNotReady(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{} //nolint:exhaustruct // SilenceErrors only
	err := silenceGracefulStop(cmd, ErrDoctorNotReady)
	if !errors.Is(err, ErrDoctorNotReady) {
		t.Fatalf("err = %v", err)
	}
	if !cmd.SilenceErrors {
		t.Error("SilenceErrors should be set for ErrDoctorNotReady")
	}
}
