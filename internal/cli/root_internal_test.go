package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/config"
)

//nolint:paralleltest // mutates global os.Args to drive the real Execute hermetically
func TestExecute(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }() //nolint:reassign // restoring original os.Args

	// "--help" makes cobra print usage and return nil without running
	// PersistentPreRunE, so Execute's success path is exercised without reading
	// the real environment (config loading is skipped for --help).
	os.Args = []string{"cynative", "--help"} //nolint:reassign // hermetic help invocation

	if err := Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

//nolint:paralleltest // mutates global os.Args via Execute's production wiring
func TestExecuteError(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }() //nolint:reassign // restoring original os.Args

	os.Args = []string{"cynative", "--definitely-not-a-flag"} //nolint:reassign // hermetic unknown-flag error

	err := Execute()
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestNewRootCmd_Help(t *testing.T) {
	t.Parallel()

	rootCmd := NewRootCmd(testDeps())

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agentic security research tool") {
		t.Errorf("expected help output to contain 'Agentic security research tool', got: %s", output)
	}
}

func TestNewRootCmd_Research(t *testing.T) {
	t.Parallel()

	var called bool

	d := testDeps()
	d.run = func(_ context.Context, task string, _ config.Config, _ researchFlags) error {
		called = true

		if task != "test task" {
			t.Errorf("expected task 'test task', got %q", task)
		}

		return nil
	}

	rootCmd := NewRootCmd(d)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"-p", "test task"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !called {
		t.Error("expected run to be called")
	}
}

func TestNewRootCmd_ConfigLoadError(t *testing.T) {
	t.Parallel()

	// A config load failure in PersistentPreRunE aborts before the research command
	// runs. We inject a loadConfig that errors to exercise that path hermetically.
	loadErr := errors.New("config load boom")

	d := testDeps()
	d.loadConfig = func(string) (config.Config, error) { return config.Config{}, loadErr } //nolint:exhaustruct // error path

	rootCmd := NewRootCmd(d)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"-p", "test task"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when config load fails")
	}

	if !errors.Is(err, loadErr) {
		t.Errorf("expected wrapped loadErr, got: %v", err)
	}
}

// TestNewRootCmd_ConfigLoadError_RealLoader exercises the real config loader
// through a malformed YAML file, with a hermetic (empty) env so no CYNATIVE_*
// var leaks in. This covers the loadConfig wiring against the production loader.
func TestNewRootCmd_ConfigLoadError_RealLoader(t *testing.T) {
	t.Parallel()

	cfgPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte(":\n  not: valid: yaml: ["), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := testDeps()
	d.loadConfig = func(path string) (config.Config, error) {
		return config.NewLoader(func(string) (string, bool) { return "", false }).Load(path)
	}

	rootCmd := NewRootCmd(d)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "-p", "test task"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when config load fails")
	}
}

func TestSilenceGracefulStop_SuppressesInterruptPrint(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{} //nolint:exhaustruct // only SilenceErrors is under test.
	err := silenceGracefulStop(cmd, fmt.Errorf("research run failed: %w", agent.ErrInterrupted))
	if !errors.Is(err, agent.ErrInterrupted) {
		t.Errorf("must return the interrupt error so ExitCodeFor maps it to 130, got %v", err)
	}
	if !cmd.SilenceErrors {
		t.Error("a graceful stop must set SilenceErrors so Cobra does not print a duplicate line")
	}
}

func TestSilenceGracefulStop_PassesOtherErrorsThrough(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{} //nolint:exhaustruct // only SilenceErrors is under test.
	err := silenceGracefulStop(cmd, errors.New("boom"))
	if err == nil || err.Error() != "boom" {
		t.Errorf("non-interrupt error must pass through unchanged, got %v", err)
	}
	if cmd.SilenceErrors {
		t.Error("a non-interrupt error must still print (SilenceErrors stays false)")
	}
}

func TestSilenceGracefulStop_NilPassesThrough(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{} //nolint:exhaustruct // only SilenceErrors is under test.
	if err := silenceGracefulStop(cmd, nil); err != nil {
		t.Errorf("nil must pass through, got %v", err)
	}
	if cmd.SilenceErrors {
		t.Error("nil must not silence errors")
	}
}

func TestSilenceGracefulStop_SilencesLLMUnavailable(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{} //nolint:exhaustruct // only SilenceErrors is under test.
	err := silenceGracefulStop(cmd, ErrLLMUnavailable)
	if !errors.Is(err, ErrLLMUnavailable) {
		t.Errorf("error should pass through: %v", err)
	}
	if !cmd.SilenceErrors {
		t.Error("SilenceErrors should be set for ErrLLMUnavailable (no duplicate cobra Error line)")
	}
	if ExitCodeFor(ErrLLMUnavailable) != 1 {
		t.Errorf("ExitCodeFor(ErrLLMUnavailable) = %d, want 1", ExitCodeFor(ErrLLMUnavailable))
	}
}
