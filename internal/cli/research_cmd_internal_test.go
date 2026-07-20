package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/config"
)

func runWithArgs(t *testing.T, d *deps, args []string) (*bytes.Buffer, error) {
	t.Helper()

	rootCmd := NewRootCmd(d)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	return buf, rootCmd.Execute()
}

func TestRootCmd_PrintFlagOneShot(t *testing.T) {
	t.Parallel()

	var got struct {
		task        string
		interactive bool
	}

	d := testDeps()
	d.run = func(_ context.Context, task string, _ config.Config, f researchFlags) error {
		got.task, got.interactive = task, f.interactive

		return nil
	}

	if _, err := runWithArgs(t, d, []string{"-p", "audit s3"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.task != "audit s3" || got.interactive {
		t.Errorf("got {task:%q interactive:%v}, want {task:%q interactive:false}",
			got.task, got.interactive, "audit s3")
	}
}

func TestRootCmd_BareInteractive(t *testing.T) {
	t.Parallel()

	var got struct {
		task        string
		interactive bool
	}

	d := testDeps()
	d.run = func(_ context.Context, task string, _ config.Config, f researchFlags) error {
		got.task, got.interactive = task, f.interactive

		return nil
	}

	if _, err := runWithArgs(t, d, []string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.task != "" || !got.interactive {
		t.Errorf("got {task:%q interactive:%v}, want {task:\"\" interactive:true}", got.task, got.interactive)
	}
}

func TestRootCmd_SeededInteractive(t *testing.T) {
	t.Parallel()

	var got struct {
		task        string
		interactive bool
	}

	d := testDeps()
	d.run = func(_ context.Context, task string, _ config.Config, f researchFlags) error {
		got.task, got.interactive = task, f.interactive

		return nil
	}

	if _, err := runWithArgs(t, d, []string{"start here"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.task != "start here" || !got.interactive {
		t.Errorf("got {task:%q interactive:%v}, want {task:%q interactive:true}",
			got.task, got.interactive, "start here")
	}
}

func TestRootCmd_PipedStdinOneShot(t *testing.T) {
	t.Parallel()

	var gotTask string

	d := testDeps()
	d.stdinIsTTY = false
	d.readStdin = func() (string, bool, error) { return "piped task", false, nil }
	d.run = func(_ context.Context, task string, _ config.Config, _ researchFlags) error {
		gotTask = task

		return nil
	}

	if _, err := runWithArgs(t, d, []string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTask != "piped task" {
		t.Errorf("got task %q, want %q", gotTask, "piped task")
	}
}

func TestRootCmd_StdinTruncationThreads(t *testing.T) {
	t.Parallel()

	var gotTask string

	d := testDeps()
	d.stdinIsTTY = false
	d.readStdin = func() (string, bool, error) { return "huge", true, nil }
	d.run = func(_ context.Context, task string, _ config.Config, _ researchFlags) error {
		gotTask = task

		return nil
	}

	if _, err := runWithArgs(t, d, []string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotTask, "[stdin truncated at 1 MiB]") {
		t.Errorf("expected truncation marker threaded into task, got %q", gotTask)
	}
}

func TestRootCmd_NoTaskError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.run = func(context.Context, string, config.Config, researchFlags) error {
		t.Fatal("run must not be called when there is no task")

		return nil
	}

	_, err := runWithArgs(t, d, []string{"-p"})
	if !errors.Is(err, ErrNoTask) {
		t.Fatalf("expected ErrNoTask, got: %v", err)
	}
}

func TestRootCmd_NoApprovalTerminalError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.stdinIsTTY = false
	d.hasTerminal = false
	d.readStdin = func() (string, bool, error) {
		t.Fatal("readStdin must not be called when failing closed on no approval terminal")

		return "", false, nil
	}

	_, err := runWithArgs(t, d, []string{"-p"})
	if !errors.Is(err, ErrNoApprovalTerminal) {
		t.Fatalf("expected ErrNoApprovalTerminal, got: %v", err)
	}
}

func TestRootCmd_ReadStdinError(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.stdinIsTTY = false
	d.readStdin = func() (string, bool, error) { return "", false, errors.New("boom") }

	_, err := runWithArgs(t, d, []string{"-p"})
	if err == nil || !strings.Contains(err.Error(), "read stdin") {
		t.Fatalf("expected wrapped read stdin error, got: %v", err)
	}
}

func TestRootCmd_TooManyArgs(t *testing.T) {
	t.Parallel()

	buf, err := runWithArgs(t, testDeps(), []string{"one", "two"})
	if err == nil {
		t.Fatal("expected an error for too many args")
	}
	if !strings.Contains(buf.String()+err.Error(), "accepts at most 1 arg") {
		t.Errorf("expected arg-count error, got: %v / %s", err, buf.String())
	}
}

func TestRootCmd_HelpShowsPrintFlag(t *testing.T) {
	t.Parallel()

	buf, err := runWithArgs(t, testDeps(), []string{"--help"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"--print", "-p", "--auto-approve", "--verbose", "Available Commands", "doctor"} {
		if !strings.Contains(out, want) {
			t.Errorf("help should mention %q, got:\n%s", want, out)
		}
	}
	// The removed -i flag must stay gone.
	if strings.Contains(out, "--interactive") {
		t.Errorf("help should not contain --interactive, got:\n%s", out)
	}
}
