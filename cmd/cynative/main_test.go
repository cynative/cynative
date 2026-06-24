package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestMainFunc exercises main()'s success path. "--help" makes cobra print usage
// and return nil without running PersistentPreRunE, so main() returns without
// exiting non-zero or reading the real environment.
//
//nolint:paralleltest // mutates global os.Args to drive main() hermetically
func TestMainFunc(_ *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }() //nolint:reassign // restoring original os.Args

	os.Args = []string{"cynative", "--help"} //nolint:reassign // hermetic help invocation

	main()
}

func TestMainFunc_Error(t *testing.T) {
	t.Parallel()

	//nolint:forbidigo // subprocess re-exec idiom: detect the child invocation that runs main().
	if os.Getenv("TEST_MAIN_ERROR") == "1" {
		os.Args = []string{"cynative", "--definitely-not-a-flag"} //nolint:reassign // hermetic unknown-flag error
		main()

		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainFunc_Error")
	//nolint:forbidigo // subprocess re-exec idiom: forward the parent environment to the child main().
	cmd.Env = append(os.Environ(), "TEST_MAIN_ERROR=1")

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected process to exit with error")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}

	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}
