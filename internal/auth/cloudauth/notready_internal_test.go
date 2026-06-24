package cloudauth

import (
	"errors"
	"strings"
	"testing"
)

func TestNotReady(t *testing.T) {
	t.Parallel()

	cause := errors.New("boom")

	err := NotReady("aws_hardening", "policy fetch", cause)

	if !errors.Is(err, cause) {
		t.Errorf("returned error must wrap the cause via %%w, got %v", err)
	}
	if !strings.Contains(err.Error(), "aws_hardening: policy fetch: ") {
		t.Errorf("returned error = %q, want the <prefix>: <step>: prefix", err.Error())
	}
}
