package authreq_test

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

var errGate = errors.New("gate: no match")

func TestUnmatchedRequestError_PassesThrough(t *testing.T) {
	t.Parallel()

	var err error = &authreq.UnmatchedRequestError{Service: "route53", Err: errGate}
	if err.Error() != "gate: no match" {
		t.Errorf("Error() = %q", err.Error())
	}
	if !errors.Is(err, errGate) {
		t.Error("errors.Is must reach the wrapped gate error")
	}
	var um *authreq.UnmatchedRequestError
	if !errors.As(err, &um) || um.Service != "route53" {
		t.Errorf("errors.As = %v, %+v", errors.As(err, &um), um)
	}
}
