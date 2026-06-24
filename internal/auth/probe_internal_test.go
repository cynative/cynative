package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// timeoutError is a [net.Error] reporting Timeout() == true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// statusError models an SDK response error exposing an HTTP status code (the
// shape AWS smithy response errors implement).
type statusError struct{ code int }

func (e statusError) Error() string       { return fmt.Sprintf("http %d", e.code) }
func (e statusError) HTTPStatusCode() int { return e.code }

func TestIsTransientProbeErr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline", context.DeadlineExceeded, true},
		{"canceled", context.Canceled, true},
		// string match must NOT count — only errors.Is/As unwrapping:
		{"wrapped deadline", errors.New("probe: " + context.DeadlineExceeded.Error()), false},
		{"errorf-wrapped deadline", wrap(context.DeadlineExceeded), true},
		{"net timeout", timeoutError{}, true},
		{"http 503", statusError{503}, true},
		{"http 429", statusError{429}, true},
		{"http 404", statusError{404}, false},
		{"plain denied", errors.New("AccessDenied"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := isTransientProbeErr(c.err); got != c.want {
				t.Fatalf("isTransientProbeErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func wrap(err error) error { return errWrapError{err} }

type errWrapError struct{ err error }

func (e errWrapError) Error() string { return "probe: " + e.err.Error() }
func (e errWrapError) Unwrap() error { return e.err }

func TestEscalateForTransient(t *testing.T) {
	t.Parallel()

	if got := escalateForTransient(emitWhenExplicitOrVerbose, context.DeadlineExceeded); got != emitAlways {
		t.Fatalf("transient must escalate to emitAlways, got %v", got)
	}
	if got := escalateForTransient(emitWhenExplicitOrVerbose, errors.New("denied")); got != emitWhenExplicitOrVerbose {
		t.Fatalf("non-transient must keep policy, got %v", got)
	}
	if got := escalateForTransient(emitAlways, nil); got != emitAlways {
		t.Fatalf("nil err keeps policy, got %v", got)
	}
}

func TestRetryProbe(t *testing.T) {
	t.Parallel()

	t.Run("success first try runs once", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryProbe(func() error { calls++; return nil })
		if err != nil || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})

	t.Run("non-transient failure runs once", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryProbe(func() error { calls++; return errors.New("denied") })
		if err == nil || calls != 1 {
			t.Fatalf("err=%v calls=%d (must not retry non-transient)", err, calls)
		}
	})

	t.Run("transient failure retries once", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryProbe(func() error {
			calls++
			if calls == 1 {
				return context.DeadlineExceeded
			}
			return nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("err=%v calls=%d (must retry transient once)", err, calls)
		}
	})

	t.Run("transient twice returns second error", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := retryProbe(func() error { calls++; return context.DeadlineExceeded })
		if !errors.Is(err, context.DeadlineExceeded) || calls != 2 {
			t.Fatalf("err=%v calls=%d (retry once then give up)", err, calls)
		}
	})
}
