package audit

import (
	"errors"
	"testing"
)

type brokenWriter struct{ n int }

func (w *brokenWriter) Write([]byte) (int, error) {
	w.n++

	return 0, errors.New("disk full")
}

// TestLogger_Log_LatchedCallsDoNotAdvanceSeq pins that a call refused by the latch leaves seq where the failed
// write left it, so no sequence number is spent on a record that was never attempted.
func TestLogger_Log_LatchedCallsDoNotAdvanceSeq(t *testing.T) {
	t.Parallel()

	w := &brokenWriter{}
	l := New(w)
	for range 3 {
		_ = l.Log(Record{Tool: "x"}) //nolint:exhaustruct // Logger stamps the rest.
	}
	if l.seq != 1 || w.n != 1 {
		t.Errorf("seq = %d after %d writes, want 1 and 1", l.seq, w.n)
	}
}
