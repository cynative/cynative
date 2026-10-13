package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRecordLoadFailure_KeepsTheLastFetchError pins that the recorder holds the last fetch error, clears it on a
// later success, and that a nil recorder reports nothing.
func TestRecordLoadFailure_KeepsTheLastFetchError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	var calls atomic.Int32
	c := newCache(t.TempDir(), time.Now, func(context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, boom
		}

		return []byte(goodRaw), nil
	})
	f := RecordLoadFailure(c)
	if err := f.Err(); err != nil {
		t.Fatalf("before any fetch: %v", err)
	}
	if c.Get(t.Context()) != nil || !errors.Is(f.Err(), boom) {
		t.Fatalf("after a failure: %v", f.Err())
	}
	if c.Get(t.Context()) == nil || f.Err() != nil {
		t.Fatalf("after a success: %v", f.Err())
	}
	var none *LoadFailure
	if none.Err() != nil {
		t.Errorf("nil recorder: %v", none.Err())
	}
}
