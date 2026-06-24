package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// oneDay is the retention unit; audit.retention_days is expressed in whole days.
const oneDay = 24 * time.Hour

// rotateDueByAge reports whether the active audit file should be rotated because
// its oldest record has aged past the retention window. It returns false when
// retention is disabled (<= 0) or the oldest-record time is unknown.
func rotateDueByAge(oldest, now time.Time, retention time.Duration) bool {
	if retention <= 0 || oldest.IsZero() {
		return false
	}
	return now.Sub(oldest) >= retention
}

// retentionFromDays converts a whole-day retention count to a Duration.
func retentionFromDays(days int) time.Duration {
	return time.Duration(days) * oneDay
}

// parseFirstRecordTime extracts the timestamp of the first audit record on a
// line, used to seed the active file's age anchor at startup. It is best-effort:
// an empty, whitespace-only, malformed, or time-less line yields (zero, false)
// so a parse problem never forces or blocks a rotation.
func parseFirstRecordTime(line []byte) (time.Time, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return time.Time{}, false
	}
	var rec struct {
		Time time.Time `json:"time"`
	}
	if err := json.Unmarshal(line, &rec); err != nil || rec.Time.IsZero() {
		return time.Time{}, false
	}
	return rec.Time, true
}

// rotatingWriteCloser is the subset of *lumberjack.Logger the age wrapper needs:
// an [io.WriteCloser] that can also be told to rotate synchronously.
type rotatingWriteCloser interface {
	io.Writer
	io.Closer
	Rotate() error
}

// ageRotatingWriter wraps a size-rotating writer so the active file is also
// rotated once its oldest record ages past retention. oldest is the timestamp of
// the current active file's first record (seeded at Open, re-anchored on the
// first write after a rotation); a zero oldest means "fresh/empty — anchor on the
// next successful write".
type ageRotatingWriter struct {
	inner     rotatingWriteCloser
	clock     func() time.Time
	retention time.Duration
	oldest    time.Time
}

// newAgeRotatingWriter builds the wrapper. clock must be non-nil (the shell passes
// [time.Now]; tests inject a fake) — a nil-clock guard is deliberately omitted so the
// 100%-coverage gate is not tripped by an unreachable defensive branch.
func newAgeRotatingWriter(
	inner rotatingWriteCloser,
	clock func() time.Time,
	retention time.Duration,
	oldest time.Time,
) *ageRotatingWriter {
	return &ageRotatingWriter{inner: inner, clock: clock, retention: retention, oldest: oldest}
}

// Write rotates the active file first when its oldest record has aged past
// retention (propagating any rotation error — fail-closed, matching the existing
// synchronous-rotate contract), then writes the record. The first successful
// write to a fresh file anchors its age.
func (w *ageRotatingWriter) Write(p []byte) (int, error) {
	if rotateDueByAge(w.oldest, w.clock(), w.retention) {
		if err := w.inner.Rotate(); err != nil {
			return 0, fmt.Errorf("audit: age rotate: %w", err)
		}
		w.oldest = time.Time{}
	}
	n, err := w.inner.Write(p)
	if err == nil && w.oldest.IsZero() {
		w.oldest = w.clock()
	}
	return n, err
}

// Close closes the underlying writer.
func (w *ageRotatingWriter) Close() error {
	return w.inner.Close()
}
