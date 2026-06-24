package audit

import (
	"errors"
	"testing"
	"time"
)

func TestRotateDueByAge(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	tests := []struct {
		name      string
		oldest    time.Time
		now       time.Time
		retention time.Duration
		want      bool
	}{
		{"disabled retention zero", base.Add(-100 * day), base, 0, false},
		{"disabled retention negative", base.Add(-100 * day), base, -day, false},
		{"oldest unknown", time.Time{}, base, day, false},
		{"younger than retention", base.Add(-12 * time.Hour), base, day, false},
		{"exactly retention", base.Add(-day), base, day, true},
		{"older than retention", base.Add(-3 * day), base, day, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := rotateDueByAge(tt.oldest, tt.now, tt.retention); got != tt.want {
				t.Errorf("rotateDueByAge(%v,%v,%v) = %v, want %v",
					tt.oldest, tt.now, tt.retention, got, tt.want)
			}
		})
	}
}

func TestRetentionFromDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		days int
		want time.Duration
	}{
		{"zero", 0, 0},
		{"one day", 1, 24 * time.Hour},
		{"thirty days", 30, 30 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := retentionFromDays(tt.days); got != tt.want {
				t.Errorf("retentionFromDays(%d) = %v, want %v", tt.days, got, tt.want)
			}
		})
	}
}

func TestParseFirstRecordTime(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 6, 19, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name   string
		line   []byte
		wantOK bool
	}{
		{"valid record", []byte(`{"time":"2026-06-19T09:30:00Z","seq":1,"actor":"x"}` + "\n"), true},
		{"extra fields ignored", []byte(`{"actor":"x","time":"2026-06-19T09:30:00Z","result":"y"}`), true},
		{"empty", []byte(""), false},
		{"whitespace only", []byte("   \n"), false},
		{"malformed json", []byte("{not json"), false},
		{"no time field", []byte(`{"seq":1,"actor":"x"}`), false},
		{"zero time", []byte(`{"time":"0001-01-01T00:00:00Z"}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseFirstRecordTime(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && !got.Equal(want) {
				t.Errorf("time = %v, want %v", got, want)
			}
		})
	}
}

type fakeRotator struct {
	writes    [][]byte
	rotates   int
	writeErr  error
	rotateErr error
	closeErr  error
}

func (f *fakeRotator) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeRotator) Rotate() error { f.rotates++; return f.rotateErr }
func (f *fakeRotator) Close() error  { return f.closeErr }

func TestAgeRotatingWriter_FreshFileAnchorsThenNoRotate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fr := &fakeRotator{}
	w := newAgeRotatingWriter(fr, clock, 24*time.Hour, time.Time{})

	if _, err := w.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fr.rotates != 0 {
		t.Fatalf("fresh file should not rotate, got %d", fr.rotates)
	}
	// Anchored at now; a second write a few hours later still within retention.
	now = now.Add(6 * time.Hour)
	if _, err := w.Write([]byte("b")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fr.rotates != 0 {
		t.Fatalf("within retention should not rotate, got %d", fr.rotates)
	}
	if len(fr.writes) != 2 {
		t.Fatalf("want 2 writes, got %d", len(fr.writes))
	}
}

func TestAgeRotatingWriter_StaleSeedRotatesOnceThenReanchors(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fr := &fakeRotator{}
	// Seeded oldest = 3 days ago, retention = 1 day → first write rotates.
	w := newAgeRotatingWriter(fr, clock, 24*time.Hour, now.Add(-72*time.Hour))

	if _, err := w.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fr.rotates != 1 {
		t.Fatalf("stale seed should rotate once, got %d", fr.rotates)
	}
	// Re-anchored at now; a write within retention does not rotate again.
	now = now.Add(6 * time.Hour)
	if _, err := w.Write([]byte("b")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fr.rotates != 1 {
		t.Fatalf("want still 1 rotate, got %d", fr.rotates)
	}
}

func TestAgeRotatingWriter_RotateErrorIsFailClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fr := &fakeRotator{rotateErr: errors.New("rename failed")}
	w := newAgeRotatingWriter(fr, func() time.Time { return now }, 24*time.Hour, now.Add(-72*time.Hour))

	if _, err := w.Write([]byte("a")); err == nil {
		t.Fatal("expected write to fail closed when rotate fails")
	}
	if len(fr.writes) != 0 {
		t.Fatalf("no record should be written after a failed rotate, got %d", len(fr.writes))
	}
}

func TestAgeRotatingWriter_DisabledNeverRotates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fr := &fakeRotator{}
	// retention 0 = disabled; even a very old seed must not rotate.
	w := newAgeRotatingWriter(fr, func() time.Time { return now }, 0, now.Add(-1000*time.Hour))

	if _, err := w.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fr.rotates != 0 {
		t.Fatalf("disabled retention must not rotate, got %d", fr.rotates)
	}
}

func TestAgeRotatingWriter_WriteErrorDoesNotAnchor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fr := &fakeRotator{writeErr: errors.New("disk full")}
	w := newAgeRotatingWriter(fr, func() time.Time { return now }, 24*time.Hour, time.Time{})

	if _, err := w.Write([]byte("a")); err == nil {
		t.Fatal("expected write error to propagate")
	}
	if !w.oldest.IsZero() {
		t.Fatal("anchor must stay unset after a failed write")
	}
}

func TestAgeRotatingWriter_CloseDelegates(t *testing.T) {
	t.Parallel()

	fr := &fakeRotator{closeErr: errors.New("boom")}
	w := newAgeRotatingWriter(fr, time.Now, 24*time.Hour, time.Time{})
	if err := w.Close(); err == nil {
		t.Fatal("expected Close to surface the inner error")
	}
}
