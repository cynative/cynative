package audit

import "time"

// WithClock injects a deterministic clock (test seam); nil is ignored.
func WithClock(c func() time.Time) Option {
	return func(l *Logger) {
		if c != nil {
			l.clock = c
		}
	}
}

// WithRedactor injects a redactor (test seam); nil is ignored.
func WithRedactor(r redactor) Option {
	return func(l *Logger) {
		if r != nil {
			l.redactor = r
		}
	}
}
