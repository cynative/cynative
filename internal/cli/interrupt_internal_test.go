package cli

import "testing"

func TestSignalAction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		isTerm      bool
		kill        bool
		wantRestore bool
		wantExit    bool
		wantCode    int
	}{
		{"sigterm always exits", true, false, true, true, exitTerminated},
		{"sigint kill exits", false, true, true, true, exitInterrupted},
		{"sigint graceful no exit", false, false, false, false, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			r, e, code := signalAction(c.isTerm, c.kill)
			if r != c.wantRestore || e != c.wantExit || code != c.wantCode {
				t.Errorf("signalAction(%v,%v) = (%v,%v,%d), want (%v,%v,%d)",
					c.isTerm, c.kill, r, e, code, c.wantRestore, c.wantExit, c.wantCode)
			}
		})
	}
}
