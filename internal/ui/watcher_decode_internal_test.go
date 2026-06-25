//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import (
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/tools"
)

func TestKeyDecoder_CtrlC(t *testing.T) {
	t.Parallel()

	d := &keyDecoder{}
	got := d.next(byteCtrlC)

	if got.kind != evInterrupt {
		t.Fatalf("ctrl-c: want evInterrupt, got %v", got.kind)
	}
}

func TestKeyDecoder_LoneEsc(t *testing.T) {
	t.Parallel()

	d := &keyDecoder{}

	// Feeding ESC transitions to modeEsc; the byte itself yields evIgnore.
	e1 := d.next(byteEsc)
	if e1.kind != evIgnore {
		t.Fatalf("esc byte: want evIgnore, got %v", e1.kind)
	}
	if d.mode != modeEsc {
		t.Fatalf("after esc byte: want modeEsc, got %v", d.mode)
	}

	// A timeout resolves the pending Esc as interrupt and resets to ground.
	e2 := d.timeout()
	if e2.kind != evInterrupt {
		t.Fatalf("esc timeout: want evInterrupt, got %v", e2.kind)
	}
	if d.mode != modeGround {
		t.Fatalf("after esc timeout: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_CSIUpArrow(t *testing.T) {
	t.Parallel()

	// ESC [ A — cursor-up CSI sequence.
	d := &keyDecoder{}
	seq := []byte{byteEsc, '[', 'A'}
	for _, b := range seq {
		got := d.next(b)
		if got.kind != evIgnore {
			t.Fatalf("CSI up-arrow byte 0x%02x: want evIgnore, got %v", b, got.kind)
		}
	}
	if d.mode != modeGround {
		t.Fatalf("after CSI up-arrow: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_SS3F1(t *testing.T) {
	t.Parallel()

	// ESC O P — SS3 F1 sequence.
	d := &keyDecoder{}
	seq := []byte{byteEsc, 'O', 'P'}
	for _, b := range seq {
		got := d.next(b)
		if got.kind != evIgnore {
			t.Fatalf("SS3 F1 byte 0x%02x: want evIgnore, got %v", b, got.kind)
		}
	}
	if d.mode != modeGround {
		t.Fatalf("after SS3 F1: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_EscNonIntroducer(t *testing.T) {
	t.Parallel()

	// ESC x — not a CSI/SS3 introducer; the byte is dropped and we get evInterrupt.
	d := &keyDecoder{}
	e1 := d.next(byteEsc)
	if e1.kind != evIgnore {
		t.Fatalf("esc byte: want evIgnore, got %v", e1.kind)
	}
	e2 := d.next('x')
	if e2.kind != evInterrupt {
		t.Fatalf("esc+x: want evInterrupt, got %v", e2.kind)
	}
	if d.mode != modeGround {
		t.Fatalf("after esc+x: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_CSIWithIntermediates(t *testing.T) {
	t.Parallel()

	// ESC [ 1 ; 5 A — CSI with parameter and sub-parameter bytes before final.
	d := &keyDecoder{}
	seq := []byte{byteEsc, '[', '1', ';', '5', 'A'}
	for _, b := range seq {
		got := d.next(b)
		if got.kind != evIgnore {
			t.Fatalf("CSI-with-intermediates byte 0x%02x: want evIgnore, got %v", b, got.kind)
		}
	}
	if d.mode != modeGround {
		t.Fatalf("after CSI with intermediates: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_ApprovalActive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    byte
		wantKind eventKind
		wantDec  tools.Decision
	}{
		{"y lower", 'y', evDecision, tools.ApproveOnce},
		{"Y upper", 'Y', evDecision, tools.ApproveOnce},
		{"a lower", 'a', evDecision, tools.ApproveSession},
		{"A upper", 'A', evDecision, tools.ApproveSession},
		{"n lower", 'n', evDecision, tools.Deny},
		{"N upper", 'N', evDecision, tools.Deny},
		{"q non-yan denies", 'q', evDecision, tools.Deny},
		{"space denies", ' ', evDecision, tools.Deny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &keyDecoder{approvalActive: true}
			got := d.next(tc.input)

			if got.kind != tc.wantKind {
				t.Fatalf("byte %q: want kind %v, got %v", tc.input, tc.wantKind, got.kind)
			}
			if got.kind == evDecision && got.decision != tc.wantDec {
				t.Fatalf("byte %q: want decision %v, got %v", tc.input, tc.wantDec, got.decision)
			}
		})
	}
}

func TestKeyDecoder_ApprovalInactive(t *testing.T) {
	t.Parallel()

	// When approvalActive is false, y/a/n keys should all yield evIgnore.
	d := &keyDecoder{approvalActive: false}
	for _, b := range []byte{'y', 'a', 'n'} {
		got := d.next(b)
		if got.kind != evIgnore {
			t.Fatalf("approval inactive, byte %q: want evIgnore, got %v", b, got.kind)
		}
	}
}

func TestKeyDecoder_TimeoutInGround(t *testing.T) {
	t.Parallel()

	// A timeout when already in modeGround is a no-op.
	d := &keyDecoder{}
	got := d.timeout()
	if got.kind != evIgnore {
		t.Fatalf("timeout in ground: want evIgnore, got %v", got.kind)
	}
	if d.mode != modeGround {
		t.Fatalf("after ground timeout: want modeGround, got %v", d.mode)
	}
}

func TestKeyDecoder_DecodeRealByte(t *testing.T) {
	t.Parallel()

	d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
	got := d.decode(1, nil, 'a')           // a real byte during an approval window.
	if got.kind != evDecision || got.decision != tools.ApproveSession {
		t.Fatalf("real byte: want evDecision/ApproveSession, got %v/%v", got.kind, got.decision)
	}
}

func TestKeyDecoder_DecodeTimeout(t *testing.T) {
	t.Parallel()

	d := &keyDecoder{} //nolint:exhaustruct // mode zero is modeGround.
	d.mode = modeEsc   // a pending Esc resolves to interrupt on a VTIME timeout.
	if got := d.decode(0, nil, 0); got.kind != evInterrupt {
		t.Fatalf("zero-byte timeout in modeEsc: want evInterrupt, got %v", got.kind)
	}
}

func TestKeyDecoder_DecodeReadErrorDoesNotReplayStaleByte(t *testing.T) {
	t.Parallel()

	// A read error returns n == -1 with the previous buffer contents; during an
	// approval window a stale 'y' must NOT be decoded into an approve decision.
	d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
	if got := d.decode(-1, errors.New("read"), 'y'); got.kind != evIgnore {
		t.Fatalf("read error must not decode the stale byte: got %v/%v", got.kind, got.decision)
	}
}

func TestKeyDecoder_DecodeErrorWithPositiveCountStillIgnores(t *testing.T) {
	t.Parallel()

	// A non-nil error takes precedence even if n looks positive: no byte is decoded.
	d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
	if got := d.decode(1, errors.New("read"), 'y'); got.kind != evIgnore {
		t.Fatalf("errored read must be ignored regardless of n: got %v/%v", got.kind, got.decision)
	}
}

// countInterrupts feeds a byte stream through next() one byte at a time and
// returns how many evInterrupt events it produced, plus the final mode.
func countInterrupts(d *keyDecoder, seq []byte) (int, decodeMode) {
	n := 0
	for _, b := range seq {
		if d.next(b).kind == evInterrupt {
			n++
		}
	}

	return n, d.mode
}

func TestKeyDecoder_OSC11ReplyNoInterrupt(t *testing.T) {
	t.Parallel()

	// A real OSC 11 background-color reply terminated with ST (ESC '\'). The
	// watcher used to read its leading "ESC ]" as a lone Esc.
	d := &keyDecoder{} //nolint:exhaustruct // mode zero is modeGround.
	got, mode := countInterrupts(d, []byte("\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\"))
	if got != 0 {
		t.Fatalf("OSC 11 reply: want 0 interrupts, got %d", got)
	}
	if mode != modeGround {
		t.Fatalf("OSC 11 reply: want end modeGround, got %v", mode)
	}
}

func TestKeyDecoder_OSCReplyBELTerminated(t *testing.T) {
	t.Parallel()

	// Some terminals end OSC with BEL (0x07) instead of ST.
	d := &keyDecoder{} //nolint:exhaustruct // mode zero is modeGround.
	got, mode := countInterrupts(d, []byte("\x1b]11;rgb:1c1c/1c1c/1c1c\x07"))
	if got != 0 {
		t.Fatalf("BEL-terminated OSC: want 0 interrupts, got %d", got)
	}
	if mode != modeGround {
		t.Fatalf("BEL-terminated OSC: want end modeGround, got %v", mode)
	}
}

func TestKeyDecoder_StringSeqIntroducers(t *testing.T) {
	t.Parallel()

	// DCS (P), APC (_), PM (^), SOS (X) all open a string sequence after ESC.
	for _, intro := range []byte{'P', '_', '^', 'X'} {
		d := &keyDecoder{} //nolint:exhaustruct // mode zero is modeGround.
		if d.next(byteEsc).kind != evIgnore {
			t.Fatalf("intro %q: esc byte should ignore", intro)
		}
		if got := d.next(intro); got.kind != evIgnore {
			t.Fatalf("intro %q: want evIgnore, got %v", intro, got.kind)
		}
		if d.mode != modeStr {
			t.Fatalf("intro %q: want modeStr, got %v", intro, d.mode)
		}
	}
}

func TestKeyDecoder_StringSeqEscNonTerminatorKeepsConsuming(t *testing.T) {
	t.Parallel()

	// ESC inside a string sequence followed by a non-'\' byte is NOT a terminator;
	// stay consuming so the next bytes can't be decoded as an approval decision.
	d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
	for _, b := range []byte("\x1b]11;\x1bx") {
		if got := d.next(b); got.kind != evIgnore {
			t.Fatalf("byte 0x%02x: want evIgnore, got %v/%v", b, got.kind, got.decision)
		}
	}
	if d.mode != modeStr {
		t.Fatalf("after ESC+non-terminator: want modeStr, got %v", d.mode)
	}
	// A following 'y' is still payload (modeStr), not an approve decision.
	if got := d.next('y'); got.kind != evIgnore {
		t.Fatalf("payload 'y' in modeStr: want evIgnore, got %v/%v", got.kind, got.decision)
	}
}

func TestKeyDecoder_OSCReplyDuringApprovalNoDecision(t *testing.T) {
	t.Parallel()

	// The exact safety property: an OSC reply read during an open approval
	// window must yield no decision (and no interrupt).
	d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
	for _, b := range []byte("\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\") {
		if got := d.next(b); got.kind != evIgnore {
			t.Fatalf("byte 0x%02x during approval: want evIgnore, got %v/%v", b, got.kind, got.decision)
		}
	}
}

func TestKeyDecoder_TimeoutDoesNotAbandonSequence(t *testing.T) {
	t.Parallel()

	// A quiet VTIME tick mid-sequence must NOT drop to ground: the sequence's
	// remaining bytes must keep being consumed, never leak to ground where a final
	// byte could be misread. Only modeEsc resolves on a timeout (lone Esc); every
	// other sequence mode is preserved.
	cases := []struct {
		name string
		seq  []byte
		want decodeMode
	}{
		{"CSI partial stays modeEscSeq", []byte{byteEsc, '['}, modeEscSeq},
		{"OSC partial stays modeStr", []byte{byteEsc, ']'}, modeStr},
		{"OSC esc partial stays modeStrEsc", []byte{byteEsc, ']', byteEsc}, modeStrEsc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &keyDecoder{} //nolint:exhaustruct // mode zero is modeGround.
			for _, b := range tc.seq {
				_ = d.next(b)
			}
			if got := d.timeout(); got.kind != evIgnore {
				t.Fatalf("%s: timeout want evIgnore, got %v", tc.name, got.kind)
			}
			if d.mode != tc.want {
				t.Fatalf("%s: want mode %v preserved, got %v", tc.name, tc.want, d.mode)
			}
		})
	}
}

func TestKeyDecoder_SplitControlSequenceDuringApprovalDenies(t *testing.T) {
	t.Parallel()

	// Security: a control sequence (arrow/function key) split across a VTIME tick
	// during an approval window must never have its trailing byte decoded as an
	// approval key. e.g. cursor-up "ESC [ A" / app-cursor-up "ESC O A" over a laggy
	// link must not grant ApproveSession from the trailing 'A'. Fail closed: evIgnore.
	cases := []struct {
		name  string
		intro byte
	}{
		{"CSI up-arrow", '['},
		{"SS3 up-arrow", 'O'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &keyDecoder{approvalActive: true} //nolint:exhaustruct // mode zero is modeGround.
			_ = d.next(byteEsc)
			_ = d.next(tc.intro)
			_ = d.timeout() // the ~100ms split between the introducer and the final byte.
			if got := d.next('A'); got.kind != evIgnore {
				t.Fatalf("%s: split trailing 'A' must be ignored, got %v/%v", tc.name, got.kind, got.decision)
			}
		})
	}
}
