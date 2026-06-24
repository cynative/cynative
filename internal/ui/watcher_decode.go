//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import "github.com/cynative/cynative/internal/tools"

// decodeMode is the keyDecoder's parser state.
type decodeMode int

const (
	modeGround decodeMode = iota // not inside an escape sequence.
	modeEsc                      // just saw ESC; the next byte (or a timeout) decides lone-Esc vs a sequence.
	modeEscSeq                   // inside a CSI/SS3 control sequence; consume until the final byte.
	modeStr                      // inside an OSC/DCS/APC/PM/SOS string sequence; consume until ST/BEL.
	modeStrEsc                   // saw ESC inside a string sequence; the next byte decides ST vs continuation.
)

// eventKind classifies a decoded keystroke.
type eventKind int

const (
	evIgnore    eventKind = iota // nothing actionable.
	evInterrupt                  // Ctrl-C or a lone Esc: the read-loop calls interrupt.State.Trip().
	evDecision                   // a y/a/n approval answer (only when an approval is active).
)

// keyEvent is the decoder's output for one input.
type keyEvent struct {
	kind     eventKind
	decision tools.Decision // valid only when kind == evDecision.
}

// Control bytes recognized by the decoder.
const (
	byteCtrlC = 0x03
	byteEsc   = 0x1b
	byteBEL   = 0x07 // terminates an OSC string sequence.
	byteST    = '\\' // the second byte of a String Terminator (ESC '\').
)

// isStringSeqIntroducer reports whether b, following ESC, opens a string sequence a
// terminal can emit as a query reply: OSC (]), DCS (P), SOS (X), PM (^), or APC (_).
// Such sequences are consumed and ignored, never mistaken for a lone Esc.
func isStringSeqIntroducer(b byte) bool {
	switch b {
	case ']', 'P', 'X', '^', '_':
		return true
	default:
		return false
	}
}

// keyDecoder is the pure byte->event state machine for the cbreak keystroke watcher.
// It disambiguates a lone Esc (interrupt) from CSI/SS3 control sequences and from the
// OSC/DCS/APC/PM/SOS string sequences a terminal emits as query replies (e.g. the
// OSC 11 background-color reply lipgloss reads), recognizes Ctrl-C, and maps y/a/n to
// an approval decision when an approval is active. No I/O.
type keyDecoder struct {
	mode           decodeMode
	approvalActive bool
}

// decode resolves one watcher read into an event. A real byte (n > 0 and no error)
// is decoded; a VTIME timeout (n == 0) or a read error (n < 0, or a non-nil err) feed
// the timeout tick instead, which never yields an approval decision — so a failed read
// can never replay the stale buffer byte and approve a credentialed call.
func (d *keyDecoder) decode(n int, err error, b byte) keyEvent {
	if n <= 0 || err != nil {
		return d.timeout()
	}

	return d.next(b)
}

// timeout resolves a quiet VTIME tick. Only modeEsc resolves on a timeout: no sequence
// byte followed the Esc, so it was a lone keypress -> interrupt. Every other non-ground
// mode is mid-sequence and is left UNCHANGED so the sequence keeps consuming: a control
// sequence split across a tick (e.g. cursor-up "ESC [ A" over a laggy link) must never
// drop to ground, where its trailing byte ('A') could be decoded as an approval key.
// Real keypress sequences always terminate, so this cannot strand the decoder in
// practice; staying in-sequence fails closed (consumes, never approves). Ground: no-op.
func (d *keyDecoder) timeout() keyEvent {
	if d.mode == modeEsc {
		d.mode = modeGround

		return keyEvent{kind: evInterrupt}
	}

	return keyEvent{kind: evIgnore}
}

// next feeds one input byte and returns the resulting event, advancing the parser state.
func (d *keyDecoder) next(b byte) keyEvent {
	switch d.mode { //nolint:exhaustive // default covers modeGround and any future modes.
	case modeEscSeq:
		if b >= 0x40 && b <= 0x7e { // a CSI/SS3 final byte ends the sequence.
			d.mode = modeGround
		}

		return keyEvent{kind: evIgnore}
	case modeEsc:
		return d.afterEsc(b)
	case modeStr:
		return d.inString(b)
	case modeStrEsc:
		return d.afterStringEsc(b)
	default: // modeGround
		return d.ground(b)
	}
}

// afterEsc resolves the byte following an ESC: a CSI/SS3 introducer or a string-
// sequence introducer starts a sequence to consume; anything else is a lone Esc
// followed by a printable byte -> interrupt (the byte is dropped).
func (d *keyDecoder) afterEsc(b byte) keyEvent {
	switch {
	case b == '[' || b == 'O': // CSI or SS3 introducer.
		d.mode = modeEscSeq

		return keyEvent{kind: evIgnore}
	case isStringSeqIntroducer(b): // OSC/DCS/APC/PM/SOS reply.
		d.mode = modeStr

		return keyEvent{kind: evIgnore}
	default:
		d.mode = modeGround

		return keyEvent{kind: evInterrupt}
	}
}

// inString consumes a byte inside a string sequence: BEL ends it, ESC may begin the
// ST terminator (-> modeStrEsc), anything else is payload. Never an interrupt or a
// decision, so a reply's payload cannot be misread (incl. during an approval window).
func (d *keyDecoder) inString(b byte) keyEvent {
	switch b {
	case byteBEL:
		d.mode = modeGround
	case byteEsc:
		d.mode = modeStrEsc
	}

	return keyEvent{kind: evIgnore}
}

// afterStringEsc resolves the byte after an ESC inside a string sequence: a backslash
// completes the ST terminator (-> ground); anything else was not a terminator, so keep
// consuming (-> modeStr) rather than dropping to ground where a payload byte could be
// decoded as an approval decision.
func (d *keyDecoder) afterStringEsc(b byte) keyEvent {
	if b == byteST {
		d.mode = modeGround

		return keyEvent{kind: evIgnore}
	}
	d.mode = modeStr

	return keyEvent{kind: evIgnore}
}

// ground decodes a byte outside any escape sequence.
func (d *keyDecoder) ground(b byte) keyEvent {
	switch b {
	case byteCtrlC:
		return keyEvent{kind: evInterrupt}
	case byteEsc:
		d.mode = modeEsc

		return keyEvent{kind: evIgnore}
	}
	if d.approvalActive {
		// Fail closed, matching the cooked prompt's parseDecision: only y/a approve;
		// n and every other printable key deny (Ctrl-C/Esc were handled above).
		switch b {
		case 'y', 'Y':
			return keyEvent{kind: evDecision, decision: tools.ApproveOnce}
		case 'a', 'A':
			return keyEvent{kind: evDecision, decision: tools.ApproveSession}
		default:
			return keyEvent{kind: evDecision, decision: tools.Deny}
		}
	}

	return keyEvent{kind: evIgnore}
}
