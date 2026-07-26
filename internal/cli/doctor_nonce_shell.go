package cli

import (
	"crypto/rand"
	"encoding/hex"
)

// doctorProbeNonce builds a unique token for doctor --live-llm. Lives in the
// shell so the gated doctor core never reaches crypto/rand directly.
func doctorProbeNonce() string {
	var b [16]byte
	// crypto/rand.Read fills the whole buffer on success; a failure leaves zeros
	// and we still emit a stable-shaped token rather than aborting doctor.
	_, _ = rand.Read(b[:])

	return "DOCTOR-" + hex.EncodeToString(b[:])
}
