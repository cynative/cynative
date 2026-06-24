package cloudauth

import "fmt"

// NotReady formats a lazy-init step failure as the inner one-line error
// "<prefix>: <step>: <err>" for the aws/gcp/azure hardening providers. The
// provider's lazyInit wrapper (internal/auth/lazyinit.go) then exposes it to the
// model as "<prefix>: not_ready: …". NotReady emits no separate operator log —
// that would only duplicate the error the model already receives.
func NotReady(prefix, step string, err error) error {
	return fmt.Errorf("%s: %s: %w", prefix, step, err)
}
