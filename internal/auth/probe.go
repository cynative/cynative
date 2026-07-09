package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// credentialProbeTimeout bounds each connector's registration credential probe.
// Fast "no credential" paths return in milliseconds; this cap only bounds a
// pathological hang (e.g. a blackholed metadata endpoint). It replaces the
// former per-connector gcpProbeTimeout / azureProbeTimeout values.
const credentialProbeTimeout = 5 * time.Second

// ceilingValidationTimeout bounds the registration-time fetch+validation of the
// configured ceiling (AWS policy doc, GCP role, Azure role definition). It is
// larger than credentialProbeTimeout because the ceiling fetch is a real
// multi-call API round-trip, not a token mint; it is decoupled so a slow ceiling
// fetch on a healthy credential does not false-skip the connector.
const ceilingValidationTimeout = 30 * time.Second

// isTransientProbeErr reports whether a registration-probe error is operational
// /transient (a timeout/cancellation, a network timeout, or an HTTP 429/5xx)
// as opposed to a definitive answer (no credential, access denied).
// Classification is deliberately conservative so a genuine "denied" is never
// misrouted as transient. The HTTP-status check matches AWS smithy response
// errors (which expose HTTPStatusCode); GCP/Azure service-side 5xx that surface
// as plain SDK errors are NOT classified here and route per their explicitness
// (a known, accepted limitation — the dominant transient case, a metadata/token
// hang, is a timeout and IS caught).
func isTransientProbeErr(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	var httpErr interface{ HTTPStatusCode() int }
	if errors.As(err, &httpErr) {
		code := httpErr.HTTPStatusCode()

		return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
	}

	return false
}

// escalateForTransient promotes a skip diagnostic to emitAlways (loud, even when
// ambient) when the skip was caused by a transient probe error, so a cloud-VM
// metadata/token blip at registration is never silently swallowed. A
// non-transient error keeps the caller's policy (ambient absence stays quiet).
func escalateForTransient(policy emitPolicy, err error) emitPolicy {
	if isTransientProbeErr(err) {
		return emitAlways
	}

	return policy
}

// retryProbe runs fn once and, only if it fails transiently, runs it a second
// time, returning the second result. A non-transient failure (or success) is
// returned immediately. The caller bounds fn via the probe's context, so the
// retry shares the same deadline and cannot extend the bounded window.
func retryProbe(fn func() error) error {
	err := fn()
	if err != nil && isTransientProbeErr(err) {
		return fn()
	}

	return err
}
