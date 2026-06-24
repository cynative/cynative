package auth

import (
	"errors"
	"fmt"
)

// emitPolicy classifies a provider-registration skip for diagnostic routing.
// Two policies suffice: the ambient-absence case is exactly
// emitWhenExplicitOrVerbose with explicit == false, so no separate
// verbose-only policy is needed.
type emitPolicy int

const (
	// emitAlways is a genuine "can't even load" or structural error: loud
	// regardless of explicitness or verbosity.
	emitAlways emitPolicy = iota
	// emitWhenExplicitOrVerbose is loud only when the connector was explicitly
	// configured; otherwise (ambient absence) it is shown only under --verbose.
	emitWhenExplicitOrVerbose
)

// shouldEmit decides whether a skip diagnostic with the given policy is printed
// by default (loud) or only under --verbose. It is the pure routing primitive.
func shouldEmit(p emitPolicy, explicit, verbose bool) bool {
	if p == emitAlways {
		return true
	}

	return explicit || verbose
}

// kubeSkipPolicy maps a Kubernetes registration error (from extractSelected /
// resolveSelected) to an emit policy. The two skip sentinels are explicit-gated;
// every other (structural) error is always loud.
func kubeSkipPolicy(err error) emitPolicy {
	if errors.Is(err, ErrNoCurrentContext) || errors.Is(err, ErrUnsupportedFeature) {
		return emitWhenExplicitOrVerbose
	}

	return emitAlways
}

// awsSkipResult maps the AWS config-load and credential-retrieve outcomes to a
// skip decision: a load failure is always loud; a retrieve failure is
// explicit-gated; success does not skip.
func awsSkipResult(loadErr, retrieveErr error) (bool, emitPolicy, string) {
	switch {
	case loadErr != nil:
		return true, emitAlways, fmt.Sprintf("aws_hardening: skipped (config load failed): %v", loadErr)
	case retrieveErr != nil:
		return true, emitWhenExplicitOrVerbose,
			fmt.Sprintf("aws_hardening: skipped (no usable credentials): %v", retrieveErr)
	default:
		return false, emitAlways, ""
	}
}

// gcpSkipResult maps the GCP find-credentials and (explicit-only) token-probe
// outcomes to (skipped, message). GCP has no "can't even load" case, so every
// skip is explicit-gated (emitWhenExplicitOrVerbose) — the caller supplies that
// policy, so it is not returned here.
func gcpSkipResult(findErr, probeErr error) (bool, string) {
	if err := cmpErr(findErr, probeErr); err != nil {
		return true, fmt.Sprintf("gcp_hardening: skipped (no usable credentials): %v", err)
	}

	return false, ""
}

// azureSkipResult maps the Azure chain-construction and (explicit-only) ARM-probe
// outcomes to (skipped, message). Like GCP, every Azure skip is explicit-gated,
// so the policy is supplied by the caller rather than returned here.
func azureSkipResult(chainErr, probeErr error) (bool, string) {
	if err := cmpErr(chainErr, probeErr); err != nil {
		return true, fmt.Sprintf("azure_hardening: skipped (no usable credentials): %v", err)
	}

	return false, ""
}

// kubeSkipResult maps the kubeconfig-load and post-load (extract/resolve)
// outcomes to a skip decision: a load failure is always loud; a post-load
// failure is policy-classified by kubeSkipPolicy; success does not skip.
func kubeSkipResult(loadErr, postErr error) (bool, emitPolicy, string) {
	switch {
	case loadErr != nil:
		return true, emitAlways, fmt.Sprintf("kubernetes_hardening: skipped (load kubeconfig): %v", loadErr)
	case postErr != nil:
		return true, kubeSkipPolicy(postErr), fmt.Sprintf("kubernetes_hardening: skipped: %v", postErr)
	default:
		return false, emitAlways, ""
	}
}

// cmpErr returns the first non-nil error (find/chain before probe).
func cmpErr(first, second error) error {
	if first != nil {
		return first
	}

	return second
}
