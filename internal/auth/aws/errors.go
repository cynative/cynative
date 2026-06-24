package aws

import "errors"

// ErrPolicyDenied is the sentinel returned when the policy evaluator denies
// the requested action. Distinct from ErrPolicyEvalFailed (API-level failure).
var ErrPolicyDenied = errors.New("aws_hardening: action denied by policy")

// ErrActionUnresolved is the sentinel returned when no IAM action could be
// resolved for the classified operation from any source (fail-closed deny).
var ErrActionUnresolved = errors.New("aws_hardening: could not resolve IAM action for operation")

// ErrSigningNameUnresolved is the sentinel returned when the SigV4 signing name
// for a request host cannot be resolved from the model archive (no candidate
// serves the host's endpoint prefix, or candidates disagree).
var ErrSigningNameUnresolved = errors.New("aws_hardening: could not resolve SigV4 signing name")
