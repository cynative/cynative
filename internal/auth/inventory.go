package auth

import (
	"github.com/cynative/cynative/internal/auth/exposure"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
)

// connectorOutcome is one registrar's result: zero or more providers, a slice of
// statuses to surface, and an index-aligned visibility slice. statuses is aligned
// with visible (emitOutcome zips them), NOT with providers: a registrar may return
// more providers than statuses — a cloud connector folds its managed K8s provider
// (eks/gke/aks) into the parent's status line via the Managed field while still
// returning the managed provider for the agent to use. providers is index-free
// (find() is by name).
type connectorOutcome struct {
	providers []Provider
	statuses  []ConnectorStatus
	visible   []bool
}

// emitOutcome streams one registrar's visible statuses to onStatus (nil-safe) and
// returns its providers. It is the per-outcome core shared by the sequential and
// concurrent GetProviders drivers.
func emitOutcome(out connectorOutcome, onStatus func(ConnectorStatus)) []Provider {
	for i, st := range out.statuses {
		if out.visible[i] && onStatus != nil {
			onStatus(st)
		}
	}

	return out.providers
}

// driveConcurrent runs each registrar thunk in its own goroutine and drains the
// outcomes through a single consumer (the caller's goroutine). It emits each
// outcome's visible statuses to onStatus inline as it ARRIVES (completion order —
// so the inventory streams as connectors resolve), but RETURNS providers in
// registrar (argument) ORDER, not completion order — so the provider slice is
// deterministic run-to-run (it feeds the agent's system-prompt provider list;
// nondeterministic order would bust prompt caching and reproducibility). Because
// only the caller calls emitOutcome/onStatus, those are never invoked
// concurrently; the registrar thunks must be independent (no shared mutable
// state). Covered core (no I/O — GetProviders injects the real thunks).
func driveConcurrent(registrars []func() connectorOutcome, onStatus func(ConnectorStatus)) []Provider {
	type indexedOutcome struct {
		index   int
		outcome connectorOutcome
	}

	outcomes := make(chan indexedOutcome, len(registrars))
	for i, r := range registrars {
		go func() { outcomes <- indexedOutcome{index: i, outcome: r()} }()
	}

	byIndex := make([][]Provider, len(registrars))
	for range registrars {
		res := <-outcomes
		byIndex[res.index] = emitOutcome(res.outcome, onStatus) // emit in completion order.
	}

	var providers []Provider
	for _, ps := range byIndex { // assemble in registrar order — deterministic.
		providers = append(providers, ps...)
	}

	return providers
}

// awsPostureLabel renders the inventory posture from an IAM policy ARN as the full
// ARN with the "policy=" term (e.g. "policy=arn:aws:iam::aws:policy/SecurityAudit").
// The " · sts=<label>" downscoping suffix is appended by the AWS registration
// outcome (workstream B2), not here.
func awsPostureLabel(policyARN string) string {
	return "policy=" + policyARN
}

// gcpPostureLabel renders the GCP inventory posture as "role=<roles/...>" — the
// configured connectors.gcp.role verbatim.
func gcpPostureLabel(role string) string {
	return "role=" + role
}

// azurePostureLabel renders the Azure inventory posture as "role definition=<name>"
// — the configured connectors.azure.role_definition verbatim.
func azurePostureLabel(roleDefinition string) string {
	return "role definition=" + roleDefinition
}

// k8sPostureLabel renders the inventory posture for a Kubernetes connector as
// "cluster role=<name>" — the configured cluster_role verbatim.
func k8sPostureLabel(clusterRole string) string {
	return "cluster role=" + clusterRole
}

// githubPosture renders the github inventory posture as the compact effective-
// ceiling scalar (e.g. "permissions=default=read,secret-scanning=none") and whether
// it is loud (any write-broadening or opened secret-scanning is a ⚠).
func githubPosture(e exposure.Exposure) (string, bool) {
	return "permissions=" + githubhardening.InventoryPosture(e), githubhardening.PostureLoud(e)
}

// gitlabPosture renders the gitlab inventory posture as the compact effective-
// ceiling scalar (e.g. "permissions=default=read,ci-variables=none") and whether it
// is loud (any write-broadening or opened ci-variables is a ⚠).
func gitlabPosture(e exposure.Exposure) (string, bool) {
	return "permissions=" + gitlabclass.InventoryPosture(e), gitlabclass.PostureLoud(e)
}

// joinIdentity joins non-empty project and principal with " · ".
func joinIdentity(project, principal string) string {
	switch {
	case project != "" && principal != "":
		return project + " · " + principal
	case project != "":
		return project
	default:
		return principal
	}
}
