package auth

import (
	"strings"

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

// buildPosture renders the connector inventory posture: the access level, the
// enforcement locus, and the configured ceiling id, joined by " · ".
func buildPosture(access, enforced, ceiling string) string {
	return "access=" + access + " · enforced=" + enforced + " · " + ceiling
}

// awsAccess reports default(read-only) when the policy ARN is the curated default
// (exact match), custom otherwise.
func awsAccess(policyARN string) string {
	if policyARN == defaultAWSPolicyARN {
		return accessDefault
	}

	return accessCustom
}

// gcpAccess reports default(read-only) for the curated default role, custom otherwise.
func gcpAccess(role string) string {
	if role == defaultGCPRole {
		return accessDefault
	}

	return accessCustom
}

// azureAccess reports default(read-only) for the curated default role definition,
// case-insensitively (the Azure role lookup is case-insensitive); custom otherwise
// (configuring the Reader GUID instead of the name reads as custom).
func azureAccess(roleDef string) string {
	if strings.EqualFold(roleDef, defaultAzureRoleDefinition) {
		return accessDefault
	}

	return accessCustom
}

// k8sAccess reports default(read-only) for the curated default ClusterRole, custom otherwise.
func k8sAccess(clusterRole string) string {
	if clusterRole == defaultClusterRole {
		return accessDefault
	}

	return accessCustom
}

// exposureAccess reports default(read-only) when the operator supplied no
// permissions override (the secure baseline is in force), custom otherwise.
// Raw-config check (not [maps.Equal] on the effective ceiling) so a redundant
// no-op override reads consistently as custom.
func exposureAccess(operator map[string]string) string {
	if len(operator) == 0 {
		return accessDefault
	}

	return accessCustom
}

// ManagedK8sPosture builds the inventory/prompt posture for a managed K8s
// connector (eks/gke/aks) from its configured ClusterRole. Exported so the cli
// can attach prompt metadata for connectors that have no own inventory line.
func ManagedK8sPosture(clusterRole string) string {
	return buildPosture(k8sAccess(clusterRole), enforcedClient, k8sPostureLabel(clusterRole))
}
