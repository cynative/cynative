package auth

import "github.com/cynative/cynative/internal/outbound"

// HardeningConfig bundles the per-connector hardening settings the composition
// root assembles from config, replacing GetProviders' former 8 positional config
// parameters.
type HardeningConfig struct {
	Github     GithubHardeningConfig
	GitLab     GitLabHardeningConfig
	AWS        AWSHardeningConfig
	EKS        EKSHardeningConfig
	GCP        GCPHardeningConfig
	GKE        GKEHardeningConfig
	Azure      AzureHardeningConfig
	AKS        AKSHardeningConfig
	Kubernetes KubernetesHardeningConfig
	// Outbound is the operator's proxy configuration, shared by every connector:
	// the registration probes and the authorization-data fetches route exactly
	// as the request path does. The zero value dials directly.
	Outbound outbound.Routing
}
