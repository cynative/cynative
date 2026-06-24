package auth

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
}
