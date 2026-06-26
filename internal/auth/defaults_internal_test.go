package auth

import (
	"testing"

	"github.com/cynative/cynative/internal/config"
)

// TestDefaultConstantsMatchConfig pins the auth-local default-ceiling constants
// against internal/config's shipped defaults, so a config default change cannot
// silently make access= mislabel custom ceilings as default.
func TestDefaultConstantsMatchConfig(t *testing.T) {
	t.Parallel()

	def := config.DefaultConfig()
	cases := []struct {
		name      string
		constant  string
		configVal string
	}{
		{"aws policy", defaultAWSPolicyARN, def.Connectors.AWS.Policy},
		{"gcp role", defaultGCPRole, def.Connectors.GCP.Role},
		{"azure role definition", defaultAzureRoleDefinition, def.Connectors.Azure.RoleDefinition},
		{"k8s cluster role", defaultClusterRole, def.Connectors.Kubernetes.ClusterRole},
	}
	for _, tc := range cases {
		if tc.constant != tc.configVal {
			t.Errorf("%s: auth const %q != config default %q", tc.name, tc.constant, tc.configVal)
		}
	}
}
