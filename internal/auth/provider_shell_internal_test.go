package auth

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2/google"
)

// TestBuildRegistrationDeps_ThreadsTheEgressPolicy pins the policy assignments
// in buildRegistrationDeps: the deps' own field, which the status scrubber
// reads, and the one each Kubernetes-flavored provider carries into its
// ClusterRole bootstrap fetch. Dropping any of them leaves every other gate
// green while that connector's fetch silently takes the direct path under a
// proxy-only policy.
func TestBuildRegistrationDeps_ThreadsTheEgressPolicy(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})

	deps := buildRegistrationDeps(HardeningConfig{Egress: e})
	if deps.egress != e {
		t.Fatalf("deps.egress = %p, want the configured policy %p", deps.egress, e)
	}

	// These builders construct providers from already-resolved material; none of
	// them performs network or filesystem I/O.
	_, eks := deps.buildAWS(aws.Config{}, nil)
	_, gke := deps.buildGCP(&google.Credentials{})
	_, aks := deps.buildAzure(nil)
	kube := deps.buildKube(resolvedCluster{})

	carried := map[string]*Egress{
		eksProviderName:        eks.egress,
		gkeProviderName:        gke.egress,
		aksProviderName:        aks.egress,
		kubernetesProviderName: kube.egress,
	}
	for name, got := range carried {
		if got != e {
			t.Errorf("%s provider egress = %p, want the configured policy %p", name, got, e)
		}
	}
}
